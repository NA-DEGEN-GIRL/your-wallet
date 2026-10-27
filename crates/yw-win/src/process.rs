#![allow(unsafe_code)]
//! Process setup, single instance and the yw-host process helpers (spec/01 §7.6, spec/05 §7.2,
//! §7.4, §7.8): the current user's SID string, detached `CreateProcessW` without handle
//! inheritance, and unbuffered standard handles.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_BROKEN_PIPE, HANDLE,
    INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType, ReadFile, WriteFile};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::ErrorReporting::WerAddExcludedApplication;
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleFileNameW, LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
};
use windows_sys::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, CreateMutexW, CreateProcessW,
    DETACHED_PROCESS, GetCurrentProcess, OpenProcessToken, PROCESS_CREATION_FLAGS,
    PROCESS_INFORMATION, STARTUPINFOW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::AllowSetForegroundWindow;

use crate::error::WinError;
use crate::wide::{path_wide, to_wide};

/// `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`.
///
/// # Errors
///
/// [`WinError`] from the call.
pub fn init_process() -> Result<(), WinError> {
    // SAFETY: Changes only the process DLL search order.
    let ok = unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if ok == 0 {
        return Err(WinError::last("SetDefaultDllDirectories"));
    }
    Ok(())
}

/// Single-instance failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceError {
    /// The named mutex already exists (`ERROR_ALREADY_EXISTS`).
    AlreadyRunning,
    /// `CreateMutexW` failed.
    Os(WinError),
}

/// Holds the named mutex for the life of the process.
#[derive(Debug)]
pub struct SingleInstance {
    handle: HANDLE,
}

impl SingleInstance {
    /// `CreateMutexW(NULL, FALSE, name)`; `ERROR_ALREADY_EXISTS` closes the handle and returns
    /// [`InstanceError::AlreadyRunning`].
    ///
    /// # Errors
    ///
    /// [`InstanceError`].
    pub fn acquire(name: &str) -> Result<Self, InstanceError> {
        let wide = to_wide(name, "CreateMutexW").map_err(InstanceError::Os)?;
        // SAFETY: `wide` is NUL-terminated and live; default security, not initially owned.
        let handle = unsafe { CreateMutexW(core::ptr::null(), 0, wide.as_ptr()) };
        let error = WinError::last("CreateMutexW");
        if handle.is_null() {
            return Err(InstanceError::Os(error));
        }
        if error.code == ERROR_ALREADY_EXISTS {
            // SAFETY: Closes the handle just returned to us.
            unsafe { CloseHandle(handle) };
            return Err(InstanceError::AlreadyRunning);
        }
        Ok(Self { handle })
    }
}

impl Drop for SingleInstance {
    fn drop(&mut self) {
        // SAFETY: Closes the mutex handle owned by `self` exactly once.
        unsafe { CloseHandle(self.handle) };
    }
}

// SAFETY: A mutex handle may be closed from any thread.
unsafe impl Send for SingleInstance {}

/// `AllowSetForegroundWindow(pid)`.
#[must_use]
pub fn allow_set_foreground_window(pid: u32) -> bool {
    // SAFETY: Plain value argument.
    unsafe { AllowSetForegroundWindow(pid) != 0 }
}

fn current_exe_wide() -> Result<Vec<u16>, WinError> {
    let mut size = 260_usize;
    loop {
        let mut buffer = vec![0_u16; size];
        let capacity =
            u32::try_from(size).map_err(|_| WinError::invalid_argument("GetModuleFileNameW"))?;
        // SAFETY: `buffer` is writable for `capacity` units; null module = this executable.
        let len =
            unsafe { GetModuleFileNameW(core::ptr::null_mut(), buffer.as_mut_ptr(), capacity) };
        if len == 0 {
            return Err(WinError::last("GetModuleFileNameW"));
        }
        let len =
            usize::try_from(len).map_err(|_| WinError::invalid_argument("GetModuleFileNameW"))?;
        if len < size {
            buffer.truncate(len);
            buffer.push(0);
            return Ok(buffer);
        }
        if size >= 32_768 {
            return Err(WinError::invalid_argument("GetModuleFileNameW"));
        }
        size = size.saturating_mul(2).min(32_768);
    }
}

/// `WerAddExcludedApplication(<current exe>, FALSE)` (spec/01 §5.4; recommended, not required).
///
/// # Errors
///
/// [`WinError`] with the HRESULT as code.
pub fn exclude_from_error_reporting() -> Result<(), WinError> {
    let exe = current_exe_wide()?;
    // SAFETY: `exe` is the NUL-terminated executable path, live for the call.
    let hr = unsafe { WerAddExcludedApplication(exe.as_ptr(), 0) };
    if hr != 0 {
        return Err(WinError::new(
            "WerAddExcludedApplication",
            u32::from_ne_bytes(hr.to_ne_bytes()),
        ));
    }
    Ok(())
}

/// A kernel handle closed on drop (token, process, thread).
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: The handle was returned to us by the OS and is closed exactly once here.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Longest SID string accepted (a SID has at most 15 sub-authorities: well under 200 chars).
const MAX_SID_CHARS: usize = 256;

/// `ConvertSidToStringSidW` → `String`, freeing the OS buffer with `LocalFree`.
///
/// # Safety
///
/// `sid` must point to a valid SID that stays alive for the duration of the call.
pub(crate) unsafe fn sid_to_string(sid: PSID) -> Result<String, WinError> {
    let mut text: *mut u16 = core::ptr::null_mut();
    // SAFETY: The caller guarantees `sid`; `text` is a writable out pointer.
    let ok = unsafe { ConvertSidToStringSidW(sid, &raw mut text) };
    if ok == 0 || text.is_null() {
        return Err(WinError::last("ConvertSidToStringSidW"));
    }
    let length = (0..MAX_SID_CHARS).find(|&index| {
        // SAFETY: `text` is NUL-terminated and every unit before `index` was non-NUL (the search
        // stops at the first NUL), so `index` is inside the string or is its terminator.
        let unit = unsafe { *text.wrapping_add(index) };
        unit == 0
    });
    let result = length
        .ok_or(WinError::invalid_argument("ConvertSidToStringSidW"))
        .and_then(|length| {
            // SAFETY: The first `length` units precede the terminator and are initialized; the
            // buffer stays alive until the `LocalFree` below.
            let units = unsafe { core::slice::from_raw_parts(text, length) };
            String::from_utf16(units)
                .map_err(|_| WinError::invalid_argument("ConvertSidToStringSidW"))
        });
    // SAFETY: `text` was allocated by `ConvertSidToStringSidW` with LocalAlloc; freed once here.
    unsafe { LocalFree(text.cast()) };
    result
}

/// The current process user's SID as a string (`S-1-5-21-…`): `OpenProcessToken(TOKEN_QUERY)` →
/// `GetTokenInformation(TokenUser)` → `ConvertSidToStringSidW` → `LocalFree`.
///
/// # Errors
///
/// [`WinError`] from the failing call.
pub fn current_user_sid_string() -> Result<String, WinError> {
    // SAFETY: Returns the current-process pseudo handle; nothing to close.
    let process = unsafe { GetCurrentProcess() };
    let mut raw_token: HANDLE = core::ptr::null_mut();
    // SAFETY: `process` is the valid pseudo handle; `raw_token` is a writable out pointer.
    let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut raw_token) };
    if ok == 0 {
        return Err(WinError::last("OpenProcessToken"));
    }
    let token = OwnedHandle(raw_token);
    let mut needed = 0_u32;
    // SAFETY: Size query: a null buffer of length 0 and a writable `needed`.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            core::ptr::null_mut(),
            0,
            &raw mut needed,
        )
    };
    let needed_bytes =
        usize::try_from(needed).map_err(|_| WinError::invalid_argument("GetTokenInformation"))?;
    if needed_bytes < core::mem::size_of::<TOKEN_USER>() || needed_bytes > 4_096 {
        return Err(WinError::last("GetTokenInformation"));
    }
    // `u64` storage keeps the TOKEN_USER (pointer-aligned) correctly aligned.
    let mut buffer = vec![0_u64; needed_bytes.div_ceil(8)];
    let capacity = u32::try_from(buffer.len().saturating_mul(8))
        .map_err(|_| WinError::invalid_argument("GetTokenInformation"))?;
    // SAFETY: `buffer` is writable for `capacity` bytes and 8-byte aligned; `needed` is writable.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            capacity,
            &raw mut needed,
        )
    };
    if ok == 0 {
        return Err(WinError::last("GetTokenInformation"));
    }
    // SAFETY: On success the buffer starts with an initialized, aligned TOKEN_USER.
    let user = unsafe { buffer.as_ptr().cast::<TOKEN_USER>().read() };
    // SAFETY: `user.User.Sid` points into `buffer`, which outlives the call.
    unsafe { sid_to_string(user.User.Sid) }
}

/// Whether `arg` matches `^[A-Za-z0-9._:-]{1,64}$` (the only arguments [`spawn_detached`] passes).
fn valid_spawn_arg(arg: &str) -> bool {
    (1..=64).contains(&arg.len())
        && arg
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

/// The NUL-terminated command line `"<exe>" <args…>`; rejects a `"` in the path or a bad argument.
fn spawn_command_line(exe: &Path, args: &[&str]) -> Result<Vec<u16>, WinError> {
    const API: &str = "CreateProcessW";
    let path: Vec<u16> = exe.as_os_str().encode_wide().collect();
    if path.is_empty() || path.contains(&u16::from(b'"')) || path.contains(&0) {
        return Err(WinError::invalid_argument(API));
    }
    if !args.iter().all(|arg| valid_spawn_arg(arg)) {
        return Err(WinError::invalid_argument(API));
    }
    let mut line = vec![u16::from(b'"')];
    line.extend_from_slice(&path);
    line.push(u16::from(b'"'));
    for arg in args {
        line.push(u16::from(b' '));
        line.extend(arg.encode_utf16());
    }
    line.push(0);
    Ok(line)
}

fn create_process(
    exe: &[u16],
    mut command_line: Vec<u16>,
    directory: &[u16],
    flags: PROCESS_CREATION_FLAGS,
) -> Result<(), WinError> {
    let startup = STARTUPINFOW {
        cb: u32::try_from(core::mem::size_of::<STARTUPINFOW>())
            .map_err(|_| WinError::invalid_argument("CreateProcessW"))?,
        ..STARTUPINFOW::default()
    };
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: `exe` and `directory` are NUL-terminated and live; `command_line` is a writable
    // NUL-terminated buffer (CreateProcessW may modify it); no handle is inherited; the
    // environment is inherited (null); `startup` and `info` are valid for the call.
    let ok = unsafe {
        CreateProcessW(
            exe.as_ptr(),
            command_line.as_mut_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            0,
            flags,
            core::ptr::null(),
            directory.as_ptr(),
            &raw const startup,
            &raw mut info,
        )
    };
    if ok == 0 {
        return Err(WinError::last("CreateProcessW"));
    }
    drop(OwnedHandle(info.hThread));
    drop(OwnedHandle(info.hProcess));
    Ok(())
}

/// Starts `exe` with `args` fully detached (spec/01 §7.6, spec/05 §7.4): `CreateProcessW` with
/// `bInheritHandles = FALSE` (Chrome's stdio pipes must not leak into the child),
/// `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB` and the executable's
/// folder as current directory; on `ERROR_ACCESS_DENIED` (the job forbids breakaway) it retries
/// once without `CREATE_BREAKAWAY_FROM_JOB`. The process and thread handles are closed at once.
/// `std::process::Command` is not used: it creates processes with `bInheritHandles = TRUE`.
///
/// # Errors
///
/// An argument error when an argument does not match `^[A-Za-z0-9._:-]{1,64}$` or the path
/// contains `"` or has no parent folder; otherwise [`WinError`] from `CreateProcessW`.
pub fn spawn_detached(exe: &Path, args: &[&str]) -> Result<(), WinError> {
    let command_line = spawn_command_line(exe, args)?;
    let exe_wide = path_wide(exe, "CreateProcessW")?;
    let directory = exe
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(WinError::invalid_argument("CreateProcessW"))?;
    let directory_wide = path_wide(directory, "CreateProcessW")?;
    let flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
    match create_process(
        &exe_wide,
        command_line.clone(),
        &directory_wide,
        flags | CREATE_BREAKAWAY_FROM_JOB,
    ) {
        Err(error) if error.code == ERROR_ACCESS_DENIED => {
            create_process(&exe_wide, command_line, &directory_wide, flags)
        }
        result => result,
    }
}

fn std_handle(which: STD_HANDLE) -> Option<HANDLE> {
    // SAFETY: Reads the process standard handle table; the handle is borrowed, never closed.
    let handle = unsafe { GetStdHandle(which) };
    (!handle.is_null() && handle != INVALID_HANDLE_VALUE).then_some(handle)
}

fn clamp_len(length: usize) -> u32 {
    u32::try_from(length).unwrap_or(u32::MAX)
}

fn os_error(code: u32) -> io::Error {
    io::Error::from_raw_os_error(i32::from_ne_bytes(code.to_ne_bytes()))
}

/// Unbuffered standard input: `GetStdHandle(STD_INPUT_HANDLE)` + synchronous `ReadFile` (no CRT
/// text mode, no std console handling; spec/05 §7.2). A 0-byte success, `ERROR_BROKEN_PIPE` or a
/// missing handle is EOF (`Ok(0)`).
#[derive(Clone, Copy, Debug, Default)]
pub struct StdIn;

impl io::Read for StdIn {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let Some(handle) = std_handle(STD_INPUT_HANDLE) else {
            return Ok(0);
        };
        let mut read = 0_u32;
        // SAFETY: `buffer` is writable for the clamped length; synchronous call (no OVERLAPPED).
        let ok = unsafe {
            ReadFile(
                handle,
                buffer.as_mut_ptr(),
                clamp_len(buffer.len()),
                &raw mut read,
                core::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let code = WinError::last("ReadFile").code;
            if code == ERROR_BROKEN_PIPE {
                return Ok(0);
            }
            return Err(os_error(code));
        }
        usize::try_from(read).map_err(|_| io::ErrorKind::InvalidData.into())
    }
}

/// Unbuffered standard output: `GetStdHandle(STD_OUTPUT_HANDLE)` + synchronous `WriteFile`.
/// `flush` does nothing (there is no buffer).
#[derive(Clone, Copy, Debug, Default)]
pub struct StdOut;

impl io::Write for StdOut {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let Some(handle) = std_handle(STD_OUTPUT_HANDLE) else {
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        let mut written = 0_u32;
        // SAFETY: `buffer` is readable for the clamped length; synchronous call (no OVERLAPPED).
        let ok = unsafe {
            WriteFile(
                handle,
                buffer.as_ptr(),
                clamp_len(buffer.len()),
                &raw mut written,
                core::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(os_error(WinError::last("WriteFile").code));
        }
        usize::try_from(written).map_err(|_| io::ErrorKind::InvalidData.into())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Whether stdin and stdout are both pipes (`GetFileType == FILE_TYPE_PIPE`), as when Chrome
/// launches a native messaging host.
#[must_use]
pub fn std_handles_are_pipes() -> bool {
    [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE]
        .into_iter()
        .all(|which| {
            std_handle(which).is_some_and(|handle| {
                // SAFETY: `handle` is a live standard handle borrowed for the call.
                let kind = unsafe { GetFileType(handle) };
                kind == FILE_TYPE_PIPE
            })
        })
}

#[cfg(test)]
mod tests {
    use super::{spawn_command_line, valid_spawn_arg};
    use std::path::Path;

    #[test]
    fn spawn_arguments_follow_the_allowed_pattern() {
        let longest = "x".repeat(64);
        for arg in ["--background", "a", "A.b_c:d-9", longest.as_str()] {
            assert!(valid_spawn_arg(arg), "{arg}");
        }
        let too_long = "x".repeat(65);
        for arg in [
            "",
            " ",
            "a b",
            "\"a",
            "a&b",
            "a/b",
            "a\\b",
            "\u{e9}",
            "a\0",
            too_long.as_str(),
        ] {
            assert!(!valid_spawn_arg(arg), "{arg:?}");
        }
    }

    #[test]
    fn spawn_command_line_quotes_the_path_and_rejects_bad_input() {
        let line = spawn_command_line(
            Path::new(r"C:\Program Files\YW\yw-app.exe"),
            &["--background"],
        )
        .unwrap();
        assert_eq!(
            String::from_utf16(&line).unwrap(),
            "\"C:\\Program Files\\YW\\yw-app.exe\" --background\0"
        );
        let bare = spawn_command_line(Path::new(r"C:\a\b.exe"), &[]).unwrap();
        assert_eq!(String::from_utf16(&bare).unwrap(), "\"C:\\a\\b.exe\"\0");
        assert!(spawn_command_line(Path::new(r#"C:\a"b\c.exe"#), &[]).is_err());
        assert!(spawn_command_line(Path::new(""), &[]).is_err());
        assert!(spawn_command_line(Path::new(r"C:\a.exe"), &["--x y"]).is_err());
        assert!(spawn_command_line(Path::new(r"C:\a.exe"), &["--ok", ""]).is_err());
    }
}
