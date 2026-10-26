#![allow(unsafe_code)]
//! Process setup and single instance (spec/01 §7.6). The yw-host pieces (`spawn_detached`,
//! `StdIn`/`StdOut`, `current_user_sid_string`) arrive with M5.

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, HANDLE};
use windows_sys::Win32::System::ErrorReporting::WerAddExcludedApplication;
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleFileNameW, LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
};
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::WindowsAndMessaging::AllowSetForegroundWindow;

use crate::error::WinError;
use crate::wide::to_wide;

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
