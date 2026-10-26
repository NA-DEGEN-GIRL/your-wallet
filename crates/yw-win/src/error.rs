#![allow(unsafe_code)]
//! The common Win32 error value (spec/01 §7).

use core::fmt;

use windows_sys::Win32::Foundation::GetLastError;

/// A failed Win32 call: the API name and the `GetLastError` (or returned) code.
///
/// `Display` is `"<api> failed: 0x<code:08X>"`. `FormatMessageW` is never used, so the value
/// carries no OS text, path or argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WinError {
    /// The Win32 function that failed.
    pub api: &'static str,
    /// The error code.
    pub code: u32,
}

impl WinError {
    /// Builds an error with an explicit code.
    #[must_use]
    pub const fn new(api: &'static str, code: u32) -> Self {
        Self { api, code }
    }

    /// Reads `GetLastError()` immediately for `api`.
    pub(crate) fn last(api: &'static str) -> Self {
        // SAFETY: `GetLastError` only reads the calling thread's last-error value.
        let code = unsafe { GetLastError() };
        Self { api, code }
    }

    /// `ERROR_INVALID_PARAMETER` for an argument rejected before any call (interior NUL etc.).
    pub(crate) const fn invalid_argument(api: &'static str) -> Self {
        Self { api, code: 87 }
    }
}

impl fmt::Display for WinError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} failed: 0x{:08X}", self.api, self.code)
    }
}

impl std::error::Error for WinError {}

#[cfg(test)]
mod tests {
    use super::WinError;

    #[test]
    fn display_is_api_and_hex_code_only() {
        let error = WinError::new("MoveFileExW", 5);
        assert_eq!(error.to_string(), "MoveFileExW failed: 0x00000005");
    }
}
