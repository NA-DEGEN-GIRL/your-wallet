//! NUL-terminated UTF-16 conversion for Win32 string arguments (spec/01 §7: interior NUL is an
//! error).

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use crate::error::WinError;

/// `text` as NUL-terminated UTF-16; an interior NUL is rejected.
pub(crate) fn to_wide(text: &str, api: &'static str) -> Result<Vec<u16>, WinError> {
    let mut wide: Vec<u16> = text.encode_utf16().collect();
    if wide.contains(&0) {
        return Err(WinError::invalid_argument(api));
    }
    wide.push(0);
    Ok(wide)
}

/// `path` as NUL-terminated UTF-16; an interior NUL is rejected.
pub(crate) fn path_wide(path: &Path, api: &'static str) -> Result<Vec<u16>, WinError> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(WinError::invalid_argument(api));
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(test)]
mod tests {
    use super::to_wide;

    #[test]
    fn interior_nul_is_rejected_and_terminator_added() {
        assert_eq!(to_wide("ab", "t"), Ok(vec![0x61, 0x62, 0]));
        assert!(to_wide("a\0b", "t").is_err());
    }
}
