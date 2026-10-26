#![allow(unsafe_code)]
//! DPAPI for the current user (spec/01 §7.2): `CryptProtectData`/`CryptUnprotectData` with
//! `CRYPTPROTECT_UI_FORBIDDEN`, no description, no prompt, never `CRYPTPROTECT_LOCAL_MACHINE`.

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};

use crate::error::WinError;
use crate::mem::{WipeBuf, wipe};

/// Largest plaintext accepted by [`protect`] (1 MiB).
pub const MAX_PLAINTEXT: usize = 1_048_576;
/// Largest blob accepted by [`unprotect`] (generous bound over the 1 MiB plaintext).
const MAX_BLOB: usize = 2 * MAX_PLAINTEXT;

fn blob_of(bytes: &[u8], api: &'static str) -> Result<CRYPT_INTEGER_BLOB, WinError> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len()).map_err(|_| WinError::invalid_argument(api))?,
        pbData: bytes.as_ptr().cast_mut(),
    })
}

/// Copies the system-allocated output into `sink`, wipes it and frees it with `LocalFree`.
fn take_output(
    out: CRYPT_INTEGER_BLOB,
    sink: &mut dyn FnMut(&[u8]) -> Result<(), WinError>,
) -> Result<(), WinError> {
    if out.pbData.is_null() {
        return Err(WinError::invalid_argument("DPAPI output"));
    }
    let len = usize::try_from(out.cbData).map_err(|_| WinError::invalid_argument("DPAPI output"));
    let result = len.and_then(|len| {
        // SAFETY: On success DPAPI returns `cbData` initialized bytes at `pbData`, owned by us
        // until `LocalFree`, with no other reference.
        let data = unsafe { core::slice::from_raw_parts_mut(out.pbData, len) };
        let copied = sink(data);
        wipe(data);
        copied
    });
    // SAFETY: `pbData` was allocated by DPAPI with LocalAlloc and is freed exactly once here.
    unsafe { LocalFree(out.pbData.cast()) };
    result
}

/// Encrypts `plain` (≤ 1 MiB) for the current user with optional `entropy`.
///
/// # Errors
///
/// [`WinError`] from `CryptProtectData`, or an argument error for oversize input.
pub fn protect(plain: &[u8], entropy: &[u8]) -> Result<Vec<u8>, WinError> {
    if plain.len() > MAX_PLAINTEXT {
        return Err(WinError::invalid_argument("CryptProtectData"));
    }
    let input = blob_of(plain, "CryptProtectData")?;
    let entropy_blob = blob_of(entropy, "CryptProtectData")?;
    let entropy_ptr: *const CRYPT_INTEGER_BLOB = if entropy.is_empty() {
        core::ptr::null()
    } else {
        &raw const entropy_blob
    };
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: core::ptr::null_mut(),
    };
    // SAFETY: `input` and `entropy_blob` describe live borrowed slices (DPAPI only reads them),
    // `out` is writable, and the description, reserved and prompt pointers are null.
    let ok = unsafe {
        CryptProtectData(
            &raw const input,
            core::ptr::null(),
            entropy_ptr,
            core::ptr::null(),
            core::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut out,
        )
    };
    if ok == 0 {
        return Err(WinError::last("CryptProtectData"));
    }
    let mut result = Vec::new();
    take_output(out, &mut |data| {
        result.extend_from_slice(data);
        Ok(())
    })?;
    Ok(result)
}

/// Decrypts a [`protect`] blob with the same `entropy`.
///
/// # Errors
///
/// [`WinError`] from `CryptUnprotectData` (wrong user, wrong entropy, tampering).
pub fn unprotect(blob: &[u8], entropy: &[u8]) -> Result<WipeBuf<u8>, WinError> {
    if blob.len() > MAX_BLOB {
        return Err(WinError::invalid_argument("CryptUnprotectData"));
    }
    let input = blob_of(blob, "CryptUnprotectData")?;
    let entropy_blob = blob_of(entropy, "CryptUnprotectData")?;
    let entropy_ptr: *const CRYPT_INTEGER_BLOB = if entropy.is_empty() {
        core::ptr::null()
    } else {
        &raw const entropy_blob
    };
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: core::ptr::null_mut(),
    };
    // SAFETY: As in `protect`; the description output pointer is null (not requested).
    let ok = unsafe {
        CryptUnprotectData(
            &raw const input,
            core::ptr::null_mut(),
            entropy_ptr,
            core::ptr::null(),
            core::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut out,
        )
    };
    if ok == 0 {
        return Err(WinError::last("CryptUnprotectData"));
    }
    let mut plain = WipeBuf::with_capacity(usize::try_from(out.cbData).unwrap_or(0));
    take_output(out, &mut |data| {
        plain
            .extend_from_slice(data)
            .map_err(|_| WinError::invalid_argument("CryptUnprotectData"))
    })?;
    Ok(plain)
}
