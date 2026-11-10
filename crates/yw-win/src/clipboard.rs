#![allow(unsafe_code)]
//! Clipboard (spec/01 §7.3, spec/04 §4.7–§4.8, D11).
//!
//! Secret copies set the three exclusion formats (monitor processing, clipboard history, cloud
//! upload) to DWORD 0 before the text, all inside one `OpenClipboard`…`CloseClipboard`; if any
//! exclusion format fails the clipboard is emptied and no text is placed. A secret copy also
//! places a private registered format ([`MARKER_FORMAT`]) holding a random per-copy nonce; the
//! automatic clear empties the clipboard only while that nonce is still there. (The sequence
//! number cannot identify our copy: `CloseClipboard` itself adds the synthesized `CF_LOCALE`,
//! `CF_TEXT` and `CF_OEMTEXT` formats and bumps it.) Paste-clear compares the sequence number
//! read with the text (reading does not change it). A copy that outlived the run that made it (the
//! process ended before its clear) is recognised by the marker format alone ([`SecretClip::ANY`]).
//! The sequencing logic runs over [`ClipOps`] so it is tested without a real clipboard.

use core::fmt;

use windows_sys::Win32::Foundation::{GlobalFree, HANDLE, HWND};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber,
    IsClipboardFormatAvailable, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
};
use windows_sys::Win32::System::Memory::{
    GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock,
};
use windows_sys::Win32::System::Ole::CF_UNICODETEXT;

use crate::error::WinError;
use crate::mem::WipeBuf;
use crate::ui::Window;
use crate::wide::to_wide;

/// Longest text accepted (UTF-16 units, excluding the terminator).
pub const MAX_TEXT_UNITS: usize = 4_096;
/// Formats set to DWORD 0 for secret copies (D11).
pub const EXCLUSION_FORMATS: [&str; 3] = [
    "ExcludeClipboardContentFromMonitorProcessing",
    "CanIncludeInClipboardHistory",
    "CanUploadToCloudClipboard",
];
/// Private format beside a secret copy's text: the copy's random nonce ([`SecretClip`]).
pub const MARKER_FORMAT: &str = "YourWalletV3SecretClipNonce";
/// Nonce length in bytes.
const NONCE_LEN: usize = 16;
const NONCE_LEN_U32: u32 = 16;
const OPEN_ATTEMPTS: u32 = 5;
const OPEN_RETRY_MS: u32 = 20;

/// Clipboard failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClipError {
    /// `OpenClipboard` failed 5 times 20 ms apart.
    Busy,
    /// The text exceeds the limit (also: no text available when reading).
    TooLong,
    /// A clipboard call failed.
    Os(WinError),
}

impl fmt::Display for ClipError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => formatter.write_str("clipboard busy"),
            Self::TooLong => formatter.write_str("clipboard text too long"),
            Self::Os(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ClipError {}

/// One secret copy, identified by the random nonce placed beside its text in [`MARKER_FORMAT`].
/// [`clear_secret`] empties the clipboard only while that nonce is still on it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecretClip {
    /// `None`: [`SecretClip::ANY`].
    nonce: Option<[u8; NONCE_LEN]>,
}

impl SecretClip {
    /// Any secret copy, whichever copy and run placed it: [`clear_secret`] with this empties the
    /// clipboard while [`MARKER_FORMAT`] holds a nonce of the right length. For a copy that
    /// outlived the run that made it (spec/04 §4.8): the next start clears it this way (it holds
    /// the single-instance mutex, so no running copy of the app placed it), and so does the panic
    /// hook ([`try_clear_secret_windowless`]). A running app clears its own copies by their nonce.
    pub const ANY: Self = Self { nonce: None };

    /// Whether `marker` (the bytes of [`MARKER_FORMAT`]) is this copy's.
    fn marks(&self, marker: &[u8]) -> bool {
        match &self.nonce {
            Some(nonce) => marker == nonce.as_slice(),
            None => marker.len() == NONCE_LEN,
        }
    }
}

impl fmt::Debug for SecretClip {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretClip(..)")
    }
}

/// The primitive clipboard operations the sequencing logic uses.
pub(crate) trait ClipOps {
    fn open(&mut self) -> bool;
    fn close(&mut self);
    fn empty(&mut self) -> Result<(), WinError>;
    fn register_format(&mut self, name: &str) -> Result<u32, WinError>;
    fn set_dword(&mut self, format: u32, value: u32) -> Result<(), WinError> {
        self.set_bytes(format, &value.to_le_bytes())
    }
    fn set_bytes(&mut self, format: u32, bytes: &[u8]) -> Result<(), WinError>;
    /// The bytes of `format` when present and at most `max_len` long (`None` otherwise).
    fn get_bytes(&mut self, format: u32, max_len: usize) -> Result<Option<Vec<u8>>, ClipError>;
    fn set_unicode(&mut self, units_with_nul: &[u16]) -> Result<(), WinError>;
    fn get_unicode(&mut self, max_units: usize) -> Result<Option<WipeBuf<u16>>, ClipError>;
    fn sequence(&mut self) -> u32;
    fn sleep(&mut self, ms: u32);
}

fn open_with_retry(ops: &mut impl ClipOps) -> Result<(), ClipError> {
    open_with_attempts(ops, OPEN_ATTEMPTS)
}

/// `attempts` tries of `OpenClipboard`, [`OPEN_RETRY_MS`] apart (no sleep after the last).
fn open_with_attempts(ops: &mut impl ClipOps, attempts: u32) -> Result<(), ClipError> {
    for attempt in 0..attempts {
        if ops.open() {
            return Ok(());
        }
        if attempt.saturating_add(1) < attempts {
            ops.sleep(OPEN_RETRY_MS);
        }
    }
    Err(ClipError::Busy)
}

fn with_nul(text: &[u16]) -> WipeBuf<u16> {
    let mut units = WipeBuf::with_capacity(text.len().saturating_add(1));
    let _ = units.extend_from_slice(text);
    let _ = units.push(0);
    units
}

pub(crate) fn set_secret_with(
    ops: &mut impl ClipOps,
    text: &[u16],
    nonce: [u8; NONCE_LEN],
) -> Result<SecretClip, ClipError> {
    if text.len() > MAX_TEXT_UNITS {
        return Err(ClipError::TooLong);
    }
    let units = with_nul(text);
    open_with_retry(ops)?;
    let result = (|| {
        ops.empty().map_err(ClipError::Os)?;
        for name in EXCLUSION_FORMATS {
            let placed = ops
                .register_format(name)
                .and_then(|format| ops.set_dword(format, 0));
            if let Err(error) = placed {
                let _ = ops.empty();
                return Err(ClipError::Os(error));
            }
        }
        let marked = ops
            .register_format(MARKER_FORMAT)
            .and_then(|format| ops.set_bytes(format, &nonce));
        if let Err(error) = marked {
            let _ = ops.empty();
            return Err(ClipError::Os(error));
        }
        if let Err(error) = ops.set_unicode(units.as_slice()) {
            let _ = ops.empty();
            return Err(ClipError::Os(error));
        }
        Ok(SecretClip { nonce: Some(nonce) })
    })();
    ops.close();
    result
}

/// Empties the clipboard only while it still carries `clip`'s nonce (our copy, unreplaced; any
/// nonce for [`SecretClip::ANY`]).
pub(crate) fn clear_secret_with(
    ops: &mut impl ClipOps,
    clip: &SecretClip,
) -> Result<bool, ClipError> {
    clear_secret_attempts(ops, clip, OPEN_ATTEMPTS)
}

/// [`clear_secret_with`] with `attempts` tries of `OpenClipboard`.
pub(crate) fn clear_secret_attempts(
    ops: &mut impl ClipOps,
    clip: &SecretClip,
    attempts: u32,
) -> Result<bool, ClipError> {
    open_with_attempts(ops, attempts)?;
    let result = (|| {
        let format = ops.register_format(MARKER_FORMAT).map_err(ClipError::Os)?;
        let ours = ops
            .get_bytes(format, NONCE_LEN)?
            .is_some_and(|bytes| clip.marks(&bytes));
        if ours {
            ops.empty().map_err(ClipError::Os)?;
        }
        Ok(ours)
    })();
    ops.close();
    result
}

pub(crate) fn set_plain_with(ops: &mut impl ClipOps, text: &[u16]) -> Result<(), ClipError> {
    if text.len() > MAX_TEXT_UNITS {
        return Err(ClipError::TooLong);
    }
    let units = with_nul(text);
    open_with_retry(ops)?;
    let result = ops
        .empty()
        .and_then(|()| ops.set_unicode(units.as_slice()))
        .map_err(ClipError::Os);
    ops.close();
    result
}

pub(crate) fn read_with(
    ops: &mut impl ClipOps,
    max_units: usize,
) -> Result<(WipeBuf<u16>, u32), ClipError> {
    open_with_retry(ops)?;
    let result = ops.get_unicode(max_units);
    let sequence = ops.sequence();
    ops.close();
    match result? {
        Some(units) => Ok((units, sequence)),
        None => Err(ClipError::TooLong),
    }
}

pub(crate) fn clear_if_unchanged_with(ops: &mut impl ClipOps, seq: u32) -> Result<bool, ClipError> {
    if ops.sequence() != seq {
        return Ok(false);
    }
    open_with_retry(ops)?;
    let unchanged = ops.sequence() == seq;
    let result = if unchanged {
        ops.empty().map_err(ClipError::Os)
    } else {
        Ok(())
    };
    ops.close();
    result.map(|()| unchanged)
}

struct Win32Clip {
    owner: HWND,
}

fn global_with(bytes_len: usize, fill: impl FnOnce(*mut u8)) -> Result<HANDLE, WinError> {
    // SAFETY: Allocates movable global memory of the requested size.
    let memory = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes_len) };
    if memory.is_null() {
        return Err(WinError::last("GlobalAlloc"));
    }
    // SAFETY: Locks the memory just allocated.
    let pointer = unsafe { GlobalLock(memory) };
    if pointer.is_null() {
        let error = WinError::last("GlobalLock");
        // SAFETY: Frees the unlocked allocation we own.
        unsafe { GlobalFree(memory) };
        return Err(error);
    }
    fill(pointer.cast::<u8>());
    // SAFETY: Unlocks the memory locked above.
    unsafe { GlobalUnlock(memory) };
    Ok(memory)
}

/// Zeroes `bytes_len` bytes of the (unlocked, still ours) global block and frees it. Used when
/// `SetClipboardData` refused the block, which may hold secret text.
fn wipe_and_free(memory: HANDLE, bytes_len: usize) {
    // SAFETY: Locks the movable block we allocated and still own.
    let pointer = unsafe { GlobalLock(memory) };
    if !pointer.is_null() {
        // SAFETY: The locked block holds at least `bytes_len` bytes (allocated with that size),
        // writable and not aliased while locked by this thread.
        let bytes = unsafe { core::slice::from_raw_parts_mut(pointer.cast::<u8>(), bytes_len) };
        crate::mem::wipe(bytes);
        // SAFETY: Unlocks the block locked above.
        unsafe { GlobalUnlock(memory) };
    }
    // SAFETY: Frees the unlocked allocation we own (ownership never transferred).
    unsafe { GlobalFree(memory) };
}

impl Win32Clip {
    fn place(memory: HANDLE, bytes_len: usize, format: u32) -> Result<(), WinError> {
        // SAFETY: The clipboard is open by this thread; on success the system owns `memory`.
        let placed = unsafe { SetClipboardData(format, memory) };
        if placed.is_null() {
            let error = WinError::last("SetClipboardData");
            wipe_and_free(memory, bytes_len);
            return Err(error);
        }
        Ok(())
    }
}

/// The text length of a `CF_UNICODETEXT` block of `available` units, scanning at most
/// `max_units + 1` units for the terminator: `Some(len)` when `len <= max_units` (NUL found, or
/// a short block without one), `None` when the text is longer than `max_units`.
fn text_len_within(units: &[u16], available: usize, max_units: usize) -> Option<usize> {
    match units.iter().position(|unit| *unit == 0) {
        Some(len) => Some(len),
        None if available <= max_units => Some(available),
        None => None,
    }
}

impl ClipOps for Win32Clip {
    fn open(&mut self) -> bool {
        // SAFETY: Opens the clipboard for our window (or the task when null).
        unsafe { OpenClipboard(self.owner) != 0 }
    }

    fn close(&mut self) {
        // SAFETY: Closes the clipboard opened by this thread.
        unsafe { CloseClipboard() };
    }

    fn empty(&mut self) -> Result<(), WinError> {
        // SAFETY: Empties the clipboard opened by this thread.
        if unsafe { EmptyClipboard() } == 0 {
            return Err(WinError::last("EmptyClipboard"));
        }
        Ok(())
    }

    fn register_format(&mut self, name: &str) -> Result<u32, WinError> {
        let wide = to_wide(name, "RegisterClipboardFormatW")?;
        // SAFETY: `wide` is NUL-terminated and live.
        let format = unsafe { RegisterClipboardFormatW(wide.as_ptr()) };
        if format == 0 {
            return Err(WinError::last("RegisterClipboardFormatW"));
        }
        Ok(format)
    }

    fn set_bytes(&mut self, format: u32, bytes: &[u8]) -> Result<(), WinError> {
        let memory = global_with(bytes.len(), |pointer| {
            // SAFETY: `pointer` addresses `bytes.len()` writable locked bytes.
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer, bytes.len()) };
        })?;
        Self::place(memory, bytes.len(), format)
    }

    fn get_bytes(&mut self, format: u32, max_len: usize) -> Result<Option<Vec<u8>>, ClipError> {
        // SAFETY: Queries the open clipboard.
        if unsafe { IsClipboardFormatAvailable(format) } == 0 {
            return Ok(None);
        }
        // SAFETY: The clipboard is open; the returned handle stays owned by the system.
        let handle = unsafe { GetClipboardData(format) };
        if handle.is_null() {
            return Ok(None);
        }
        // SAFETY: Queries the size of the system-owned global block.
        let size = unsafe { GlobalSize(handle) };
        if size == 0 || size > max_len {
            return Ok(None);
        }
        // SAFETY: Locks the system-owned global block for reading.
        let pointer = unsafe { GlobalLock(handle) };
        if pointer.is_null() {
            return Err(ClipError::Os(WinError::last("GlobalLock")));
        }
        // SAFETY: The locked block holds `size` readable bytes.
        let bytes = unsafe { core::slice::from_raw_parts(pointer.cast::<u8>(), size) }.to_vec();
        // SAFETY: Unlocks the block locked above.
        unsafe { GlobalUnlock(handle) };
        Ok(Some(bytes))
    }

    #[expect(
        clippy::cast_ptr_alignment,
        reason = "GlobalAlloc memory is 8-byte aligned, enough for u16"
    )]
    fn set_unicode(&mut self, units_with_nul: &[u16]) -> Result<(), WinError> {
        let byte_len = units_with_nul.len().saturating_mul(2);
        let memory = global_with(byte_len, |pointer| {
            // SAFETY: `pointer` addresses `byte_len` writable locked bytes; GlobalAlloc memory is
            // suitably aligned for u16.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    units_with_nul.as_ptr(),
                    pointer.cast::<u16>(),
                    units_with_nul.len(),
                );
            }
        })?;
        Self::place(memory, byte_len, u32::from(CF_UNICODETEXT))
    }

    fn get_unicode(&mut self, max_units: usize) -> Result<Option<WipeBuf<u16>>, ClipError> {
        // SAFETY: Queries the open clipboard.
        if unsafe { IsClipboardFormatAvailable(u32::from(CF_UNICODETEXT)) } == 0 {
            return Ok(None);
        }
        // SAFETY: The clipboard is open; the returned handle stays owned by the system.
        let handle = unsafe { GetClipboardData(u32::from(CF_UNICODETEXT)) };
        if handle.is_null() {
            return Ok(None);
        }
        // SAFETY: Queries the size of the system-owned global block.
        let size = unsafe { GlobalSize(handle) };
        if size == 0 {
            // `GlobalSize` failed (or an empty block): no text to read.
            return Ok(None);
        }
        // SAFETY: Locks the system-owned global block for reading.
        let pointer = unsafe { GlobalLock(handle) };
        if pointer.is_null() {
            return Err(ClipError::Os(WinError::last("GlobalLock")));
        }
        let available = size / 2;
        // Never look past `max_units + 1` units, however large the block claims to be.
        let scanned = available.min(max_units.saturating_add(1));
        // SAFETY: The locked block holds `size` bytes, i.e. at least `scanned` u16 units, aligned.
        let units = unsafe { core::slice::from_raw_parts(pointer.cast::<u16>(), scanned) };
        let result = match text_len_within(units, available, max_units) {
            None => Err(ClipError::TooLong),
            Some(text_len) => {
                let mut out = WipeBuf::with_capacity(text_len);
                let _ = out.extend_from_slice(units.get(..text_len).unwrap_or(&[]));
                Ok(Some(out))
            }
        };
        // SAFETY: Unlocks the block locked above.
        unsafe { GlobalUnlock(handle) };
        result
    }

    fn sequence(&mut self) -> u32 {
        // SAFETY: Reads the clipboard sequence number.
        unsafe { GetClipboardSequenceNumber() }
    }

    fn sleep(&mut self, ms: u32) {
        std::thread::sleep(std::time::Duration::from_millis(u64::from(ms)));
    }
}

fn ops_for(owner: &Window) -> Win32Clip {
    Win32Clip {
        owner: core::ptr::with_exposed_provenance_mut(owner.live_raw_id()),
    }
}

/// Copies non-secret text (addresses, hashes; ≤ 4096 chars).
///
/// # Errors
///
/// [`ClipError`].
pub fn set_text(owner: &Window, text: &str) -> Result<(), ClipError> {
    let units: Vec<u16> = text.encode_utf16().collect();
    set_plain_with(&mut ops_for(owner), &units)
}

fn random_nonce() -> Result<[u8; NONCE_LEN], ClipError> {
    let mut nonce = [0_u8; NONCE_LEN];
    // SAFETY: `nonce` is a writable buffer of exactly the length passed; no algorithm handle is
    // needed with BCRYPT_USE_SYSTEM_PREFERRED_RNG.
    let status = unsafe {
        BCryptGenRandom(
            core::ptr::null_mut(),
            nonce.as_mut_ptr(),
            NONCE_LEN_U32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(ClipError::Os(WinError::new(
            "BCryptGenRandom",
            status.cast_unsigned(),
        )));
    }
    Ok(nonce)
}

/// Copies secret text with the three exclusion formats and a fresh random nonce in
/// [`MARKER_FORMAT`]; the returned [`SecretClip`] is what [`clear_secret`] looks for.
///
/// # Errors
///
/// [`ClipError`].
pub fn set_secret_text(owner: &Window, text: &[u16]) -> Result<SecretClip, ClipError> {
    let nonce = random_nonce()?;
    set_secret_with(&mut ops_for(owner), text, nonce)
}

/// Empties the clipboard only if it still holds the secret copy `clip` (its nonce is present).
///
/// # Errors
///
/// [`ClipError`].
pub fn clear_secret(owner: &Window, clip: &SecretClip) -> Result<bool, ClipError> {
    clear_secret_with(&mut ops_for(owner), clip)
}

/// [`clear_secret`] with a single `OpenClipboard` attempt and no sleep: the retry of a clear that
/// found the clipboard busy, once per timer tick of the UI thread.
///
/// # Errors
///
/// [`ClipError::Busy`] when another program holds the clipboard open, or another [`ClipError`].
pub fn try_clear_secret(owner: &Window, clip: &SecretClip) -> Result<bool, ClipError> {
    clear_secret_attempts(&mut ops_for(owner), clip, 1)
}

/// [`try_clear_secret`] with the clipboard opened for the calling thread instead of a window: for
/// code with no window at hand on any thread, namely the panic hook just before the process
/// aborts (spec/04 §1.5, §4.8). One `OpenClipboard` attempt, no sleep.
///
/// # Errors
///
/// [`ClipError::Busy`] when another program holds the clipboard open, or another [`ClipError`].
pub fn try_clear_secret_windowless(clip: &SecretClip) -> Result<bool, ClipError> {
    let mut ops = Win32Clip {
        owner: core::ptr::null_mut(),
    };
    clear_secret_attempts(&mut ops, clip, 1)
}

/// Reads `CF_UNICODETEXT` (≤ `max_units`) and the current sequence number.
///
/// # Errors
///
/// [`ClipError::TooLong`] when longer or absent, or another [`ClipError`].
pub fn read_text(owner: &Window, max_units: usize) -> Result<(WipeBuf<u16>, u32), ClipError> {
    read_with(&mut ops_for(owner), max_units)
}

/// Reads the clipboard bitmap as `CF_DIB` bytes (`BITMAPINFOHEADER` + optional masks/palette +
/// pixels; a screenshot from Win+Shift+S is placed in this format by the system) when present
/// and at most `max_len` bytes; `Ok(None)` when there is no bitmap (spec/13 §6).
///
/// # Errors
///
/// [`ClipError::Busy`] or [`ClipError::Os`].
pub fn read_dib(owner: &Window, max_len: usize) -> Result<Option<Vec<u8>>, ClipError> {
    let mut ops = ops_for(owner);
    open_with_retry(&mut ops)?;
    let result = ops.get_bytes(u32::from(windows_sys::Win32::System::Ole::CF_DIB), max_len);
    ops.close();
    result
}

/// Empties the clipboard only if its sequence number is still `seq` (paste-clear: `seq` comes
/// from [`read_text`], and reading does not change it).
///
/// # Errors
///
/// [`ClipError`].
pub fn clear_if_unchanged(owner: &Window, seq: u32) -> Result<bool, ClipError> {
    clear_if_unchanged_with(&mut ops_for(owner), seq)
}

#[cfg(test)]
mod tests {
    use super::{
        ClipError, ClipOps, EXCLUSION_FORMATS, MARKER_FORMAT, MAX_TEXT_UNITS, SecretClip,
        clear_if_unchanged_with, clear_secret_attempts, clear_secret_with, read_with,
        set_plain_with, set_secret_with, text_len_within,
    };
    use crate::error::WinError;
    use crate::mem::WipeBuf;

    const NONCE: [u8; 16] = [7; 16];

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Op {
        Open,
        Close,
        Empty,
        Dword(String, u32),
        Bytes(String, Vec<u8>),
        Text(Vec<u16>),
        Sleep,
    }

    /// Models the Windows clipboard: every change bumps the sequence number, and closing after a
    /// change bumps it again (the synthesized `CF_LOCALE`/`CF_TEXT`/`CF_OEMTEXT`).
    #[derive(Default)]
    #[expect(clippy::struct_excessive_bools, reason = "independent mock switches")]
    struct Mock {
        ops: Vec<Op>,
        names: Vec<String>,
        open_failures: u32,
        fail_format: Option<&'static str>,
        fail_text: bool,
        seq: u32,
        content: Option<Vec<u16>>,
        formats: Vec<(u32, Vec<u8>)>,
        changed: bool,
        bump_on_open: bool,
        /// Another process copies (text only) right after our `CloseClipboard`.
        other_copies_on_close: bool,
    }

    impl Mock {
        fn change(&mut self) {
            self.seq += 1;
            self.changed = true;
        }
    }

    impl ClipOps for Mock {
        fn open(&mut self) -> bool {
            if self.open_failures > 0 {
                self.open_failures -= 1;
                return false;
            }
            if self.bump_on_open {
                self.seq += 1;
            }
            self.changed = false;
            self.ops.push(Op::Open);
            true
        }
        fn close(&mut self) {
            self.ops.push(Op::Close);
            if self.changed {
                self.seq += 3;
                self.changed = false;
            }
            if self.other_copies_on_close {
                self.seq += 5;
                self.formats.clear();
                self.content = Some(vec![0x6F]);
            }
        }
        fn empty(&mut self) -> Result<(), WinError> {
            self.ops.push(Op::Empty);
            self.change();
            self.content = None;
            self.formats.clear();
            Ok(())
        }
        fn register_format(&mut self, name: &str) -> Result<u32, WinError> {
            if self.fail_format == Some(name) {
                return Err(WinError::new("RegisterClipboardFormatW", 5));
            }
            let index = if let Some(index) = self.names.iter().position(|known| known == name) {
                index
            } else {
                self.names.push(name.to_owned());
                self.names.len() - 1
            };
            Ok(u32::try_from(index).unwrap() + 0xC001)
        }
        fn set_dword(&mut self, format: u32, value: u32) -> Result<(), WinError> {
            let name = self.names[usize::try_from(format - 0xC001).unwrap()].clone();
            self.ops.push(Op::Dword(name, value));
            self.formats.push((format, value.to_le_bytes().to_vec()));
            self.change();
            Ok(())
        }
        fn set_bytes(&mut self, format: u32, bytes: &[u8]) -> Result<(), WinError> {
            let name = self.names[usize::try_from(format - 0xC001).unwrap()].clone();
            self.ops.push(Op::Bytes(name, bytes.to_vec()));
            self.formats.push((format, bytes.to_vec()));
            self.change();
            Ok(())
        }
        fn get_bytes(&mut self, format: u32, max: usize) -> Result<Option<Vec<u8>>, ClipError> {
            Ok(self
                .formats
                .iter()
                .find(|(known, bytes)| *known == format && bytes.len() <= max)
                .map(|(_, bytes)| bytes.clone()))
        }
        fn set_unicode(&mut self, units: &[u16]) -> Result<(), WinError> {
            if self.fail_text {
                return Err(WinError::new("SetClipboardData", 5));
            }
            self.ops.push(Op::Text(units.to_vec()));
            self.content = Some(units[..units.len() - 1].to_vec());
            self.change();
            Ok(())
        }
        fn get_unicode(&mut self, max: usize) -> Result<Option<WipeBuf<u16>>, ClipError> {
            match &self.content {
                None => Ok(None),
                Some(text) if text.len() > max => Err(ClipError::TooLong),
                Some(text) => {
                    let mut out = WipeBuf::with_capacity(text.len());
                    out.extend_from_slice(text).unwrap();
                    Ok(Some(out))
                }
            }
        }
        fn sequence(&mut self) -> u32 {
            self.seq
        }
        fn sleep(&mut self, _ms: u32) {
            self.ops.push(Op::Sleep);
        }
    }

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn secret_copy_sets_three_exclusions_marker_then_text_in_one_session() {
        let mut mock = Mock::default();
        set_secret_with(&mut mock, &units("abc"), NONCE).unwrap();
        let mut expected = vec![Op::Open, Op::Empty];
        for name in EXCLUSION_FORMATS {
            expected.push(Op::Dword(name.to_owned(), 0));
        }
        expected.push(Op::Bytes(MARKER_FORMAT.to_owned(), NONCE.to_vec()));
        let mut text = units("abc");
        text.push(0);
        expected.push(Op::Text(text));
        expected.push(Op::Close);
        assert_eq!(mock.ops, expected);
    }

    /// Regression (adversarial PoC): `CloseClipboard` bumps the sequence number after a secret
    /// copy, so a sequence-based auto-clear never fired. The nonce-based clear still does.
    #[test]
    fn secret_copy_is_cleared_although_close_bumped_the_sequence() {
        let mut mock = Mock::default();
        let clip = set_secret_with(&mut mock, &units("abandon about"), NONCE).unwrap();
        assert_eq!(clear_secret_with(&mut mock, &clip), Ok(true));
        assert!(mock.content.is_none());
        assert!(mock.formats.is_empty());
        // A second clear finds nothing of ours.
        assert_eq!(clear_secret_with(&mut mock, &clip), Ok(false));
    }

    #[test]
    fn a_copy_by_another_process_after_ours_is_never_cleared() {
        let mut mock = Mock {
            other_copies_on_close: true,
            ..Mock::default()
        };
        let clip = set_secret_with(&mut mock, &units("abc"), NONCE).unwrap();
        mock.other_copies_on_close = false;
        assert_eq!(clear_secret_with(&mut mock, &clip), Ok(false));
        assert_eq!(mock.content, Some(vec![0x6F]));

        // Our own later copy (another nonce) is not the earlier copy either.
        let mut mock = Mock::default();
        let first = set_secret_with(&mut mock, &units("abc"), NONCE).unwrap();
        set_secret_with(&mut mock, &units("def"), [9; 16]).unwrap();
        assert_eq!(clear_secret_with(&mut mock, &first), Ok(false));
        assert_eq!(mock.content, Some(units("def")));

        // A plain copy (address) replaced it: kept.
        let mut mock = Mock::default();
        let clip = set_secret_with(&mut mock, &units("abc"), NONCE).unwrap();
        set_plain_with(&mut mock, &units("0xabc")).unwrap();
        assert_eq!(clear_secret_with(&mut mock, &clip), Ok(false));
        assert_eq!(mock.content, Some(units("0xabc")));
    }

    /// A copy whose run ended before its clear (a crash, a forced kill): the next start knows no
    /// nonce, only the marker. `ANY` clears it, but never a later copy by another program (that
    /// emptied the marker) nor a marker of another length.
    #[test]
    fn any_clears_an_earlier_runs_copy_but_not_a_later_copy() {
        let mut mock = Mock::default();
        set_secret_with(&mut mock, &units("abandon about"), NONCE).unwrap();
        assert_eq!(clear_secret_with(&mut mock, &SecretClip::ANY), Ok(true));
        assert!(mock.content.is_none());
        assert!(mock.formats.is_empty());

        let mut mock = Mock::default();
        set_secret_with(&mut mock, &units("abandon about"), NONCE).unwrap();
        set_plain_with(&mut mock, &units("0xabc")).unwrap();
        assert_eq!(clear_secret_with(&mut mock, &SecretClip::ANY), Ok(false));
        assert_eq!(mock.content, Some(units("0xabc")));

        let format = mock.register_format(MARKER_FORMAT).unwrap();
        mock.set_bytes(format, &[7; 8]).unwrap();
        assert_eq!(clear_secret_with(&mut mock, &SecretClip::ANY), Ok(false));
        assert_eq!(mock.content, Some(units("0xabc")));
    }

    #[test]
    fn text_scan_stops_after_max_units_plus_one() {
        // Terminated within the limit.
        assert_eq!(text_len_within(&units("ab\0zz"), 5, 4), Some(2));
        // No terminator in a block that is short enough: the whole block.
        assert_eq!(text_len_within(&units("abc"), 3, 4), Some(3));
        // `max + 1` units scanned without a terminator: too long, whatever follows.
        assert_eq!(text_len_within(&units("abcde"), 1_000_000, 4), None);
        // Exactly `max` units then the terminator.
        assert_eq!(text_len_within(&units("abcd\0"), 9, 4), Some(4));
        assert_eq!(text_len_within(&[], 0, 4), Some(0));
    }

    #[test]
    fn a_failing_exclusion_or_marker_format_leaves_no_text() {
        for name in EXCLUSION_FORMATS.into_iter().chain([MARKER_FORMAT]) {
            let mut mock = Mock {
                fail_format: Some(name),
                ..Mock::default()
            };
            assert!(matches!(
                set_secret_with(&mut mock, &units("secret"), NONCE),
                Err(ClipError::Os(_))
            ));
            assert!(!mock.ops.iter().any(|op| matches!(op, Op::Text(_))));
            assert_eq!(mock.ops.last(), Some(&Op::Close));
            assert_eq!(mock.ops.iter().filter(|op| **op == Op::Empty).count(), 2);
        }
        let mut mock = Mock {
            fail_text: true,
            ..Mock::default()
        };
        assert!(set_secret_with(&mut mock, &units("x"), NONCE).is_err());
        assert!(mock.content.is_none());
        assert!(mock.formats.is_empty());
    }

    #[test]
    fn open_retries_five_times_then_busy() {
        let mut mock = Mock {
            open_failures: 5,
            ..Mock::default()
        };
        assert_eq!(
            set_secret_with(&mut mock, &units("x"), NONCE),
            Err(ClipError::Busy)
        );
        assert_eq!(mock.ops.iter().filter(|op| **op == Op::Sleep).count(), 4);
        let mut mock = Mock {
            open_failures: 4,
            ..Mock::default()
        };
        assert!(set_secret_with(&mut mock, &units("x"), NONCE).is_ok());

        // The timer-tick retry of a busy clear: one attempt, never a sleep on the UI thread.
        let mut mock = Mock::default();
        let clip = set_secret_with(&mut mock, &units("x"), NONCE).unwrap();
        mock.open_failures = 1;
        mock.ops.clear();
        assert_eq!(
            clear_secret_attempts(&mut mock, &clip, 1),
            Err(ClipError::Busy)
        );
        assert!(mock.ops.is_empty());
        assert_eq!(clear_secret_attempts(&mut mock, &clip, 1), Ok(true));
        assert!(mock.content.is_none());
    }

    #[test]
    fn too_long_is_rejected_before_opening() {
        let mut mock = Mock::default();
        let long = vec![0x61_u16; MAX_TEXT_UNITS + 1];
        assert_eq!(
            set_secret_with(&mut mock, &long, NONCE),
            Err(ClipError::TooLong)
        );
        assert_eq!(set_plain_with(&mut mock, &long), Err(ClipError::TooLong));
        assert!(mock.ops.is_empty());
        assert!(set_secret_with(&mut mock, &long[..MAX_TEXT_UNITS], NONCE).is_ok());
    }

    #[test]
    fn paste_clear_only_when_sequence_unchanged() {
        // Paste of another app's (closed) copy: reading leaves the sequence alone.
        let mut mock = Mock::default();
        set_plain_with(&mut mock, &units("s")).unwrap();
        let (_, seq) = read_with(&mut mock, 16).unwrap();
        assert_eq!(clear_if_unchanged_with(&mut mock, seq), Ok(true));
        assert!(mock.content.is_none());

        let mut mock = Mock::default();
        set_plain_with(&mut mock, &units("s")).unwrap();
        let (_, seq) = read_with(&mut mock, 16).unwrap();
        set_plain_with(&mut mock, &units("other")).unwrap();
        mock.ops.clear();
        assert_eq!(clear_if_unchanged_with(&mut mock, seq), Ok(false));
        assert!(mock.ops.is_empty());
        assert_eq!(mock.content, Some(units("other")));

        let mut racing = Mock {
            bump_on_open: true,
            ..Mock::default()
        };
        let seq = racing.seq;
        assert_eq!(clear_if_unchanged_with(&mut racing, seq), Ok(false));
        assert!(!racing.ops.contains(&Op::Empty));
    }

    #[test]
    fn plain_copy_has_no_exclusion_formats_and_read_returns_sequence() {
        let mut mock = Mock::default();
        set_plain_with(&mut mock, &units("0xabc")).unwrap();
        assert!(
            !mock
                .ops
                .iter()
                .any(|op| matches!(op, Op::Dword(..) | Op::Bytes(..)))
        );
        let (text, seq) = read_with(&mut mock, 16).unwrap();
        assert_eq!(text.as_slice(), units("0xabc").as_slice());
        assert_eq!(seq, mock.seq);
        assert_eq!(read_with(&mut mock, 2).map(|_| ()), Err(ClipError::TooLong));
        let mut empty = Mock::default();
        assert_eq!(
            read_with(&mut empty, 16).map(|_| ()),
            Err(ClipError::TooLong)
        );
    }
}
