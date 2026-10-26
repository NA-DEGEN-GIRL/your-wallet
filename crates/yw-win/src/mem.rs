#![allow(unsafe_code)]
//! Secret memory helpers (spec/01 §5.3, §7.1): volatile wiping, a fixed-capacity wiping buffer and
//! the `VirtualLock` page that holds the resident wallet slot (D10).

use core::fmt;
use core::ptr::NonNull;
use core::sync::atomic::{Ordering, compiler_fence};

use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree, VirtualLock,
    VirtualUnlock,
};

use crate::error::WinError;

const PAGE: usize = 4_096;

/// Overwrites `buf` with zeros using volatile writes followed by a `SeqCst` compiler fence.
pub fn wipe(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, exclusive reference into `buf`.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// [`wipe`] for UTF-16 buffers.
pub fn wipe_u16(buf: &mut [u16]) {
    for unit in buf.iter_mut() {
        // SAFETY: `unit` is a valid, aligned, exclusive reference into `buf`.
        unsafe { core::ptr::write_volatile(unit, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

fn wipe_generic<T: Copy + Default>(buf: &mut [T]) {
    for item in buf.iter_mut() {
        // SAFETY: `item` is a valid, aligned, exclusive reference into `buf`; `T: Copy` has no
        // destructor to skip.
        unsafe { core::ptr::write_volatile(item, T::default()) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// A push exceeded the fixed capacity of a [`WipeBuf`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityError;

impl fmt::Display for CapacityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("buffer capacity exceeded")
    }
}

impl std::error::Error for CapacityError {}

/// A fixed-capacity buffer that never reallocates and wipes every removed element and, on drop,
/// all of its contents (spec/01 §5.3: yw-win cannot use zeroize).
pub struct WipeBuf<T: Copy + Default> {
    buf: Vec<T>,
    cap: usize,
}

impl<T: Copy + Default> WipeBuf<T> {
    /// An empty buffer with room for exactly `capacity` elements.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            cap: capacity,
        }
    }

    /// The fixed capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.cap
    }

    /// Number of elements.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Appends one element.
    ///
    /// # Errors
    ///
    /// [`CapacityError`] when full (nothing is written).
    pub fn push(&mut self, value: T) -> Result<(), CapacityError> {
        if self.buf.len() >= self.cap {
            return Err(CapacityError);
        }
        self.buf.push(value);
        Ok(())
    }

    /// Appends all of `values` or nothing.
    ///
    /// # Errors
    ///
    /// [`CapacityError`] when they do not fit.
    pub fn extend_from_slice(&mut self, values: &[T]) -> Result<(), CapacityError> {
        let total = self
            .buf
            .len()
            .checked_add(values.len())
            .ok_or(CapacityError)?;
        if total > self.cap {
            return Err(CapacityError);
        }
        self.buf.extend_from_slice(values);
        Ok(())
    }

    /// Removes and returns the last element, wiping its slot.
    pub fn pop(&mut self) -> Option<T> {
        let last = self.buf.len().checked_sub(1)?;
        let value = self.buf.get(last).copied()?;
        if let Some(slot) = self.buf.get_mut(last..) {
            wipe_generic(slot);
        }
        self.buf.truncate(last);
        Some(value)
    }

    /// Shortens the buffer to `len`, wiping the removed elements.
    pub fn truncate(&mut self, len: usize) {
        if let Some(tail) = self.buf.get_mut(len..) {
            wipe_generic(tail);
        }
        self.buf.truncate(len);
    }

    /// Wipes and empties the buffer.
    pub fn clear(&mut self) {
        self.truncate(0);
    }

    /// The contents.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.buf
    }

    /// The contents, mutable in place (length cannot change).
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.buf
    }
}

impl<T: Copy + Default> Drop for WipeBuf<T> {
    fn drop(&mut self) {
        wipe_generic(&mut self.buf);
    }
}

impl<T: Copy + Default> fmt::Debug for WipeBuf<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "WipeBuf(len={}, [REDACTED])", self.buf.len())
    }
}

/// One committed, `VirtualLock`ed page whose first `N` bytes are exposed (spec/01 §7.1).
///
/// `1 <= N <= 4096` is checked at compile time. Drop wipes the whole page, unlocks and frees it.
pub struct LockedBox<const N: usize> {
    page: NonNull<u8>,
}

impl<const N: usize> LockedBox<N> {
    const VALID_SIZE: () = assert!(N >= 1 && N <= PAGE, "LockedBox size must be 1..=4096");

    /// Allocates and locks a zeroed page (`VirtualAlloc` → `VirtualLock`). There is no fallback:
    /// a lock failure (e.g. `ERROR_WORKING_SET_QUOTA`) is returned.
    ///
    /// # Errors
    ///
    /// The failing call's [`WinError`].
    pub fn new_zeroed() -> Result<Self, WinError> {
        let () = Self::VALID_SIZE;
        // SAFETY: Requests a fresh committed private page; no existing memory is referenced.
        let raw = unsafe {
            VirtualAlloc(
                core::ptr::null(),
                PAGE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        let page = NonNull::new(raw.cast::<u8>()).ok_or_else(|| WinError::last("VirtualAlloc"))?;
        // SAFETY: `page` is the start of the PAGE-byte region just committed.
        let locked = unsafe { VirtualLock(page.as_ptr().cast_const().cast(), PAGE) };
        if locked == 0 {
            let error = WinError::last("VirtualLock");
            // SAFETY: Releases the region reserved above, which nothing else references.
            unsafe { VirtualFree(page.as_ptr().cast(), 0, MEM_RELEASE) };
            return Err(error);
        }
        Ok(Self { page })
    }

    /// The exposed bytes.
    #[must_use]
    pub const fn expose(&self) -> &[u8; N] {
        // SAFETY: The page holds PAGE >= N initialized (zeroed) bytes owned by `self`, aligned for
        // `u8`, and shared borrows of `self` only allow shared access.
        unsafe { &*self.page.as_ptr().cast::<[u8; N]>() }
    }

    /// The exposed bytes, mutably.
    pub const fn expose_mut(&mut self) -> &mut [u8; N] {
        // SAFETY: As in `expose`; `&mut self` guarantees exclusive access.
        unsafe { &mut *self.page.as_ptr().cast::<[u8; N]>() }
    }
}

impl<const N: usize> Drop for LockedBox<N> {
    fn drop(&mut self) {
        // SAFETY: The page has PAGE initialized bytes exclusively owned by `self`.
        let whole = unsafe { core::slice::from_raw_parts_mut(self.page.as_ptr(), PAGE) };
        wipe(whole);
        // SAFETY: Unlocks the region locked in `new_zeroed`.
        unsafe { VirtualUnlock(self.page.as_ptr().cast_const().cast(), PAGE) };
        // SAFETY: Releases the whole reservation; no reference to it outlives `self`.
        unsafe { VirtualFree(self.page.as_ptr().cast(), 0, MEM_RELEASE) };
    }
}

// SAFETY: `LockedBox` exclusively owns its private page (no aliasing pointer escapes except
// through borrows of `self`), so moving it to another thread is sound.
unsafe impl<const N: usize> Send for LockedBox<N> {}
// SAFETY: `&LockedBox` only grants shared read access to the bytes.
unsafe impl<const N: usize> Sync for LockedBox<N> {}

impl<const N: usize> fmt::Debug for LockedBox<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "LockedBox<{N}>([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::{CapacityError, LockedBox, WipeBuf, wipe, wipe_u16};

    #[test]
    fn wipe_zeroes_bytes_and_units() {
        let mut bytes = [1_u8, 2, 3];
        wipe(&mut bytes);
        assert_eq!(bytes, [0; 3]);
        let mut units = [7_u16; 4];
        wipe_u16(&mut units);
        assert_eq!(units, [0; 4]);
    }

    #[test]
    fn wipebuf_is_fixed_capacity_and_all_or_nothing() {
        let mut buf = WipeBuf::<u8>::with_capacity(3);
        assert_eq!(buf.extend_from_slice(b"ab"), Ok(()));
        assert_eq!(buf.extend_from_slice(b"cd"), Err(CapacityError));
        assert_eq!(buf.as_slice(), b"ab");
        assert_eq!(buf.push(b'c'), Ok(()));
        assert_eq!(buf.push(b'd'), Err(CapacityError));
        assert_eq!(buf.pop(), Some(b'c'));
        buf.truncate(1);
        assert_eq!(buf.as_slice(), b"a");
        buf.clear();
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), 3);
        assert!(!format!("{buf:?}").contains('a'));
    }

    #[test]
    fn locked_box_is_zeroed_writable_and_redacted() {
        let mut slot = LockedBox::<320>::new_zeroed().expect("VirtualLock of one page");
        assert!(slot.expose().iter().all(|byte| *byte == 0));
        slot.expose_mut()[0] = 0xAA;
        assert_eq!(slot.expose()[0], 0xAA);
        assert_eq!(format!("{slot:?}"), "LockedBox<320>([REDACTED])");
    }
}
