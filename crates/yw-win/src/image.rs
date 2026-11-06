#![allow(unsafe_code)]
//! Image file decoding through the GDI+ flat API (spec/13 §6): PNG, JPEG, BMP and GIF files (a
//! saved Win+Shift+S screenshot is PNG) become 32-bit BGRA pixels for the QR decoder. The file is
//! read by GDI+ only; nothing is written. Images above [`MAX_PIXELS`] are refused.

use std::path::Path;

use windows_sys::Win32::Graphics::GdiPlus::{
    BitmapData, GdipBitmapLockBits, GdipBitmapUnlockBits, GdipCreateBitmapFromFile,
    GdipDisposeImage, GdipGetImageHeight, GdipGetImageWidth, GdiplusShutdown, GdiplusStartup,
    GdiplusStartupInput, GdiplusStartupOutput, GpBitmap, GpImage, ImageLockModeRead, Rect,
};

use crate::error::WinError;
use crate::wide::path_wide;

/// Largest image accepted (pixels; 8K × 8K).
pub const MAX_PIXELS: u64 = 64 * 1_024 * 1_024;
/// `PixelFormat32bppARGB` (`GdiPlusPixelFormats.h`: index 10 | 32 bpp | alpha | GDI | canonical).
const PIXEL_FORMAT_32BPP_ARGB: i32 = 0x0026_200A;

/// A decoded image: `width × height` pixels, 4 bytes each in B, G, R, A order, top row first.
#[derive(Clone, PartialEq, Eq)]
pub struct Bgra {
    /// Width.
    pub width: usize,
    /// Height.
    pub height: usize,
    /// Pixels (`width * height * 4` bytes).
    pub pixels: Vec<u8>,
}

impl core::fmt::Debug for Bgra {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "Bgra({}x{})", self.width, self.height)
    }
}

struct Session(usize);

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: The token came from a successful `GdiplusStartup` and is shut down once.
        unsafe { GdiplusShutdown(self.0) };
    }
}

struct Bitmap(*mut GpBitmap);

impl Drop for Bitmap {
    fn drop(&mut self) {
        // SAFETY: The bitmap came from `GdipCreateBitmapFromFile` and is disposed once (before the
        // session, which is declared earlier and so dropped later).
        unsafe { GdipDisposeImage(self.0.cast::<GpImage>()) };
    }
}

#[expect(
    clippy::cast_sign_loss,
    reason = "the GDI+ Status is kept bit for bit in WinError::code"
)]
const fn failure(api: &'static str, status: i32) -> WinError {
    WinError::new(api, status as u32)
}

/// Decodes the image file at `path`.
///
/// # Errors
///
/// [`WinError`] with the GDI+ `Status` (e.g. 2 `InvalidParameter` for a file that is not an
/// image, 10 `FileNotFound`), or an argument error for an oversized image.
pub fn decode_file(path: &Path) -> Result<Bgra, WinError> {
    let wide = path_wide(path, "GdipCreateBitmapFromFile")?;
    let input = GdiplusStartupInput {
        GdiplusVersion: 1,
        DebugEventCallback: 0,
        SuppressBackgroundThread: 0,
        SuppressExternalCodecs: 0,
    };
    let mut output = GdiplusStartupOutput::default();
    let mut token = 0_usize;
    // SAFETY: Valid in/out pointers for this call.
    let status = unsafe { GdiplusStartup(&raw mut token, &raw const input, &raw mut output) };
    if status != 0 {
        return Err(failure("GdiplusStartup", status));
    }
    let _session = Session(token);
    let mut raw: *mut GpBitmap = core::ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated and live; `raw` is a valid out pointer.
    let status = unsafe { GdipCreateBitmapFromFile(wide.as_ptr(), &raw mut raw) };
    if status != 0 || raw.is_null() {
        return Err(failure("GdipCreateBitmapFromFile", status));
    }
    let bitmap = Bitmap(raw);
    let mut width = 0_u32;
    let mut height = 0_u32;
    // SAFETY: A live bitmap (a GpImage) and a valid out pointer.
    let status = unsafe { GdipGetImageWidth(bitmap.0.cast::<GpImage>(), &raw mut width) };
    if status != 0 {
        return Err(failure("GdipGetImageWidth", status));
    }
    // SAFETY: As above.
    let status = unsafe { GdipGetImageHeight(bitmap.0.cast::<GpImage>(), &raw mut height) };
    if status != 0 {
        return Err(failure("GdipGetImageHeight", status));
    }
    if width == 0 || height == 0 || u64::from(width) * u64::from(height) > MAX_PIXELS {
        return Err(WinError::invalid_argument("GdipGetImageWidth"));
    }
    let rect = Rect {
        X: 0,
        Y: 0,
        Width: i32::try_from(width)
            .map_err(|_| WinError::invalid_argument("GdipBitmapLockBits"))?,
        Height: i32::try_from(height)
            .map_err(|_| WinError::invalid_argument("GdipBitmapLockBits"))?,
    };
    let mut data = BitmapData::default();
    // SAFETY: A live bitmap, a rectangle inside it, read-only lock in 32bpp ARGB and a valid out
    // structure.
    let status = unsafe {
        GdipBitmapLockBits(
            bitmap.0,
            &raw const rect,
            u32::try_from(ImageLockModeRead).unwrap_or(1),
            PIXEL_FORMAT_32BPP_ARGB,
            &raw mut data,
        )
    };
    if status != 0 || data.Scan0.is_null() {
        return Err(failure("GdipBitmapLockBits", status));
    }
    let width = usize::try_from(width).unwrap_or(0);
    let height = usize::try_from(height).unwrap_or(0);
    let row_bytes = width * 4;
    let stride = isize::try_from(data.Stride).unwrap_or(0);
    let mut pixels = Vec::with_capacity(row_bytes * height);
    let stride_ok = stride.unsigned_abs() >= row_bytes;
    if stride_ok {
        for row in 0..height {
            let offset = isize::try_from(row).unwrap_or(0).saturating_mul(stride);
            // SAFETY: The locked buffer holds `height` rows `Stride` bytes apart (negative for
            // bottom-up), each at least `row_bytes` long; the row start stays inside it.
            let start = unsafe { data.Scan0.cast::<u8>().offset(offset) };
            // SAFETY: `start` addresses `row_bytes` readable bytes of the locked row.
            let line = unsafe { core::slice::from_raw_parts(start, row_bytes) };
            pixels.extend_from_slice(line);
        }
    }
    // SAFETY: Unlocks the lock taken above on the same bitmap.
    let _ = unsafe { GdipBitmapUnlockBits(bitmap.0, &raw mut data) };
    if !stride_ok {
        return Err(WinError::invalid_argument("GdipBitmapLockBits"));
    }
    Ok(Bgra {
        width,
        height,
        pixels,
    })
}
