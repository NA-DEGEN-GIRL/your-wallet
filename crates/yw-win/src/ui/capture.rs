#![allow(unsafe_code)]
//! **DEV ONLY — compiled only with debug assertions, never in release builds.** Window capture
//! for the screenshot tour (`docs/screenshots/`, `scripts/screenshot-tour.ps1`): after a
//! synchronous repaint, the client area of one of our windows is copied with `BitBlt` from its own
//! client DC into a 24-bit bitmap and returned as BMP bytes (`PrintWindow` returned the last DWM
//! frame, which could be half painted). [`dev_tour_lift_capture_exclusion`] removes the
//! capture exclusion of a window the *tour process itself* created (secret windows filled with
//! the public BIP39 test mnemonic), because an excluded window captures as black. The wallet app
//! never calls this module.

use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CreateCompatibleBitmap, CreateCompatibleDC,
    DIB_RGB_COLORS, DeleteDC, DeleteObject, GetDC, GetDIBits, RGBQUAD, ReleaseDC, SRCCOPY,
    SelectObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetClientRect, SetWindowDisplayAffinity, WDA_NONE,
};

use super::paint::Rect;
use super::window::{Hwnd, Window};
use crate::error::WinError;

/// A captured client area as a 24-bit bottom-up BMP file image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capture {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// The complete `.bmp` file.
    pub bmp: Vec<u8>,
}

fn bmp_file(width: u32, height: u32, pixels: &[u8]) -> Vec<u8> {
    let header_len: u32 = 14 + 40;
    let size = header_len.saturating_add(u32::try_from(pixels.len()).unwrap_or(u32::MAX));
    let mut out = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes());
    out.extend_from_slice(&header_len.to_le_bytes());
    out.extend_from_slice(&40_u32.to_le_bytes());
    out.extend_from_slice(&width.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&1_u16.to_le_bytes());
    out.extend_from_slice(&24_u16.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes());
    out.extend_from_slice(&u32::try_from(pixels.len()).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&2_835_u32.to_le_bytes());
    out.extend_from_slice(&2_835_u32.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes());
    out.extend_from_slice(pixels);
    out
}

struct WindowDc {
    hwnd: HWND,
    hdc: windows_sys::Win32::Graphics::Gdi::HDC,
}

impl Drop for WindowDc {
    fn drop(&mut self) {
        // SAFETY: Releases the client DC obtained with GetDC(hwnd) for the same window.
        unsafe { ReleaseDC(self.hwnd, self.hdc) };
    }
}

struct MemDc(windows_sys::Win32::Graphics::Gdi::HDC);

impl Drop for MemDc {
    fn drop(&mut self) {
        // SAFETY: Deletes the memory DC created with CreateCompatibleDC.
        unsafe { DeleteDC(self.0) };
    }
}

struct Bitmap(windows_sys::Win32::Graphics::Gdi::HBITMAP);

impl Drop for Bitmap {
    fn drop(&mut self) {
        // SAFETY: Deletes the bitmap after it was deselected from the memory DC.
        unsafe { DeleteObject(self.0) };
    }
}

/// Captures the client area of the window `target` (DEV ONLY, see the module documentation):
/// `BitBlt` from the window's own client DC, which reads the pixels the window (and its child
/// controls) last painted into its surface — call [`dev_tour_redraw`] first. Takes the identifier
/// rather than a [`Window`] so the caller holds no borrow of its state while it paints.
///
/// # Errors
///
/// [`WinError`] from the GDI calls.
pub fn capture_client(target: Hwnd) -> Result<Capture, WinError> {
    let hwnd: HWND = target.raw();
    let mut rect = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    // SAFETY: `rect` is writable storage for the window's client rectangle.
    if unsafe { GetClientRect(hwnd, &raw mut rect) } == 0 {
        return Err(WinError::last("GetClientRect"));
    }
    let client = Rect::from_win(&rect);
    let width = u32::try_from(client.w.max(1)).unwrap_or(1);
    let height = u32::try_from(client.h.max(1)).unwrap_or(1);
    // SAFETY: Gets the client DC of our window (released by `WindowDc`).
    let window_dc = unsafe { GetDC(hwnd) };
    if window_dc.is_null() {
        return Err(WinError::last("GetDC"));
    }
    let window_dc = WindowDc {
        hwnd,
        hdc: window_dc,
    };
    // SAFETY: Creates a memory DC compatible with the window DC (deleted by `MemDc`).
    let memory = unsafe { CreateCompatibleDC(window_dc.hdc) };
    if memory.is_null() {
        return Err(WinError::last("CreateCompatibleDC"));
    }
    let memory = MemDc(memory);
    // SAFETY: Creates a compatible bitmap of the client size (deleted by `Bitmap`).
    let bitmap = unsafe { CreateCompatibleBitmap(window_dc.hdc, client.w.max(1), client.h.max(1)) };
    if bitmap.is_null() {
        return Err(WinError::last("CreateCompatibleBitmap"));
    }
    let bitmap = Bitmap(bitmap);
    // SAFETY: Selects our bitmap into our memory DC; the previous object is restored below.
    let previous = unsafe { SelectObject(memory.0, bitmap.0) };
    // SAFETY: Copies the client pixels of our own window into our memory bitmap.
    let copied = unsafe {
        BitBlt(
            memory.0,
            0,
            0,
            client.w.max(1),
            client.h.max(1),
            window_dc.hdc,
            0,
            0,
            SRCCOPY,
        )
    };
    if !previous.is_null() {
        // SAFETY: Restores the memory DC's previous bitmap so ours can be read and deleted.
        unsafe { SelectObject(memory.0, previous) };
    }
    if copied == 0 {
        return Err(WinError::last("BitBlt"));
    }
    let stride = width.saturating_mul(3).saturating_add(3) / 4 * 4;
    let mut pixels = vec![0_u8; usize::try_from(stride.saturating_mul(height)).unwrap_or(0)];
    let mut info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: u32::try_from(core::mem::size_of::<BITMAPINFOHEADER>()).unwrap_or(40),
            biWidth: client.w.max(1),
            biHeight: client.h.max(1),
            biPlanes: 1,
            biBitCount: 24,
            biCompression: BI_RGB,
            biSizeImage: 0,
            biXPelsPerMeter: 0,
            biYPelsPerMeter: 0,
            biClrUsed: 0,
            biClrImportant: 0,
        },
        bmiColors: [RGBQUAD {
            rgbBlue: 0,
            rgbGreen: 0,
            rgbRed: 0,
            rgbReserved: 0,
        }],
    };
    // SAFETY: `pixels` holds `stride * height` bytes, exactly the 24-bit bottom-up DIB the
    // header describes; `info` is a valid BITMAPINFO; the bitmap is not selected into a DC.
    let lines = unsafe {
        GetDIBits(
            memory.0,
            bitmap.0,
            0,
            height,
            pixels.as_mut_ptr().cast(),
            &raw mut info,
            DIB_RGB_COLORS,
        )
    };
    if lines == 0 {
        return Err(WinError::last("GetDIBits"));
    }
    Ok(Capture {
        width,
        height,
        bmp: bmp_file(width, height, &pixels),
    })
}

/// **DEV ONLY (screenshot tour).** Repaints `target` and its children synchronously
/// (`RedrawWindow(RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW)`) so a capture
/// never sees a half-updated surface.
pub fn dev_tour_redraw(target: Hwnd) {
    use windows_sys::Win32::Graphics::Gdi::{
        RDW_ALLCHILDREN, RDW_ERASE, RDW_INVALIDATE, RDW_UPDATENOW, RedrawWindow,
    };
    // SAFETY: Repaints our own window; null rect and region mean the whole client area.
    unsafe {
        RedrawWindow(
            target.raw(),
            core::ptr::null(),
            core::ptr::null_mut(),
            RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW,
        )
    };
}

/// **DEV ONLY (screenshot tour).** Flushes this thread's batched GDI drawing so the next
/// composition (and a capture after it) has every painted pixel.
pub fn dev_tour_flush() {
    // SAFETY: Flushes the calling thread's GDI batch; no arguments.
    unsafe { windows_sys::Win32::Graphics::Gdi::GdiFlush() };
}

/// **DEV ONLY (scroll check).** Posts `WM_MOUSEWHEEL` with `delta` (120 = one notch, positive =
/// away from the user) to `target`; the next message loop processes it like wheel input (before
/// any pending `WM_PAINT`).
pub fn dev_tour_post_wheel(target: Hwnd, delta: i16) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_MOUSEWHEEL};
    let wparam = usize::from(u16::from_ne_bytes(delta.to_ne_bytes())) << 16;
    // SAFETY: Posts a plain-value message to our own window (no pointers).
    unsafe { PostMessageW(target.raw(), WM_MOUSEWHEEL, wparam, 0) };
}

/// **DEV ONLY (scroll check).** Posts `WM_VSCROLL` with an `SB_*` `code` to `target`, as the
/// window's scroll bar sends it.
pub fn dev_tour_post_vscroll(target: Hwnd, code: u16) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_VSCROLL};
    // SAFETY: Posts a plain-value message to our own window (no pointers; lParam 0 = the
    // window's own scroll bar).
    unsafe { PostMessageW(target.raw(), WM_VSCROLL, usize::from(code), 0) };
}

/// `ACTCTXW` (winbase.h). Declared here with the activation-context calls below instead of
/// through a windows-sys feature: only this debug-build module uses them (kernel32 exports).
#[repr(C)]
struct ActCtxW {
    size: u32,
    flags: u32,
    source: *const u16,
    processor_architecture: u16,
    lang_id: u16,
    assembly_directory: *const u16,
    resource_name: *const u16,
    application_name: *const u16,
    module: *mut core::ffi::c_void,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateActCtxW(context: *const ActCtxW) -> windows_sys::Win32::Foundation::HANDLE;
    fn ActivateActCtx(context: windows_sys::Win32::Foundation::HANDLE, cookie: *mut usize) -> i32;
    fn DeactivateActCtx(flags: u32, cookie: usize) -> i32;
    fn ReleaseActCtx(context: windows_sys::Win32::Foundation::HANDLE);
}

/// **DEV ONLY (scroll check).** The installed app's UI environment for the windows this thread
/// creates while the value lives: themed comctl32 v6 controls (an activation context built from
/// the app's manifest, which test binaries do not embed) and Per-Monitor-V2 DPI as this thread's
/// awareness (the process default, and so other test threads, stay as they are). Dropping it
/// restores the thread; drop it on the thread that made it, after its windows are gone.
#[derive(Debug)]
pub struct DevAppEnv {
    context: windows_sys::Win32::Foundation::HANDLE,
    cookie: usize,
    previous_dpi: windows_sys::Win32::UI::HiDpi::DPI_AWARENESS_CONTEXT,
}

/// **DEV ONLY (scroll check).** Enters [`DevAppEnv`] on this thread with the manifest at
/// `manifest` (`crates/yw-app/yw-app.manifest`).
///
/// # Errors
///
/// `CreateActCtxW`, `ActivateActCtx` or `SetThreadDpiAwarenessContext` failed.
pub fn dev_tour_app_env(manifest: &std::path::Path) -> Result<DevAppEnv, WinError> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::UI::HiDpi::{
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetThreadDpiAwarenessContext,
    };
    let source = crate::wide::path_wide(manifest, "CreateActCtxW")?;
    let request = ActCtxW {
        size: u32::try_from(core::mem::size_of::<ActCtxW>()).unwrap_or(0),
        flags: 0,
        source: source.as_ptr(),
        processor_architecture: 0,
        lang_id: 0,
        assembly_directory: core::ptr::null(),
        resource_name: core::ptr::null(),
        application_name: core::ptr::null(),
        module: core::ptr::null_mut(),
    };
    // SAFETY: `request` is a valid ACTCTXW whose only pointer, `source`, is a NUL-terminated
    // path that outlives the call.
    let context = unsafe { CreateActCtxW(&raw const request) };
    if context == INVALID_HANDLE_VALUE {
        return Err(WinError::last("CreateActCtxW"));
    }
    let mut cookie = 0_usize;
    // SAFETY: Activates the context just created on this thread; `cookie` is writable storage.
    if unsafe { ActivateActCtx(context, &raw mut cookie) } == 0 {
        let error = WinError::last("ActivateActCtx");
        // SAFETY: Releases the context created above; nothing else holds it.
        unsafe { ReleaseActCtx(context) };
        return Err(error);
    }
    let mut env = DevAppEnv {
        context,
        cookie,
        previous_dpi: core::ptr::null_mut(),
    };
    // SAFETY: Sets this thread's DPI awareness; no pointers involved.
    env.previous_dpi =
        unsafe { SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    if env.previous_dpi.is_null() {
        return Err(WinError::last("SetThreadDpiAwarenessContext"));
    }
    Ok(env)
}

impl Drop for DevAppEnv {
    fn drop(&mut self) {
        use windows_sys::Win32::UI::HiDpi::SetThreadDpiAwarenessContext;
        if !self.previous_dpi.is_null() {
            // SAFETY: Restores this thread's DPI awareness from before `dev_tour_app_env`.
            unsafe { SetThreadDpiAwarenessContext(self.previous_dpi) };
        }
        // SAFETY: Deactivates the context this value activated on this thread (raw pointer
        // fields keep it on that thread: not `Send`).
        unsafe { DeactivateActCtx(0, self.cookie) };
        // SAFETY: Releases the context this value created; nothing else holds it.
        unsafe { ReleaseActCtx(self.context) };
    }
}

/// **DEV ONLY (scroll check).** When the mouse pointer is over the top-level window `target`,
/// moves the window sideways on the pointer's monitor (to the side with more room) so it is not:
/// a themed control under a still pointer keeps a hover shade while content scrolls under it,
/// which a pixel comparison would count. Returns whether the window moved.
#[must_use]
pub fn dev_tour_clear_of_pointer(target: Hwnd) -> bool {
    use windows_sys::Win32::Foundation::POINT;
    use windows_sys::Win32::Graphics::Gdi::{
        GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromPoint,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetCursorPos, GetWindowRect, SWP_NOACTIVATE, SWP_NOSIZE, SWP_NOZORDER, SetWindowPos,
    };
    const GAP: i32 = 32;
    let mut pointer = POINT { x: 0, y: 0 };
    // SAFETY: `pointer` is writable storage for the cursor position.
    if unsafe { GetCursorPos(&raw mut pointer) } == 0 {
        return false;
    }
    let mut rect = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    // SAFETY: `rect` is writable storage for our window's rectangle.
    if unsafe { GetWindowRect(target.raw(), &raw mut rect) } == 0 {
        return false;
    }
    let over = (rect.left..rect.right).contains(&pointer.x)
        && (rect.top..rect.bottom).contains(&pointer.y);
    if !over {
        return false;
    }
    // SAFETY: Returns the monitor nearest to a point (never null with this flag).
    let monitor = unsafe { MonitorFromPoint(pointer, MONITOR_DEFAULTTONEAREST) };
    let mut info = MONITORINFO {
        cbSize: u32::try_from(core::mem::size_of::<MONITORINFO>()).unwrap_or(40),
        rcMonitor: rect,
        rcWork: rect,
        dwFlags: 0,
    };
    // SAFETY: `info` is a MONITORINFO with `cbSize` set, writable for the call.
    if unsafe { GetMonitorInfoW(monitor, &raw mut info) } == 0 {
        return false;
    }
    let work = info.rcWork;
    let x = if work.right - pointer.x >= pointer.x - work.left {
        pointer.x + GAP
    } else {
        pointer.x - GAP - (rect.right - rect.left)
    };
    // SAFETY: Moves our own top-level window; no size, z-order or activation change.
    let moved = unsafe {
        SetWindowPos(
            target.raw(),
            core::ptr::null_mut(),
            x,
            rect.top,
            0,
            0,
            SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
        )
    };
    moved != 0
}

/// **DEV ONLY (screenshot tour).** Removes `WDA_EXCLUDEFROMCAPTURE` from a window the tour
/// process created so it can be captured. Returns whether the call succeeded.
#[must_use]
pub fn dev_tour_lift_capture_exclusion(window: &Window) -> bool {
    let hwnd: HWND = window.hwnd().raw();
    // SAFETY: Changes the display affinity of our own top-level window.
    unsafe { SetWindowDisplayAffinity(hwnd, WDA_NONE) != 0 }
}

#[cfg(test)]
mod tests {
    use super::bmp_file;

    #[test]
    fn bmp_header_describes_a_24_bit_image() {
        let bmp = bmp_file(2, 1, &[0; 8]);
        assert_eq!(bmp.get(..2), Some(&b"BM"[..]));
        assert_eq!(bmp.len(), 54 + 8);
        assert_eq!(bmp.get(28..30), Some(&24_u16.to_le_bytes()[..]));
        assert_eq!(bmp.get(18..22), Some(&2_u32.to_le_bytes()[..]));
    }
}
