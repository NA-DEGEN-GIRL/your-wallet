#![allow(unsafe_code)]
//! Window classes, creation, the single wndproc trampoline, the message loop and posting
//! (spec/01 §7.7).
//!
//! Secret-window behaviour is ported from
//! `archive/spec-v2.4:crates/secret-input-ui/src/recovery_native.rs:615-679,1453-1607`: capture
//! exclusion is applied to the hidden window before any state is attached and read back, the
//! listed messages are blocked, and the per-window pointer is cleared at `WM_NCDESTROY`. The
//! one-shot `PRESENTED` guard is gone; classes are registered once; the app owns the loop.

use core::cell::{Cell, RefCell};
use core::fmt;
use std::rc::Rc;
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{
    ERROR_CLASS_ALREADY_EXISTS, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM,
};
use windows_sys::Win32::Graphics::Gdi::{
    GetMonitorInfoW, GetStockObject, InvalidateRect, MONITOR_DEFAULTTONEAREST,
    MONITOR_DEFAULTTOPRIMARY, MONITORINFO, MonitorFromWindow, SetBkColor, WHITE_BRUSH,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::{
    ICC_STANDARD_CLASSES, INITCOMMONCONTROLSEX, InitCommonControlsEx, SetScrollInfo,
};
use windows_sys::Win32::UI::HiDpi::{
    AdjustWindowRectExForDpi, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForWindow,
    SetProcessDpiAwarenessContext,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    EnableWindow, GetFocus, ReleaseCapture, SetCapture, SetFocus,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CREATESTRUCTW, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, CreateWindowExW, DefWindowProcW,
    DestroyWindow, DispatchMessageW, FLASHW_ALL, FLASHW_TIMERNOFG, FLASHWINFO, FindWindowW,
    FlashWindowEx, GA_ROOT, GWLP_USERDATA, GetAncestor, GetClientRect, GetForegroundWindow,
    GetMessageW, GetScrollInfo, GetWindowDisplayAffinity, GetWindowLongPtrW,
    GetWindowThreadProcessId, HWND_NOTOPMOST, HWND_TOPMOST, IDC_ARROW, IDI_APPLICATION, IsChild,
    IsDialogMessageW, IsIconic, KillTimer, LoadCursorW, LoadIconW, MB_ICONERROR,
    MB_ICONINFORMATION, MB_ICONWARNING, MB_OK, MINMAXINFO, MSG, MessageBoxW, PostMessageW,
    PostQuitMessage, RegisterClassExW, SB_VERT, SCROLLINFO, SIF_PAGE, SIF_POS, SIF_RANGE,
    SIF_TRACKPOS, SW_HIDE, SW_RESTORE, SW_SHOW, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE,
    SWP_NOZORDER, SetForegroundWindow, SetTimer, SetWindowDisplayAffinity, SetWindowLongPtrW,
    SetWindowPos, SetWindowTextW, ShowWindow, TranslateMessage, WDA_EXCLUDEFROMCAPTURE, WM_APP,
    WM_CHAR, WM_CTLCOLORBTN, WM_CTLCOLORSTATIC, WM_DPICHANGED, WM_GETMINMAXINFO,
    WM_IME_STARTCOMPOSITION, WM_KEYDOWN, WM_LBUTTONDOWN, WM_MBUTTONDOWN, WM_MOUSEWHEEL,
    WM_NCCREATE, WM_NCDESTROY, WM_RBUTTONDOWN, WM_SYSKEYDOWN, WNDCLASSEXW, WS_CAPTION, WS_CHILD,
    WS_CLIPCHILDREN, WS_EX_APPWINDOW, WS_EX_CONTROLPARENT, WS_EX_DLGMODALFRAME, WS_EX_TOPMOST,
    WS_MINIMIZEBOX, WS_OVERLAPPED, WS_OVERLAPPEDWINDOW, WS_SYSMENU, WS_THICKFRAME, WS_VSCROLL,
};

use super::msg::{
    CaptureExclusion, CaptureOutcome, Msg, capture_outcome, decode, is_blocked_secret_msg,
};
use super::paint::{PaintDc, Rect};
use crate::error::WinError;
use crate::wide::to_wide;

/// Opaque window identifier (cannot be used as a pointer).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hwnd(usize);

impl Hwnd {
    fn raw(self) -> HWND {
        core::ptr::with_exposed_provenance_mut(self.0)
    }

    fn from_raw(hwnd: HWND) -> Self {
        Self(hwnd.expose_provenance())
    }
}

/// UI failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiError {
    /// A Win32 call failed.
    Os(WinError),
    /// A `CaptureExclusion::Required` window could not be excluded and was destroyed.
    CaptureExclusionFailed,
}

impl fmt::Display for UiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Os(error) => write!(formatter, "{error}"),
            Self::CaptureExclusionFailed => formatter.write_str("capture exclusion failed"),
        }
    }
}

impl std::error::Error for UiError {}

impl From<WinError> for UiError {
    fn from(error: WinError) -> Self {
        Self::Os(error)
    }
}

/// A window class (spec/01 §7.7). `capture` matters only when `secret`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassSpec {
    /// Class name.
    pub name: &'static str,
    /// Secret class: capture exclusion before attach and the message block list.
    pub secret: bool,
    /// Exclusion failure policy.
    pub capture: CaptureExclusion,
}

#[derive(Clone, Copy)]
struct ClassEntry {
    name: &'static str,
    secret: bool,
    capture: CaptureExclusion,
}

static CLASSES: Mutex<Vec<ClassEntry>> = Mutex::new(Vec::new());

thread_local! {
    /// Top-level windows whose messages go through `IsDialogMessageW` (Tab navigation).
    static DIALOG_ROOTS: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

fn module_handle() -> Result<windows_sys::Win32::Foundation::HINSTANCE, WinError> {
    // SAFETY: A null module name returns the current executable module handle.
    let module = unsafe { GetModuleHandleW(core::ptr::null()) };
    if module.is_null() {
        return Err(WinError::last("GetModuleHandleW"));
    }
    Ok(module)
}

/// Per-process UI setup before the first window: Per-Monitor-V2 DPI awareness and
/// `InitCommonControlsEx`.
///
/// # Errors
///
/// The first failing call (callers may continue, spec/04 §1.4).
pub fn init() -> Result<(), WinError> {
    // SAFETY: Sets the process DPI awareness; no pointers involved.
    let dpi_ok =
        unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    // ERROR_ACCESS_DENIED: the awareness was already set (by the application manifest).
    let dpi_result = match (dpi_ok, WinError::last("SetProcessDpiAwarenessContext")) {
        (0, error) if error.code != 5 => Err(error),
        _ => Ok(()),
    };
    let controls = INITCOMMONCONTROLSEX {
        dwSize: u32::try_from(core::mem::size_of::<INITCOMMONCONTROLSEX>()).unwrap_or(8),
        dwICC: ICC_STANDARD_CLASSES,
    };
    // SAFETY: `controls` is a valid, initialized structure for the call.
    let controls_ok = unsafe { InitCommonControlsEx(&raw const controls) };
    if controls_ok == 0 {
        return Err(WinError::last("InitCommonControlsEx"));
    }
    dpi_result
}

/// Registers a class once; a second registration of the same name returns `Ok(())`.
///
/// # Errors
///
/// [`WinError`] from `RegisterClassExW`.
pub fn register_class(spec: &ClassSpec) -> Result<(), WinError> {
    let mut classes = CLASSES
        .lock()
        .map_err(|_| WinError::invalid_argument("register_class"))?;
    if classes.iter().any(|entry| entry.name == spec.name) {
        return Ok(());
    }
    let name = to_wide(spec.name, "RegisterClassExW")?;
    let instance = module_handle()?;
    // SAFETY: Loads the shared system arrow cursor (no module, no ownership).
    let cursor = unsafe { LoadCursorW(core::ptr::null_mut(), IDC_ARROW) };
    // SAFETY: Loads the shared system application icon.
    let icon = unsafe { LoadIconW(core::ptr::null_mut(), IDI_APPLICATION) };
    // SAFETY: Returns the shared stock white brush (never deleted).
    let background = unsafe { GetStockObject(WHITE_BRUSH) };
    let class = WNDCLASSEXW {
        cbSize: u32::try_from(core::mem::size_of::<WNDCLASSEXW>()).unwrap_or(80),
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(trampoline),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: instance,
        hIcon: icon,
        hCursor: cursor,
        hbrBackground: background,
        lpszMenuName: core::ptr::null(),
        lpszClassName: name.as_ptr(),
        hIconSm: core::ptr::null_mut(),
    };
    // SAFETY: `class` and the NUL-terminated class name are valid for the call (the system copies
    // the name).
    let atom = unsafe { RegisterClassExW(&raw const class) };
    if atom == 0 {
        let error = WinError::last("RegisterClassExW");
        if error.code != ERROR_CLASS_ALREADY_EXISTS {
            return Err(error);
        }
    }
    classes.push(ClassEntry {
        name: spec.name,
        secret: spec.secret,
        capture: spec.capture,
    });
    Ok(())
}

fn class_entry(name: &str) -> Option<ClassEntry> {
    CLASSES
        .lock()
        .ok()?
        .iter()
        .find(|entry| entry.name == name)
        .copied()
}

/// Window placement kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowKind {
    /// The application main window (`WS_OVERLAPPEDWINDOW`, Tab navigation among controls).
    Main,
    /// A dialog-like top-level window owned by `owner`.
    Owned {
        /// Owner window.
        owner: Hwnd,
    },
    /// A dialog-like top-level window without an owner (the approval window, spec/04 §3.6).
    Floating,
    /// A never-shown top-level window (still receives power/session broadcasts).
    HiddenTopLevel,
    /// A child panel of `parent` (`WS_CHILD | WS_CLIPCHILDREN | WS_VSCROLL`, spec/04 §1.7
    /// `YourWalletV3Panel`), positioned with [`Window::set_rect`].
    Child {
        /// Parent window.
        parent: Hwnd,
    },
}

/// Window creation parameters (sizes in DIP).
#[derive(Clone, Debug)]
pub struct WindowSpec {
    class: &'static str,
    kind: WindowKind,
    title: String,
    size: (i32, i32),
    min_size: (i32, i32),
    visible: bool,
    topmost: bool,
    resizable: bool,
}

impl WindowSpec {
    /// A spec for `class` and `kind` (640×480 DIP, hidden, not topmost, fixed size).
    #[must_use]
    pub fn new(class: &'static str, kind: WindowKind) -> Self {
        Self {
            class,
            kind,
            title: String::new(),
            size: (640, 480),
            min_size: (0, 0),
            visible: false,
            topmost: false,
            resizable: matches!(kind, WindowKind::Main),
        }
    }

    /// Title (never secret).
    #[must_use]
    pub fn title(mut self, title: &str) -> Self {
        title.clone_into(&mut self.title);
        self
    }

    /// Client size in DIP.
    #[must_use]
    pub const fn size(mut self, w: i32, h: i32) -> Self {
        self.size = (w, h);
        self
    }

    /// Minimum client size in DIP.
    #[must_use]
    pub const fn min_size(mut self, w: i32, h: i32) -> Self {
        self.min_size = (w, h);
        self
    }

    /// Show after creation.
    #[must_use]
    pub const fn visible(mut self, visible: bool) -> Self {
        self.visible = visible;
        self
    }

    /// `WS_EX_TOPMOST`.
    #[must_use]
    pub const fn topmost(mut self, topmost: bool) -> Self {
        self.topmost = topmost;
        self
    }

    /// Resizable frame (owned windows; the main window is always resizable).
    #[must_use]
    pub const fn resizable(mut self, resizable: bool) -> Self {
        self.resizable = resizable;
        self
    }

    fn styles(&self) -> (u32, u32) {
        match self.kind {
            WindowKind::Main => (
                WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                WS_EX_APPWINDOW | WS_EX_CONTROLPARENT,
            ),
            WindowKind::Owned { .. } | WindowKind::Floating => {
                let mut style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN;
                if self.resizable {
                    style |= WS_THICKFRAME | WS_MINIMIZEBOX;
                }
                let mut ex = WS_EX_APPWINDOW | WS_EX_DLGMODALFRAME;
                if self.topmost {
                    ex |= WS_EX_TOPMOST;
                }
                (style, ex)
            }
            WindowKind::HiddenTopLevel => (WS_OVERLAPPED, 0),
            WindowKind::Child { .. } => (WS_CHILD | WS_CLIPCHILDREN | WS_VSCROLL, 0),
        }
    }
}

/// A message reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// Default processing (`DefWindowProcW`, or the documented built-in default).
    Default,
    /// Handled; return this value.
    Handled(isize),
}

/// A window's message handler, called on the UI thread.
pub trait Handler {
    /// Handles one decoded message.
    fn on(&mut self, window: &Window, msg: &Msg) -> Reply;
}

/// State shared between a window's trampoline state and its [`Window`] handles.
#[derive(Debug, Default)]
struct Shared {
    alive: Cell<bool>,
    adopted: Cell<bool>,
    armed: Cell<bool>,
    capture_excluded: Cell<bool>,
}

struct WindowState {
    handler: RefCell<Option<Box<dyn Handler>>>,
    secret: bool,
    min_size: (i32, i32),
    style: u32,
    ex_style: u32,
    depth: Cell<u32>,
    pending_free: Cell<bool>,
    shared: Rc<Shared>,
}

/// A window handle (UI thread only). The value returned by [`create_window`] owns the window and
/// destroys it on drop; handles passed to a [`Handler`] are borrowed views.
pub struct Window {
    hwnd: Hwnd,
    shared: Rc<Shared>,
    owning: bool,
}

impl fmt::Debug for Window {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Window")
            .field("hwnd", &self.hwnd)
            .field("owning", &self.owning)
            .finish_non_exhaustive()
    }
}

/// `v * dpi / 96`, saturating.
#[must_use]
pub fn scale(value: i32, dpi: u32) -> i32 {
    let scaled = i64::from(value).saturating_mul(i64::from(dpi)) / 96;
    i32::try_from(scaled).unwrap_or(if scaled < 0 { i32::MIN } else { i32::MAX })
}

impl Window {
    /// The window identifier.
    #[must_use]
    pub const fn hwnd(&self) -> Hwnd {
        self.hwnd
    }

    /// Whether the window still exists.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.shared.alive.get()
    }

    /// Shows the window (restores it when minimized).
    pub fn show(&self) {
        // SAFETY: Queries the minimized state of our window handle.
        let iconic = unsafe { IsIconic(self.hwnd.raw()) } != 0;
        // SAFETY: Shows our window handle.
        unsafe { ShowWindow(self.hwnd.raw(), if iconic { SW_RESTORE } else { SW_SHOW }) };
    }

    /// Hides the window.
    pub fn hide(&self) {
        // SAFETY: Hides our window handle.
        unsafe { ShowWindow(self.hwnd.raw(), SW_HIDE) };
    }

    /// Destroys the window now.
    pub fn destroy(&self) {
        if self.shared.alive.get() {
            DIALOG_ROOTS.with(|roots| {
                if let Ok(mut roots) = roots.try_borrow_mut() {
                    roots.retain(|hwnd| *hwnd != self.hwnd.0);
                }
            });
            // SAFETY: Destroys our live window (on its own UI thread).
            unsafe { DestroyWindow(self.hwnd.raw()) };
        }
    }

    /// Enables or disables mouse and keyboard input.
    pub fn enable(&self, enabled: bool) {
        // SAFETY: Changes the enabled state of our window handle.
        unsafe { EnableWindow(self.hwnd.raw(), i32::from(enabled)) };
    }

    /// Adds or removes `WS_EX_TOPMOST`.
    pub fn set_topmost(&self, topmost: bool) {
        let after = if topmost {
            HWND_TOPMOST
        } else {
            HWND_NOTOPMOST
        };
        // SAFETY: Changes only the z-order of our window.
        unsafe {
            SetWindowPos(
                self.hwnd.raw(),
                after,
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
            )
        };
    }

    /// `SetForegroundWindow`; returns whether it succeeded.
    #[must_use]
    pub fn set_foreground(&self) -> bool {
        // SAFETY: Requests foreground activation for our window handle.
        unsafe { SetForegroundWindow(self.hwnd.raw()) != 0 }
    }

    /// `FlashWindowEx(FLASHW_ALL | FLASHW_TIMERNOFG)`.
    pub fn flash(&self) {
        let info = FLASHWINFO {
            cbSize: u32::try_from(core::mem::size_of::<FLASHWINFO>()).unwrap_or(20),
            hwnd: self.hwnd.raw(),
            dwFlags: FLASHW_ALL | FLASHW_TIMERNOFG,
            uCount: 0,
            dwTimeout: 0,
        };
        // SAFETY: `info` is a valid FLASHWINFO for our window.
        unsafe { FlashWindowEx(&raw const info) };
    }

    /// Invalidates the whole client area.
    pub fn invalidate(&self) {
        // SAFETY: Invalidates our window's client area (null rect = everything).
        unsafe { InvalidateRect(self.hwnd.raw(), core::ptr::null(), 1) };
    }

    /// Sets the title (never pass secrets).
    pub fn set_title(&self, title: &str) {
        if let Ok(wide) = to_wide(title, "SetWindowTextW") {
            // SAFETY: `wide` is NUL-terminated and live for the call. Secret windows block
            // WM_SETTEXT once armed, so titles are set before attaching or on non-secret windows.
            unsafe { SetWindowTextW(self.hwnd.raw(), wide.as_ptr()) };
        }
    }

    /// Starts (or restarts) timer `id` every `ms` milliseconds.
    ///
    /// # Errors
    ///
    /// [`WinError`] from `SetTimer`.
    pub fn set_timer(&self, id: usize, ms: u32) -> Result<(), WinError> {
        // SAFETY: Creates a window timer on our window (no callback).
        let result = unsafe { SetTimer(self.hwnd.raw(), id, ms, None) };
        if result == 0 {
            return Err(WinError::last("SetTimer"));
        }
        Ok(())
    }

    /// Stops timer `id`.
    pub fn kill_timer(&self, id: usize) {
        // SAFETY: Kills a timer on our window; unknown ids are harmless.
        unsafe { KillTimer(self.hwnd.raw(), id) };
    }

    /// Current DPI (96 if unknown).
    #[must_use]
    pub fn dpi(&self) -> u32 {
        // SAFETY: Queries the DPI of our window.
        let dpi = unsafe { GetDpiForWindow(self.hwnd.raw()) };
        if dpi == 0 { 96 } else { dpi }
    }

    /// Scales DIP to pixels at the current DPI.
    #[must_use]
    pub fn px(&self, dip: i32) -> i32 {
        scale(dip, self.dpi())
    }

    /// Client rectangle in pixels.
    #[must_use]
    pub fn client_rect(&self) -> Rect {
        let mut rect = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        // SAFETY: `rect` is writable storage for our window's client rectangle.
        unsafe { GetClientRect(self.hwnd.raw(), &raw mut rect) };
        Rect::from_win(&rect)
    }

    /// Captures the mouse.
    pub fn set_capture(&self) {
        // SAFETY: Captures the mouse for our window.
        unsafe { SetCapture(self.hwnd.raw()) };
    }

    /// Releases mouse capture.
    #[expect(
        clippy::unused_self,
        reason = "kept as a Window method per spec/01 §7.7"
    )]
    pub fn release_capture(&self) {
        // SAFETY: Releases the thread's mouse capture.
        unsafe { ReleaseCapture() };
    }

    /// Gives this window keyboard focus.
    pub fn set_focus(&self) {
        // SAFETY: Sets focus to our window.
        unsafe { SetFocus(self.hwnd.raw()) };
    }

    /// Whether this window is the foreground window.
    #[must_use]
    pub fn is_foreground(&self) -> bool {
        // SAFETY: Reads the foreground window handle.
        let foreground = unsafe { GetForegroundWindow() };
        foreground == self.hwnd.raw()
    }

    /// Whether keyboard focus is this window or one of its children.
    #[must_use]
    pub fn focus_within(&self) -> bool {
        // SAFETY: Reads the thread's focus window.
        let focus = unsafe { GetFocus() };
        if focus.is_null() {
            return false;
        }
        // SAFETY: Queries the parent/child relation of two window handles.
        focus == self.hwnd.raw() || unsafe { IsChild(self.hwnd.raw(), focus) } != 0
    }

    /// Centers the window on `anchor`'s monitor work area (or its own monitor).
    pub fn center_on(&self, anchor: Option<&Self>) {
        let target = anchor.map_or(self.hwnd, |window| window.hwnd);
        let Some(work) = work_area(target.raw(), MONITOR_DEFAULTTONEAREST) else {
            return;
        };
        let mut rect = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        // SAFETY: `rect` is writable storage for our window rectangle.
        unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::GetWindowRect(
                self.hwnd.raw(),
                &raw mut rect,
            )
        };
        let (w, h) = (rect.right - rect.left, rect.bottom - rect.top);
        let x = work.left + (work.right - work.left - w).max(0) / 2;
        let y = work.top + (work.bottom - work.top - h).max(0) / 2;
        // SAFETY: Moves our window.
        unsafe {
            SetWindowPos(
                self.hwnd.raw(),
                core::ptr::null_mut(),
                x,
                y,
                0,
                0,
                SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
            )
        };
    }

    /// Moves and sizes the window (client coordinates of the parent for a child panel).
    pub fn set_rect(&self, rect: Rect) {
        // SAFETY: Moves and sizes our window; no z-order or activation change.
        unsafe {
            SetWindowPos(
                self.hwnd.raw(),
                core::ptr::null_mut(),
                rect.x,
                rect.y,
                rect.w.max(0),
                rect.h.max(0),
                SWP_NOZORDER | SWP_NOACTIVATE,
            )
        };
    }

    /// Sets the vertical scroll bar: range `0..=max`, page size and position (pixels).
    pub fn set_vscroll(&self, pos: i32, page: i32, max: i32) {
        let info = SCROLLINFO {
            cbSize: u32::try_from(core::mem::size_of::<SCROLLINFO>()).unwrap_or(28),
            fMask: SIF_RANGE | SIF_PAGE | SIF_POS,
            nMin: 0,
            nMax: max.max(0),
            nPage: u32::try_from(page.max(0)).unwrap_or(0),
            nPos: pos.max(0),
            nTrackPos: 0,
        };
        // SAFETY: `info` is a valid SCROLLINFO for our window's vertical bar.
        unsafe { SetScrollInfo(self.hwnd.raw(), SB_VERT, &raw const info, 1) };
    }

    /// The thumb position while it is dragged (`SB_THUMBTRACK`), 0 if unknown.
    #[must_use]
    pub fn vscroll_track_pos(&self) -> i32 {
        let mut info = SCROLLINFO {
            cbSize: u32::try_from(core::mem::size_of::<SCROLLINFO>()).unwrap_or(28),
            fMask: SIF_TRACKPOS,
            nMin: 0,
            nMax: 0,
            nPage: 0,
            nPos: 0,
            nTrackPos: 0,
        };
        // SAFETY: `info` is writable with `cbSize` and `fMask` set.
        let ok = unsafe { GetScrollInfo(self.hwnd.raw(), SB_VERT, &raw mut info) };
        if ok == 0 { 0 } else { info.nTrackPos }
    }

    /// A thread-safe poster for this window.
    #[must_use]
    pub const fn poster(&self) -> Poster {
        Poster { hwnd: self.hwnd.0 }
    }

    /// Secret classes: whether capture exclusion is in effect. Other windows: `false`.
    #[must_use]
    pub fn capture_excluded(&self) -> bool {
        self.shared.capture_excluded.get()
    }

    /// `(width, height)` of `text` drawn with `font` and `flags` within `width` pixels (layout
    /// outside `WM_PAINT`).
    #[must_use]
    pub fn measure_text(
        &self,
        font: &super::paint::Font,
        text: &[u16],
        width: i32,
        flags: super::paint::DrawFlags,
    ) -> (i32, i32) {
        super::paint::measure_with(self.hwnd.raw(), font, text, width, flags)
    }

    pub(crate) const fn raw_id(&self) -> usize {
        self.hwnd.0
    }

    pub(crate) fn alive_probe(&self) -> Rc<dyn Fn() -> bool> {
        let shared = Rc::clone(&self.shared);
        Rc::new(move || shared.alive.get())
    }

    /// Starts painting (only while handling [`Msg::Paint`]).
    ///
    /// # Errors
    ///
    /// [`WinError`] from `BeginPaint`.
    pub fn begin_paint(&self) -> Result<PaintDc<'_>, WinError> {
        PaintDc::begin(self.hwnd.raw())
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        if self.owning {
            self.destroy();
        }
    }
}

fn work_area(hwnd: HWND, flags: u32) -> Option<RECT> {
    // SAFETY: Returns the monitor for a window handle (never null with these flags).
    let monitor = unsafe { MonitorFromWindow(hwnd, flags) };
    let mut info = MONITORINFO {
        cbSize: u32::try_from(core::mem::size_of::<MONITORINFO>()).unwrap_or(40),
        rcMonitor: RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        },
        rcWork: RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        },
        dwFlags: 0,
    };
    // SAFETY: `info` is writable with `cbSize` set.
    let ok = unsafe { GetMonitorInfoW(monitor, &raw mut info) };
    (ok != 0).then_some(info.rcWork)
}

/// Sizes the hidden window for its monitor's DPI and centers it on `anchor`'s monitor.
fn place(hwnd: HWND, anchor: HWND, spec: &WindowSpec, style: u32, ex_style: u32) {
    let Some(work) = work_area(anchor, MONITOR_DEFAULTTOPRIMARY) else {
        return;
    };
    // SAFETY: Moves our hidden window onto the target monitor so its DPI is that monitor's.
    unsafe {
        SetWindowPos(
            hwnd,
            core::ptr::null_mut(),
            work.left,
            work.top,
            0,
            0,
            SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
        )
    };
    // SAFETY: Queries our window's DPI.
    let dpi = match unsafe { GetDpiForWindow(hwnd) } {
        0 => 96,
        value => value,
    };
    let mut rect = RECT {
        left: 0,
        top: 0,
        right: scale(spec.size.0, dpi),
        bottom: scale(spec.size.1, dpi),
    };
    // SAFETY: `rect` is writable; style values are our window's.
    unsafe { AdjustWindowRectExForDpi(&raw mut rect, style, 0, ex_style, dpi) };
    let work_w = work.right - work.left;
    let work_h = work.bottom - work.top;
    let w = (rect.right - rect.left).min(work_w);
    let h = (rect.bottom - rect.top).min(work_h);
    let x = work.left + (work_w - w) / 2;
    let y = work.top + (work_h - h) / 2;
    // SAFETY: Positions and sizes our hidden window.
    unsafe {
        SetWindowPos(
            hwnd,
            core::ptr::null_mut(),
            x,
            y,
            w,
            h,
            SWP_NOZORDER | SWP_NOACTIVATE,
        )
    };
}

/// `true` only when setting the affinity succeeded and the read-back value is
/// `WDA_EXCLUDEFROMCAPTURE` (0x11).
#[must_use]
pub(crate) const fn exclusion_verified(set_ok: bool, read_back: Option<u32>) -> bool {
    matches!((set_ok, read_back), (true, Some(WDA_EXCLUDEFROMCAPTURE)))
}

fn apply_exclusion(hwnd: HWND) -> bool {
    // SAFETY: Sets the display affinity of our own top-level window.
    let set_ok = unsafe { SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) } != 0;
    let mut affinity = 0_u32;
    // SAFETY: `affinity` is writable DWORD storage; the window is ours.
    let read_ok = unsafe { GetWindowDisplayAffinity(hwnd, &raw mut affinity) } != 0;
    exclusion_verified(set_ok, read_ok.then_some(affinity))
}

/// Applies `WDA_EXCLUDEFROMCAPTURE` and verifies it by reading it back.
///
/// # Errors
///
/// [`UiError::CaptureExclusionFailed`] when setting or verifying fails.
pub fn exclude_from_capture(window: &Window) -> Result<(), UiError> {
    if apply_exclusion(window.hwnd.raw()) {
        window.shared.capture_excluded.set(true);
        Ok(())
    } else {
        Err(UiError::CaptureExclusionFailed)
    }
}

/// Creates a window (always hidden first). Secret classes get capture exclusion before the
/// handler is attached and follow `ClassSpec.capture` on failure (spec/01 §7.7); the handler then
/// receives a synthesized [`Msg::Create`].
///
/// # Errors
///
/// [`UiError::Os`] for creation failures, [`UiError::CaptureExclusionFailed`] for a
/// `Required` class whose exclusion failed (the window is destroyed).
#[expect(
    clippy::too_many_lines,
    reason = "one linear creation sequence with the secret-class branch"
)]
pub fn create_window(spec: &WindowSpec, handler: Box<dyn Handler>) -> Result<Window, UiError> {
    let class =
        class_entry(spec.class).ok_or(UiError::Os(WinError::new("CreateWindowExW", 1_407)))?;
    let (style, ex_style) = spec.styles();
    let shared = Rc::new(Shared::default());
    let mut pending_handler = Some(handler);
    let state = Box::new(WindowState {
        handler: RefCell::new(if class.secret {
            None
        } else {
            pending_handler.take()
        }),
        secret: class.secret,
        min_size: spec.min_size,
        style,
        ex_style,
        depth: Cell::new(0),
        pending_free: Cell::new(false),
        shared: Rc::clone(&shared),
    });
    let class_name = to_wide(spec.class, "CreateWindowExW")?;
    let title = to_wide(&spec.title, "CreateWindowExW")?;
    let owner = match spec.kind {
        WindowKind::Owned { owner } => owner.raw(),
        WindowKind::Child { parent } => parent.raw(),
        WindowKind::Main | WindowKind::Floating | WindowKind::HiddenTopLevel => {
            core::ptr::null_mut()
        }
    };
    let instance = module_handle()?;
    let raw_state = Box::into_raw(state);
    // SAFETY: Class and title are NUL-terminated and live; `raw_state` is a valid boxed state
    // adopted by the trampoline at WM_NCCREATE (ownership tracked through `shared.adopted`).
    let hwnd = unsafe {
        CreateWindowExW(
            ex_style,
            class_name.as_ptr(),
            title.as_ptr(),
            style,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            0,
            0,
            owner,
            core::ptr::null_mut(),
            instance,
            raw_state.cast_const().cast(),
        )
    };
    if hwnd.is_null() {
        let error = WinError::last("CreateWindowExW");
        if !shared.adopted.get() {
            // SAFETY: The trampoline never adopted the box, so it is still exclusively ours.
            drop(unsafe { Box::from_raw(raw_state) });
        }
        return Err(UiError::Os(error));
    }
    let window = Window {
        hwnd: Hwnd::from_raw(hwnd),
        shared: Rc::clone(&shared),
        owning: true,
    };
    if !matches!(spec.kind, WindowKind::Child { .. }) {
        place(
            hwnd,
            if owner.is_null() { hwnd } else { owner },
            spec,
            style,
            ex_style,
        );
    }
    if matches!(spec.kind, WindowKind::Main) {
        DIALOG_ROOTS.with(|roots| {
            if let Ok(mut roots) = roots.try_borrow_mut() {
                roots.push(window.hwnd.0);
            }
        });
    }
    if class.secret {
        let excluded = apply_exclusion(hwnd);
        match capture_outcome(class.capture, excluded) {
            CaptureOutcome::Destroy => {
                drop(window);
                return Err(UiError::CaptureExclusionFailed);
            }
            CaptureOutcome::Excluded | CaptureOutcome::Unprotected => {}
        }
        shared.capture_excluded.set(excluded);
        // SAFETY: The window is alive (just created on this thread), so its state pointer in
        // GWLP_USERDATA is the box adopted at WM_NCCREATE.
        let state_ptr = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) };
        let state_ptr = core::ptr::with_exposed_provenance::<WindowState>(
            usize::try_from(state_ptr).unwrap_or(0),
        );
        if state_ptr.is_null() {
            return Err(UiError::Os(WinError::new("GetWindowLongPtrW", 1_400)));
        }
        {
            // SAFETY: Non-null pointer to the live adopted state (freed only at WM_NCDESTROY,
            // which cannot run inside this block).
            let state = unsafe { &*state_ptr };
            if let Ok(mut slot) = state.handler.try_borrow_mut() {
                *slot = pending_handler.take();
            }
        }
        shared.armed.set(true);
        deliver_synthesized(state_ptr.cast_mut(), window.hwnd, &shared, &Msg::Create);
        if !shared.alive.get() {
            return Err(UiError::Os(WinError::new("CreateWindowExW", 1_400)));
        }
    }
    if spec.visible {
        window.show();
    }
    Ok(window)
}

/// Delivers a synthesized message with the same depth accounting as the trampoline, so a handler
/// that destroys its window during the call cannot free the state under itself.
fn deliver_synthesized(state_ptr: *mut WindowState, hwnd: Hwnd, shared: &Rc<Shared>, msg: &Msg) {
    // SAFETY: The caller passes the live adopted state of a window that is still alive.
    let state = unsafe { &*state_ptr };
    state.depth.set(state.depth.get().saturating_add(1));
    let view = Window {
        hwnd,
        shared: Rc::clone(shared),
        owning: false,
    };
    if let Ok(mut slot) = state.handler.try_borrow_mut()
        && let Some(handler) = slot.as_mut()
    {
        handler.on(&view, msg);
    }
    let depth = state.depth.get().saturating_sub(1);
    state.depth.set(depth);
    if depth == 0 && state.pending_free.get() {
        // SAFETY: WM_NCDESTROY ran during the call and deferred the free; nothing references the
        // state any more.
        drop(unsafe { Box::from_raw(state_ptr) });
    }
}

fn foreign_focus(hwnd: HWND, target: usize) -> bool {
    let target: HWND = core::ptr::with_exposed_provenance_mut(target);
    if target.is_null() {
        return true;
    }
    if target == hwnd {
        return false;
    }
    // SAFETY: Queries the parent/child relation of two window handles.
    unsafe { IsChild(hwnd, target) == 0 }
}

fn default_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    // SAFETY: Forwards the unchanged message to the default window procedure.
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

fn dispatch(state: &WindowState, hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let view = Window {
        hwnd: Hwnd::from_raw(hwnd),
        shared: Rc::clone(&state.shared),
        owning: false,
    };
    if state.secret {
        if msg == WM_IME_STARTCOMPOSITION
            && let Ok(mut slot) = state.handler.try_borrow_mut()
            && let Some(handler) = slot.as_mut()
        {
            handler.on(&view, &Msg::ImeAttempt);
        }
        if is_blocked_secret_msg(msg, state.shared.armed.get()) {
            return 0;
        }
    }
    match msg {
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => {
            let hdc: windows_sys::Win32::Graphics::Gdi::HDC =
                core::ptr::with_exposed_provenance_mut(wparam);
            // SAFETY: `wParam` is the child control's DC for this notification.
            unsafe { SetBkColor(hdc, 0x00FF_FFFF) };
            // SAFETY: Returns the shared stock white brush (never deleted).
            let brush = unsafe { GetStockObject(WHITE_BRUSH) };
            return brush.expose_provenance().cast_signed();
        }
        WM_GETMINMAXINFO if state.min_size != (0, 0) => {
            // SAFETY: Queries our window's DPI.
            let dpi = match unsafe { GetDpiForWindow(hwnd) } {
                0 => 96,
                value => value,
            };
            let mut rect = RECT {
                left: 0,
                top: 0,
                right: scale(state.min_size.0, dpi),
                bottom: scale(state.min_size.1, dpi),
            };
            // SAFETY: `rect` is writable; styles are our window's.
            unsafe { AdjustWindowRectExForDpi(&raw mut rect, state.style, 0, state.ex_style, dpi) };
            let info: *mut MINMAXINFO =
                core::ptr::with_exposed_provenance_mut(lparam.cast_unsigned());
            if !info.is_null() {
                // SAFETY: For WM_GETMINMAXINFO, lParam points to a writable MINMAXINFO.
                unsafe {
                    (*info).ptMinTrackSize = POINT {
                        x: rect.right - rect.left,
                        y: rect.bottom - rect.top,
                    };
                }
            }
            return 0;
        }
        _ => {}
    }
    let decoded = decode(msg, wparam, lparam, |target| foreign_focus(hwnd, target));
    let reply = match decoded {
        Some(message) => match state.handler.try_borrow_mut() {
            Ok(mut slot) => match slot.as_mut() {
                Some(handler) => handler.on(&view, &message),
                None => Reply::Default,
            },
            Err(_) => Reply::Default,
        },
        None => Reply::Default,
    };
    match reply {
        Reply::Handled(value) => value,
        Reply::Default if msg == WM_DPICHANGED => {
            let suggested: *const RECT = core::ptr::with_exposed_provenance(lparam.cast_unsigned());
            if !suggested.is_null() {
                // SAFETY: For WM_DPICHANGED, lParam points to the suggested window RECT.
                let rect = unsafe { *suggested };
                // SAFETY: Applies the suggested rectangle to our window.
                unsafe {
                    SetWindowPos(
                        hwnd,
                        core::ptr::null_mut(),
                        rect.left,
                        rect.top,
                        rect.right - rect.left,
                        rect.bottom - rect.top,
                        SWP_NOZORDER | SWP_NOACTIVATE,
                    )
                };
            }
            0
        }
        Reply::Default => default_proc(hwnd, msg, wparam, lparam),
    }
}

// SAFETY (contract): Windows calls this procedure on the window's thread with a live HWND. The
// only pointer stored in GWLP_USERDATA is the `Box<WindowState>` passed through
// `lpCreateParams`; it is freed exactly once, at WM_NCDESTROY or, if a handler is running, after
// the outermost dispatch returns.
unsafe extern "system" fn trampoline(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if msg == WM_NCCREATE {
        let create: *const CREATESTRUCTW =
            core::ptr::with_exposed_provenance(lparam.cast_unsigned());
        if !create.is_null() {
            // SAFETY: For WM_NCCREATE, lParam points to the CREATESTRUCTW of this creation.
            let params = unsafe { (*create).lpCreateParams };
            if !params.is_null() {
                // SAFETY: Stores our boxed state pointer in the window's user data.
                unsafe {
                    SetWindowLongPtrW(
                        hwnd,
                        GWLP_USERDATA,
                        params.expose_provenance().cast_signed(),
                    )
                };
                // SAFETY: `params` is the live `Box<WindowState>` from `create_window`.
                let state = unsafe { &*params.cast::<WindowState>() };
                state.shared.adopted.set(true);
                state.shared.alive.set(true);
            }
        }
        return default_proc(hwnd, msg, wparam, lparam);
    }
    // SAFETY: Reads the pointer-sized user data of our window.
    let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) };
    let state_ptr = core::ptr::with_exposed_provenance_mut::<WindowState>(raw.cast_unsigned());
    if state_ptr.is_null() {
        return default_proc(hwnd, msg, wparam, lparam);
    }
    if msg == WM_NCDESTROY {
        // SAFETY: Clears the user data so no later message can reach the state.
        unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) };
        // SAFETY: The pointer is the live adopted state (cleared above, freed below at most once).
        let state = unsafe { &*state_ptr };
        state.shared.alive.set(false);
        state.shared.armed.set(false);
        if state.depth.get() == 0 {
            // SAFETY: No dispatch is running on this state; reclaim the box exactly once.
            drop(unsafe { Box::from_raw(state_ptr) });
        } else {
            state.pending_free.set(true);
        }
        return default_proc(hwnd, msg, wparam, lparam);
    }
    // SAFETY: The pointer is the live adopted state; it is not freed while `depth > 0`.
    let state = unsafe { &*state_ptr };
    state.depth.set(state.depth.get().saturating_add(1));
    let result = dispatch(state, hwnd, msg, wparam, lparam);
    let depth = state.depth.get().saturating_sub(1);
    state.depth.set(depth);
    if depth == 0 && state.pending_free.get() {
        // SAFETY: WM_NCDESTROY ran during this dispatch and deferred the free to the outermost
        // frame; nothing references the state any more.
        drop(unsafe { Box::from_raw(state_ptr) });
    }
    result
}

/// Posts application messages to a window from any thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poster {
    hwnd: usize,
}

impl Poster {
    /// `PostMessageW(hwnd, msg, wparam, 0)`; `msg` must be `>= WM_APP` (no pointers in wParam).
    ///
    /// # Errors
    ///
    /// [`WinError`] from `PostMessageW` or for `msg < WM_APP`.
    pub fn post(&self, msg: u32, wparam: usize) -> Result<(), WinError> {
        if msg < WM_APP {
            return Err(WinError::invalid_argument("PostMessageW"));
        }
        let hwnd: HWND = core::ptr::with_exposed_provenance_mut(self.hwnd);
        // SAFETY: Posts a plain-value message; a stale handle only makes the call fail.
        let ok = unsafe { PostMessageW(hwnd, msg, wparam, 0) };
        if ok == 0 {
            return Err(WinError::last("PostMessageW"));
        }
        Ok(())
    }
}

/// Input observed by [`run_loop`] before dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputKind {
    /// `WM_KEYDOWN`/`WM_SYSKEYDOWN` (`Some(vk)`) or `WM_CHAR` (`None`).
    Key {
        /// Virtual key for key-down messages.
        vk: Option<u16>,
    },
    /// `WM_LBUTTONDOWN`, `WM_RBUTTONDOWN`, `WM_MBUTTONDOWN` or `WM_MOUSEWHEEL`.
    Mouse,
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "virtual key codes are the low word of wParam"
)]
const fn observed_input(msg: u32, wparam: usize) -> Option<InputKind> {
    match msg {
        WM_KEYDOWN | WM_SYSKEYDOWN => Some(InputKind::Key {
            vk: Some((wparam & 0xFFFF) as u16),
        }),
        WM_CHAR => Some(InputKind::Key { vk: None }),
        WM_LBUTTONDOWN | WM_RBUTTONDOWN | WM_MBUTTONDOWN | WM_MOUSEWHEEL => Some(InputKind::Mouse),
        _ => None,
    }
}

/// Runs the application's only message loop until `WM_QUIT`; returns its exit code. `observe`
/// sees key and button input first (idle tracking, spec/04 §5.1). Main windows get Tab
/// navigation through `IsDialogMessageW`.
pub fn run_loop(observe: &mut dyn FnMut(InputKind, Hwnd)) -> i32 {
    let mut message = MSG {
        hwnd: core::ptr::null_mut(),
        message: 0,
        wParam: 0,
        lParam: 0,
        time: 0,
        pt: POINT { x: 0, y: 0 },
    };
    loop {
        // SAFETY: `message` is writable storage; retrieves messages for this thread.
        let result = unsafe { GetMessageW(&raw mut message, core::ptr::null_mut(), 0, 0) };
        if result == 0 {
            return i32::try_from(message.wParam).unwrap_or(0);
        }
        if result < 0 {
            return 1;
        }
        if let Some(kind) = observed_input(message.message, message.wParam) {
            observe(kind, Hwnd::from_raw(message.hwnd));
        }
        // SAFETY: Reads the root ancestor of the message window (null-safe).
        let root = unsafe { GetAncestor(message.hwnd, GA_ROOT) };
        let dialog_root = !root.is_null()
            && DIALOG_ROOTS.with(|roots| {
                roots
                    .try_borrow()
                    .is_ok_and(|roots| roots.contains(&root.expose_provenance()))
            });
        // SAFETY: `root` is our main window and `message` the message just retrieved.
        if dialog_root && unsafe { IsDialogMessageW(root, &raw const message) } != 0 {
            continue;
        }
        // SAFETY: Translates the message just retrieved.
        unsafe { TranslateMessage(&raw const message) };
        // SAFETY: Dispatches the message just retrieved to its window procedure.
        unsafe { DispatchMessageW(&raw const message) };
    }
}

/// `PostQuitMessage(code)`.
pub fn quit(code: i32) {
    // SAFETY: Posts WM_QUIT to this thread's queue.
    unsafe { PostQuitMessage(code) };
}

/// Message box kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MbKind {
    /// Information.
    Info,
    /// Warning.
    Warning,
    /// Error.
    Error,
}

/// Message box result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MbResult {
    /// OK.
    Ok,
}

/// `MessageBoxW` — only for errors before the main loop (startup failures).
#[must_use]
pub fn message_box(owner: Option<&Window>, text: &str, caption: &str, kind: MbKind) -> MbResult {
    let (Ok(text), Ok(caption)) = (
        to_wide(text, "MessageBoxW"),
        to_wide(caption, "MessageBoxW"),
    ) else {
        return MbResult::Ok;
    };
    let icon = match kind {
        MbKind::Info => MB_ICONINFORMATION,
        MbKind::Warning => MB_ICONWARNING,
        MbKind::Error => MB_ICONERROR,
    };
    let owner = owner.map_or(core::ptr::null_mut(), |window| window.hwnd.raw());
    // SAFETY: Text and caption are NUL-terminated and live; the owner is ours or null.
    unsafe { MessageBoxW(owner, text.as_ptr(), caption.as_ptr(), MB_OK | icon) };
    MbResult::Ok
}

/// `FindWindowW(class)` + `GetWindowThreadProcessId`: the existing window's poster and process id
/// (second-instance hand-off, spec/04 §1.1).
#[must_use]
pub fn find_window(class: &'static str) -> Option<(Poster, u32)> {
    let name = to_wide(class, "FindWindowW").ok()?;
    // SAFETY: `name` is NUL-terminated and live; no title filter.
    let hwnd = unsafe { FindWindowW(name.as_ptr(), core::ptr::null()) };
    if hwnd.is_null() {
        return None;
    }
    let mut pid = 0_u32;
    // SAFETY: `pid` is writable; the handle may belong to another process (read-only query).
    unsafe { GetWindowThreadProcessId(hwnd, &raw mut pid) };
    Some((
        Poster {
            hwnd: hwnd.expose_provenance(),
        },
        pid,
    ))
}

#[cfg(test)]
mod tests {
    use super::{InputKind, exclusion_verified, observed_input, scale};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        WM_CHAR, WM_KEYDOWN, WM_MOUSEMOVE, WM_RBUTTONDOWN,
    };

    #[test]
    fn exclusion_requires_set_and_exact_read_back() {
        assert!(exclusion_verified(true, Some(0x11)));
        assert!(!exclusion_verified(false, Some(0x11)));
        assert!(!exclusion_verified(true, Some(0x1)));
        assert!(!exclusion_verified(true, Some(0)));
        assert!(!exclusion_verified(true, None));
    }

    #[test]
    fn dip_scaling() {
        assert_eq!(scale(960, 96), 960);
        assert_eq!(scale(960, 144), 1_440);
        assert_eq!(scale(10, 120), 12);
        assert_eq!(scale(i32::MAX, 192), i32::MAX);
    }

    #[test]
    fn observed_input_kinds() {
        assert_eq!(
            observed_input(WM_KEYDOWN, 0x4C),
            Some(InputKind::Key { vk: Some(0x4C) })
        );
        assert_eq!(
            observed_input(WM_CHAR, 0x61),
            Some(InputKind::Key { vk: None })
        );
        assert_eq!(observed_input(WM_RBUTTONDOWN, 0), Some(InputKind::Mouse));
        assert_eq!(observed_input(WM_MOUSEMOVE, 0), None);
    }
}
