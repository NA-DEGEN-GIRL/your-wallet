#![allow(unsafe_code)]
//! Window classes, creation, the single wndproc trampoline, the message loop and posting
//! (spec/01 §7.7).
//!
//! Secret-window behaviour is ported from
//! `archive/spec-v2.4:crates/secret-input-ui/src/recovery_native.rs:615-679,1453-1607`: capture
//! exclusion is applied to the hidden window before any state is attached and read back, the
//! listed messages are blocked, and the per-window pointer is cleared at `WM_NCDESTROY`. The
//! one-shot `PRESENTED` guard is gone; classes are registered once; the app owns the loop.
//!
//! Message parameters are not trusted to carry our pointers: the per-window state is found in a
//! thread-local registry (hwnd → state), never through `GWLP_USERDATA` (which another process can
//! overwrite), and `WM_NCCREATE` adopts its `lpCreateParams` only when it is exactly the state
//! [`create_window`] is creating on this thread. Messages whose `lParam` the trampoline
//! dereferences are never legitimately posted, so [`run_loop`] drops posted copies.

use core::cell::{Cell, RefCell};
use core::fmt;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::Foundation::{
    ERROR_CLASS_ALREADY_EXISTS, ERROR_INVALID_WINDOW_HANDLE, HWND, LPARAM, LRESULT, POINT, RECT,
    WPARAM,
};
use windows_sys::Win32::Graphics::Gdi::{
    GetMonitorInfoW, GetStockObject, GetUpdateRect, InvalidateRect, MONITOR_DEFAULTTONEAREST,
    MONITOR_DEFAULTTOPRIMARY, MONITORINFO, MonitorFromWindow, RDW_ALLCHILDREN, RDW_INVALIDATE,
    RDW_UPDATENOW, RedrawWindow, SetBkColor, WHITE_BRUSH,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::{
    ICC_BAR_CLASSES, ICC_STANDARD_CLASSES, INITCOMMONCONTROLSEX, InitCommonControlsEx,
    SetScrollInfo,
};
use windows_sys::Win32::UI::HiDpi::{
    AdjustWindowRectExForDpi, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForSystem,
    GetDpiForWindow, GetSystemMetricsForDpi, SetProcessDpiAwarenessContext,
};
use windows_sys::Win32::UI::Input::Ime::ImmAssociateContextEx;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    EnableWindow, GetFocus, ReleaseCapture, SetCapture, SetFocus,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CREATESTRUCTW, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, CreateWindowExW, DefWindowProcW,
    DestroyWindow, DispatchMessageW, FLASHW_ALL, FLASHW_TIMERNOFG, FLASHWINFO, FindWindowExW,
    FlashWindowEx, GA_ROOT, GWLP_USERDATA, GetAncestor, GetClientRect, GetForegroundWindow,
    GetMessageW, GetScrollInfo, GetWindowDisplayAffinity, GetWindowLongPtrW,
    GetWindowThreadProcessId, HICON, HWND_NOTOPMOST, HWND_TOPMOST, IDC_ARROW, IDI_APPLICATION,
    IMAGE_ICON, IsChild, IsDialogMessageW, IsIconic, IsWindowVisible, KillTimer, LR_DEFAULTCOLOR,
    LoadCursorW, LoadIconW, LoadImageW, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONWARNING, MB_OK,
    MINMAXINFO, MSG, MessageBoxW, PostMessageW, PostQuitMessage, RegisterClassExW, SB_VERT,
    SCROLLINFO, SIF_DISABLENOSCROLL, SIF_PAGE, SIF_POS, SIF_RANGE, SIF_TRACKPOS, SM_CXICON,
    SM_CXSMICON, SM_CYICON, SM_CYSMICON, SPI_GETWHEELSCROLLLINES, SW_HIDE, SW_INVALIDATE,
    SW_RESTORE, SW_SCROLLCHILDREN, SW_SHOW, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER,
    SYSTEM_METRICS_INDEX, ScrollWindowEx, SendMessageW, SetForegroundWindow, SetTimer,
    SetWindowDisplayAffinity, SetWindowLongPtrW, SetWindowPos, SetWindowTextW, ShowWindow,
    SystemParametersInfoW, TranslateMessage, WDA_EXCLUDEFROMCAPTURE, WM_APP, WM_CHAR, WM_CREATE,
    WM_CTLCOLORBTN, WM_CTLCOLORSTATIC, WM_DESTROY, WM_DPICHANGED, WM_DRAWITEM, WM_ERASEBKGND,
    WM_GETMINMAXINFO, WM_IME_STARTCOMPOSITION, WM_KEYDOWN, WM_LBUTTONDOWN, WM_MBUTTONDOWN,
    WM_MOUSEWHEEL, WM_NCCREATE, WM_NCDESTROY, WM_PAINT, WM_RBUTTONDOWN, WM_SETCURSOR, WM_SETREDRAW,
    WM_SYSKEYDOWN, WM_TIMER, WNDCLASSEXW, WS_CAPTION, WS_CHILD, WS_CLIPCHILDREN, WS_EX_APPWINDOW,
    WS_EX_CONTROLPARENT, WS_EX_DLGMODALFRAME, WS_EX_TOPMOST, WS_MINIMIZEBOX, WS_OVERLAPPED,
    WS_OVERLAPPEDWINDOW, WS_SYSMENU, WS_THICKFRAME, WS_VSCROLL,
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
    pub(crate) fn raw(self) -> HWND {
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
    /// Live windows of this thread: hwnd → address of the adopted `Box<WindowState>`. The
    /// trampoline dereferences only a state found here (added at `WM_NCCREATE`, removed at
    /// `WM_NCDESTROY`).
    static STATES: RefCell<HashMap<usize, usize>> = RefCell::new(HashMap::new());
    /// The state box [`create_window`] is creating on this thread (0 = none). `WM_NCCREATE`
    /// adopts exactly this pointer, once.
    static CREATING: Cell<usize> = const { Cell::new(0) };
    /// [`Handler::on`] calls running on this thread. While one runs, its window's handler (and
    /// the app state behind it) is borrowed, so a `WM_PAINT` sent from inside it could not be
    /// painted: synchronous repaints wait for the last call to return ([`Window::update_now`]).
    static HANDLERS: Cell<u32> = const { Cell::new(0) };
    /// Repaints owed to our windows: hwnd and the rectangle to invalidate again (`None` = only
    /// what is still invalid), run when the last handler call returns ([`flush_owed`]).
    static OWED: RefCell<Vec<(usize, Option<RECT>)>> = const { RefCell::new(Vec::new()) };
    /// [`flush_owed`] is running (it does not start again from the paints it causes).
    static FLUSHING: Cell<bool> = const { Cell::new(false) };
}

/// Records a repaint owed to `hwnd` (merged with one already owed: the rectangles' union).
fn owe(hwnd: HWND, rect: Option<RECT>) {
    OWED.with(|owed| {
        let Ok(mut owed) = owed.try_borrow_mut() else {
            return;
        };
        let key = hwnd.expose_provenance();
        match owed.iter_mut().find(|(owner, _)| *owner == key) {
            Some((_, existing)) => {
                *existing = match (*existing, rect) {
                    (Some(a), Some(b)) => Some(RECT {
                        left: a.left.min(b.left),
                        top: a.top.min(b.top),
                        right: a.right.max(b.right),
                        bottom: a.bottom.max(b.bottom),
                    }),
                    (a, b) => a.or(b),
                };
            }
            None => owed.push((key, rect)),
        }
    });
}

/// A `WM_PAINT` that cannot be painted now (the handler, or the app state it needs, is busy in a
/// call further up this thread's stack): the default processing validates the update region as
/// before, so a queued paint does not repeat, and the region is owed — repainted when the last
/// running handler call returns ([`flush_owed`]) instead of keeping whatever pixels were there
/// (after `ScrollWindowEx`, a stale copy of the content).
fn defer_paint(hwnd: HWND) {
    let mut update = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    // SAFETY: Reads our live window's update rectangle into writable storage (no erase).
    let pending = unsafe { GetUpdateRect(hwnd, &raw mut update, 0) } != 0;
    default_proc(hwnd, WM_PAINT, 0, 0);
    if pending {
        owe(hwnd, Some(update));
    }
}

/// Runs the repaints owed while handlers ran: invalidates each owed rectangle again and paints
/// the window and its children synchronously (`RDW_UPDATENOW`), now that no handler holds the
/// app state. Paints deferred once more during this flush (state still borrowed by code outside
/// any handler, e.g. a test) are only invalidated, for the message loop to paint.
fn flush_owed() {
    if FLUSHING.with(Cell::get) {
        return;
    }
    let take = || {
        OWED.with(|owed| {
            owed.try_borrow_mut()
                .map(|mut owed| core::mem::take(&mut *owed))
                .unwrap_or_default()
        })
    };
    let owed = take();
    if owed.is_empty() {
        return;
    }
    FLUSHING.with(|flag| flag.set(true));
    for (key, rect) in &owed {
        repaint_owed(*key, rect.as_ref(), true);
    }
    FLUSHING.with(|flag| flag.set(false));
    for (key, rect) in &take() {
        repaint_owed(*key, rect.as_ref(), false);
    }
}

fn repaint_owed(key: usize, rect: Option<&RECT>, now: bool) {
    let hwnd: HWND = core::ptr::with_exposed_provenance_mut(key);
    // Only a window still alive on this thread (one destroyed meanwhile is skipped).
    if registered_state(hwnd).is_null() {
        return;
    }
    if let Some(rect) = rect {
        // SAFETY: Invalidates part of our live window's client area; `rect` is valid for the
        // call; no erase.
        unsafe { InvalidateRect(hwnd, rect, 0) };
    }
    if now {
        // SAFETY: Paints our live window's and its children's pending update regions now; null
        // rectangle and region = no new invalidation.
        unsafe {
            RedrawWindow(
                hwnd,
                core::ptr::null(),
                core::ptr::null_mut(),
                RDW_UPDATENOW | RDW_ALLCHILDREN,
            )
        };
    }
}

/// Calls the window's handler for one message, counting the call ([`HANDLERS`]); `None` when the
/// handler is already running (a message sent to the window from inside its own handler). When
/// the last running handler call returns, the repaints owed meanwhile run.
fn call_handler(state: &WindowState, view: &Window, message: &Msg) -> Option<Reply> {
    let reply = {
        let Ok(mut slot) = state.handler.try_borrow_mut() else {
            return None;
        };
        let Some(handler) = slot.as_mut() else {
            return Some(Reply::Default);
        };
        HANDLERS.with(|count| count.set(count.get().saturating_add(1)));
        let reply = handler.on(view, message);
        HANDLERS.with(|count| count.set(count.get().saturating_sub(1)));
        reply
    };
    if HANDLERS.with(Cell::get) == 0 {
        flush_owed();
    }
    Some(reply)
}

/// The `WM_NCCREATE` adoption rule: the creation parameter is exactly the state being created
/// on this thread, the window's user data was never set and the window is not registered yet.
const fn may_adopt(params: usize, creating: usize, user_data: isize, registered: bool) -> bool {
    params != 0 && params == creating && user_data == 0 && !registered
}

/// The registered state of `hwnd` on this thread (null when there is none).
fn registered_state(hwnd: HWND) -> *mut WindowState {
    let address = STATES.with(|states| {
        states
            .try_borrow()
            .ok()
            .and_then(|states| states.get(&hwnd.expose_provenance()).copied())
            .unwrap_or(0)
    });
    core::ptr::with_exposed_provenance_mut(address)
}

fn register_state(hwnd: HWND, state: usize) -> bool {
    STATES.with(|states| {
        states.try_borrow_mut().is_ok_and(|mut states| {
            states.insert(hwnd.expose_provenance(), state);
            true
        })
    })
}

fn unregister_state(hwnd: HWND) {
    STATES.with(|states| {
        if let Ok(mut states) = states.try_borrow_mut() {
            states.remove(&hwnd.expose_provenance());
        }
    });
}

/// Messages the trampoline treats as coming from the system (it dereferences their `lParam` or
/// they change the window's lifecycle). Windows sends them; a posted copy is forged and
/// [`run_loop`] drops it.
const fn never_posted(msg: u32) -> bool {
    matches!(
        msg,
        WM_NCCREATE
            | WM_CREATE
            | WM_NCDESTROY
            | WM_DESTROY
            | WM_GETMINMAXINFO
            | WM_DPICHANGED
            | WM_DRAWITEM
            | WM_CTLCOLORSTATIC
            | WM_CTLCOLORBTN
    )
}

fn module_handle() -> Result<windows_sys::Win32::Foundation::HINSTANCE, WinError> {
    // SAFETY: A null module name returns the current executable module handle.
    let module = unsafe { GetModuleHandleW(core::ptr::null()) };
    if module.is_null() {
        return Err(WinError::last("GetModuleHandleW"));
    }
    Ok(module)
}

/// Integer resource identifier of the application icon group (`RT_GROUP_ICON 1` in
/// `crates/yw-app/icons/yw-app.res`, spec/04 §1.7).
const APP_ICON_ID: usize = 1;

/// The application icon at the system large and small icon sizes (system DPI), loaded once from
/// the executable and kept for the process lifetime (shared by every class, never destroyed). The
/// class icons are what the caption (also with `WS_EX_DLGMODALFRAME`), taskbar and Alt-Tab show.
/// `None` when the executable has no such resource (test binaries): classes then use the shared
/// system application icon.
fn app_icons() -> Option<(HICON, HICON)> {
    static ICONS: OnceLock<Option<(usize, usize)>> = OnceLock::new();
    let icons = *ICONS.get_or_init(|| {
        let instance = module_handle().ok()?;
        // SAFETY: No arguments; returns the system DPI.
        let dpi = unsafe { GetDpiForSystem() };
        let big = load_app_icon(instance, SM_CXICON, SM_CYICON, dpi)?;
        let small = load_app_icon(instance, SM_CXSMICON, SM_CYSMICON, dpi)?;
        Some((big.expose_provenance(), small.expose_provenance()))
    });
    icons.map(|(big, small)| {
        (
            core::ptr::with_exposed_provenance_mut(big),
            core::ptr::with_exposed_provenance_mut(small),
        )
    })
}

fn load_app_icon(
    instance: windows_sys::Win32::Foundation::HINSTANCE,
    width_metric: SYSTEM_METRICS_INDEX,
    height_metric: SYSTEM_METRICS_INDEX,
    dpi: u32,
) -> Option<HICON> {
    // SAFETY: Metric query; no pointers.
    let width = unsafe { GetSystemMetricsForDpi(width_metric, dpi) };
    // SAFETY: Metric query; no pointers.
    let height = unsafe { GetSystemMetricsForDpi(height_metric, dpi) };
    // SAFETY: `instance` is this executable's module handle and the name is an integer resource
    // identifier (MAKEINTRESOURCEW), which the call does not dereference. Without LR_SHARED the
    // icon is a private copy at the requested size; it is intentionally never destroyed.
    let icon = unsafe {
        LoadImageW(
            instance,
            core::ptr::without_provenance(APP_ICON_ID),
            IMAGE_ICON,
            width,
            height,
            LR_DEFAULTCOLOR,
        )
    };
    (!icon.is_null()).then_some(icon)
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
        // The bar classes include the tooltip control (icon buttons' tooltips, 2026-11-11).
        dwICC: ICC_STANDARD_CLASSES | ICC_BAR_CLASSES,
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
    let (icon, small_icon) = app_icons().unwrap_or_else(|| {
        // SAFETY: Loads the shared system application icon (the system derives the small one).
        let shared = unsafe { LoadIconW(core::ptr::null_mut(), IDI_APPLICATION) };
        (shared, core::ptr::null_mut())
    });
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
        hIconSm: small_icon,
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
            // The main window scrolls its own client area (spec/04 §1.7): the bar is always
            // there (disabled when everything fits, `set_vscroll_content`) so the layout width
            // never jumps.
            WindowKind::Main => (
                WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_VSCROLL,
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
    paints: Cell<PaintStats>,
}

/// `WM_PAINT` messages a window received and the bounding box of their update rectangles
/// (client pixels), for repaint checks ([`Window::take_paint_stats`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PaintStats {
    /// Number of `WM_PAINT` messages.
    pub count: u32,
    /// Bounding box of their update rectangles (empty when `count` is 0).
    pub area: Rect,
}

impl PaintStats {
    fn record(self, rect: Rect) -> Self {
        let area = if self.count == 0 {
            rect
        } else {
            let left = self.area.x.min(rect.x);
            let top = self.area.y.min(rect.y);
            let right = self.area.right().max(rect.right());
            let bottom = self.area.bottom().max(rect.bottom());
            Rect::new(
                left,
                top,
                right.saturating_sub(left),
                bottom.saturating_sub(top),
            )
        };
        Self {
            count: self.count.saturating_add(1),
            area,
        }
    }
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

    /// The raw handle while the window exists. After `WM_NCDESTROY` the handle value may be
    /// reused by an unrelated window, so every method below does nothing (or returns a neutral
    /// value) once the window is gone.
    fn live(&self) -> Option<HWND> {
        self.shared.alive.get().then(|| self.hwnd.raw())
    }

    /// Shows the window (restores it when minimized).
    pub fn show(&self) {
        let Some(hwnd) = self.live() else { return };
        // SAFETY: Queries the minimized state of our live window handle.
        let iconic = unsafe { IsIconic(hwnd) } != 0;
        // SAFETY: Shows our live window handle.
        unsafe { ShowWindow(hwnd, if iconic { SW_RESTORE } else { SW_SHOW }) };
    }

    /// Whether the window is hidden or minimized (a destroyed window counts as hidden): the
    /// app pauses its periodic balance reads meanwhile.
    #[must_use]
    pub fn is_hidden_or_minimized(&self) -> bool {
        let Some(hwnd) = self.live() else { return true };
        // SAFETY: Queries the visibility of our live window handle.
        let visible = unsafe { IsWindowVisible(hwnd) } != 0;
        // SAFETY: Queries the minimized state of our live window handle.
        !visible || unsafe { IsIconic(hwnd) } != 0
    }

    /// Hides the window.
    pub fn hide(&self) {
        let Some(hwnd) = self.live() else { return };
        // SAFETY: Hides our live window handle.
        unsafe { ShowWindow(hwnd, SW_HIDE) };
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
        let Some(hwnd) = self.live() else { return };
        // SAFETY: Changes the enabled state of our live window handle.
        unsafe { EnableWindow(hwnd, i32::from(enabled)) };
    }

    /// Adds or removes `WS_EX_TOPMOST`.
    pub fn set_topmost(&self, topmost: bool) {
        let Some(hwnd) = self.live() else { return };
        let after = if topmost {
            HWND_TOPMOST
        } else {
            HWND_NOTOPMOST
        };
        // SAFETY: Changes only the z-order of our live window.
        unsafe {
            SetWindowPos(
                hwnd,
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
        let Some(hwnd) = self.live() else {
            return false;
        };
        // SAFETY: Requests foreground activation for our live window handle.
        unsafe { SetForegroundWindow(hwnd) != 0 }
    }

    /// `FlashWindowEx(FLASHW_ALL | FLASHW_TIMERNOFG)`.
    pub fn flash(&self) {
        let Some(hwnd) = self.live() else { return };
        let info = FLASHWINFO {
            cbSize: u32::try_from(core::mem::size_of::<FLASHWINFO>()).unwrap_or(20),
            hwnd,
            dwFlags: FLASHW_ALL | FLASHW_TIMERNOFG,
            uCount: 0,
            dwTimeout: 0,
        };
        // SAFETY: `info` is a valid FLASHWINFO for our live window.
        unsafe { FlashWindowEx(&raw const info) };
    }

    /// Invalidates the whole client area. No background erase: every paint session draws the
    /// full update area into a back buffer ([`PaintDc`]).
    pub fn invalidate(&self) {
        let Some(hwnd) = self.live() else { return };
        // SAFETY: Invalidates our live window's client area (null rect = everything).
        unsafe { InvalidateRect(hwnd, core::ptr::null(), 0) };
    }

    /// Suspends drawing (`WM_SETREDRAW` false) so many child moves (a scroll or re-layout) land
    /// as one repaint in [`Window::end_batch`] instead of one flash per control.
    pub fn begin_batch(&self) {
        let Some(hwnd) = self.live() else { return };
        // SAFETY: WM_SETREDRAW(FALSE) to our live window; no pointers involved.
        unsafe { SendMessageW(hwnd, WM_SETREDRAW, 0, 0) };
    }

    /// Resumes drawing, invalidates the window and all children, and paints them once, all
    /// together ([`Window::update_now`]: synchronously, or right after the running handler
    /// returns).
    pub fn end_batch(&self) {
        let Some(hwnd) = self.live() else { return };
        // SAFETY: WM_SETREDRAW(TRUE) to our live window; no pointers involved.
        unsafe { SendMessageW(hwnd, WM_SETREDRAW, 1, 0) };
        // SAFETY: Invalidates our live window and its children (null rect/region = the whole
        // client area); no erase, every paint draws the full area into a back buffer.
        unsafe {
            RedrawWindow(
                hwnd,
                core::ptr::null(),
                core::ptr::null_mut(),
                RDW_INVALIDATE | RDW_ALLCHILDREN,
            )
        };
        self.update_now();
    }

    /// For a handler that cannot paint now (its state is busy further up the stack): validates
    /// the pending update region like the default `WM_PAINT` processing, and repaints it when
    /// the last running handler call returns — never leaving the old pixels there. Call it
    /// instead of answering [`Msg::Paint`] with [`Reply::Default`].
    pub fn defer_paint(&self) {
        let Some(hwnd) = self.live() else { return };
        defer_paint(hwnd);
    }

    /// Invalidates only `rect` (client pixels), without background erase, so a periodic update
    /// (a progress bar, a countdown) repaints just that part.
    pub fn invalidate_rect(&self, rect: Rect) {
        let Some(hwnd) = self.live() else { return };
        if rect.w <= 0 || rect.h <= 0 {
            return;
        }
        let win = rect.to_win();
        // SAFETY: Invalidates part of our live window's client area; `win` is valid for the call.
        unsafe { InvalidateRect(hwnd, &raw const win, 0) };
    }

    /// The `WM_PAINT` statistics since the previous call (then resets them).
    #[must_use]
    pub fn take_paint_stats(&self) -> PaintStats {
        self.shared.paints.replace(PaintStats::default())
    }

    /// Sets the title (never pass secrets).
    pub fn set_title(&self, title: &str) {
        let Some(hwnd) = self.live() else { return };
        if let Ok(wide) = to_wide(title, "SetWindowTextW") {
            // SAFETY: `wide` is NUL-terminated and live for the call. Secret windows block
            // WM_SETTEXT once armed, so titles are set before attaching or on non-secret windows.
            unsafe { SetWindowTextW(hwnd, wide.as_ptr()) };
        }
    }

    /// Starts (or restarts) timer `id` every `ms` milliseconds.
    ///
    /// # Errors
    ///
    /// [`WinError`] from `SetTimer` (`ERROR_INVALID_WINDOW_HANDLE` once the window is gone).
    pub fn set_timer(&self, id: usize, ms: u32) -> Result<(), WinError> {
        let hwnd = self
            .live()
            .ok_or(WinError::new("SetTimer", ERROR_INVALID_WINDOW_HANDLE))?;
        // SAFETY: Creates a window timer on our live window (no callback).
        let result = unsafe { SetTimer(hwnd, id, ms, None) };
        if result == 0 {
            return Err(WinError::last("SetTimer"));
        }
        Ok(())
    }

    /// Stops timer `id`.
    pub fn kill_timer(&self, id: usize) {
        let Some(hwnd) = self.live() else { return };
        // SAFETY: Kills a timer on our live window; unknown ids are harmless.
        unsafe { KillTimer(hwnd, id) };
    }

    /// Current DPI (96 if unknown).
    #[must_use]
    pub fn dpi(&self) -> u32 {
        let Some(hwnd) = self.live() else { return 96 };
        // SAFETY: Queries the DPI of our live window.
        let dpi = unsafe { GetDpiForWindow(hwnd) };
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
        if let Some(hwnd) = self.live() {
            // SAFETY: `rect` is writable storage for our live window's client rectangle.
            unsafe { GetClientRect(hwnd, &raw mut rect) };
        }
        Rect::from_win(&rect)
    }

    /// Captures the mouse.
    pub fn set_capture(&self) {
        let Some(hwnd) = self.live() else { return };
        // SAFETY: Captures the mouse for our live window.
        unsafe { SetCapture(hwnd) };
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
        let Some(hwnd) = self.live() else { return };
        // SAFETY: Sets focus to our live window.
        unsafe { SetFocus(hwnd) };
    }

    /// Whether this window is the foreground window.
    #[must_use]
    pub fn is_foreground(&self) -> bool {
        let Some(hwnd) = self.live() else {
            return false;
        };
        // SAFETY: Reads the foreground window handle.
        let foreground = unsafe { GetForegroundWindow() };
        foreground == hwnd
    }

    /// Whether keyboard focus is this window or one of its children.
    #[must_use]
    pub fn focus_within(&self) -> bool {
        let Some(hwnd) = self.live() else {
            return false;
        };
        // SAFETY: Reads the thread's focus window.
        let focus = unsafe { GetFocus() };
        if focus.is_null() {
            return false;
        }
        // SAFETY: Queries the parent/child relation of two window handles.
        focus == hwnd || unsafe { IsChild(hwnd, focus) } != 0
    }

    /// Centers the window on `anchor`'s monitor work area (or its own monitor), fitted into it
    /// (2026-11-10): the window is first moved onto that monitor, so a monitor of another DPI
    /// resizes it through `WM_DPICHANGED` (its suggested rectangle), and then its outer size is
    /// cut to the work area and centered. The minimum track size of `WM_GETMINMAXINFO` still
    /// applies (`SetWindowPos` goes through `WM_WINDOWPOSCHANGING`).
    pub fn center_on(&self, anchor: Option<&Self>) {
        let Some(hwnd) = self.live() else { return };
        let target = anchor.and_then(Self::live).unwrap_or(hwnd);
        let Some(work) = work_area(target, MONITOR_DEFAULTTONEAREST) else {
            return;
        };
        // SAFETY: Moves our live window onto the target monitor (size unchanged); a DPI change
        // there is handled by our window procedure (the suggested rectangle).
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
        let mut rect = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        // SAFETY: `rect` is writable storage for our live window's rectangle.
        unsafe { windows_sys::Win32::UI::WindowsAndMessaging::GetWindowRect(hwnd, &raw mut rect) };
        let work_w = (work.right - work.left).max(1);
        let work_h = (work.bottom - work.top).max(1);
        let w = (rect.right - rect.left).min(work_w);
        let h = (rect.bottom - rect.top).min(work_h);
        let x = work.left + (work_w - w).max(0) / 2;
        let y = work.top + (work_h - h).max(0) / 2;
        // SAFETY: Moves and sizes our live window inside the work area.
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

    /// Moves and sizes the window (client coordinates of the parent for a child panel).
    pub fn set_rect(&self, rect: Rect) {
        let Some(hwnd) = self.live() else { return };
        // SAFETY: Moves and sizes our live window; no z-order or activation change.
        unsafe {
            SetWindowPos(
                hwnd,
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
        let Some(hwnd) = self.live() else { return };
        let info = SCROLLINFO {
            cbSize: u32::try_from(core::mem::size_of::<SCROLLINFO>()).unwrap_or(28),
            fMask: SIF_RANGE | SIF_PAGE | SIF_POS,
            nMin: 0,
            nMax: max.max(0),
            nPage: u32::try_from(page.max(0)).unwrap_or(0),
            nPos: pos.max(0),
            nTrackPos: 0,
        };
        // SAFETY: `info` is a valid SCROLLINFO for our live window's vertical bar.
        unsafe { SetScrollInfo(hwnd, SB_VERT, &raw const info, 1) };
    }

    /// Sets the vertical scroll bar for `content` pixels of content seen through a `page`-pixel
    /// view at offset `pos`. The bar stays visible (disabled) when everything fits
    /// (`SIF_DISABLENOSCROLL`), so the client width does not change with the content.
    pub fn set_vscroll_content(&self, pos: i32, page: i32, content: i32) {
        let Some(hwnd) = self.live() else { return };
        let info = SCROLLINFO {
            cbSize: u32::try_from(core::mem::size_of::<SCROLLINFO>()).unwrap_or(28),
            fMask: SIF_RANGE | SIF_PAGE | SIF_POS | SIF_DISABLENOSCROLL,
            nMin: 0,
            // The range is inclusive: positions 0..=content-page.
            nMax: content.saturating_sub(1).max(0),
            nPage: u32::try_from(page.max(0)).unwrap_or(0),
            nPos: pos.max(0),
            nTrackPos: 0,
        };
        // SAFETY: `info` is a valid SCROLLINFO for our live window's vertical bar.
        unsafe { SetScrollInfo(hwnd, SB_VERT, &raw const info, 1) };
    }

    /// Scrolls the client area by `dy` pixels (positive = content moves down): the system copies
    /// the pixels that stay visible, moves every child window with them
    /// (`SW_SCROLLCHILDREN`) and invalidates only the uncovered strip (`SW_INVALIDATE`, no
    /// erase). Call [`Window::update_now`] to paint that strip at once.
    pub fn scroll_content(&self, dy: i32) {
        let Some(hwnd) = self.live() else { return };
        if dy == 0 {
            return;
        }
        // SAFETY: Scrolls our live window's whole client area (null rectangles and region; no
        // output pointers).
        unsafe {
            ScrollWindowEx(
                hwnd,
                0,
                dy,
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                SW_SCROLLCHILDREN | SW_INVALIDATE,
            )
        };
    }

    /// Paints whatever is invalid in the window and its children (nothing else): at once, or —
    /// when called from inside a handler, where the `WM_PAINT` would find the handler and the app
    /// state still borrowed and be dropped unpainted — right after the last running handler call
    /// returns, still before the next message is taken from the queue.
    pub fn update_now(&self) {
        let Some(hwnd) = self.live() else { return };
        if HANDLERS.with(Cell::get) > 0 {
            owe(hwnd, None);
            return;
        }
        // SAFETY: Validates our live window and children by painting their pending update
        // regions; null rectangle and region = no new invalidation.
        unsafe {
            RedrawWindow(
                hwnd,
                core::ptr::null(),
                core::ptr::null_mut(),
                RDW_UPDATENOW | RDW_ALLCHILDREN,
            )
        };
    }

    /// The thumb position while it is dragged (`SB_THUMBTRACK`), 0 if unknown.
    #[must_use]
    pub fn vscroll_track_pos(&self) -> i32 {
        let Some(hwnd) = self.live() else { return 0 };
        let mut info = SCROLLINFO {
            cbSize: u32::try_from(core::mem::size_of::<SCROLLINFO>()).unwrap_or(28),
            fMask: SIF_TRACKPOS,
            nMin: 0,
            nMax: 0,
            nPage: 0,
            nPos: 0,
            nTrackPos: 0,
        };
        // SAFETY: `info` is writable with `cbSize` and `fMask` set; the window is live.
        let ok = unsafe { GetScrollInfo(hwnd, SB_VERT, &raw mut info) };
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
        // A destroyed window measures on the screen DC (null window) instead of a stale handle.
        let hwnd = self.live().unwrap_or(core::ptr::null_mut());
        super::paint::measure_with(hwnd, font, text, width, flags)
    }

    /// The raw handle value while the window exists, 0 (no window) afterwards.
    pub(crate) fn live_raw_id(&self) -> usize {
        if self.shared.alive.get() {
            self.hwnd.0
        } else {
            0
        }
    }

    pub(crate) fn alive_probe(&self) -> Rc<dyn Fn() -> bool> {
        let shared = Rc::clone(&self.shared);
        Rc::new(move || shared.alive.get())
    }

    /// Starts painting (only while handling [`Msg::Paint`]).
    ///
    /// # Errors
    ///
    /// [`WinError`] from `BeginPaint` (`ERROR_INVALID_WINDOW_HANDLE` once the window is gone).
    pub fn begin_paint(&self) -> Result<PaintDc<'_>, WinError> {
        let hwnd = self
            .live()
            .ok_or(WinError::new("BeginPaint", ERROR_INVALID_WINDOW_HANDLE))?;
        PaintDc::begin(hwnd)
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

/// A top-level window's place (spec/04 §1.7, 2026-11-10): its restored (normal) rectangle in
/// screen pixels — also while maximized or minimized —, whether it is (or restores to)
/// maximized, and its DPI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    /// The restored rectangle (outer, screen pixels).
    pub rect: Rect,
    /// Maximized, or minimized from maximized.
    pub maximized: bool,
    /// The window's DPI.
    pub dpi: u32,
}

/// A monitor's work area (screen pixels) and effective DPI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MonitorArea {
    /// The work area (without the taskbar and docked toolbars).
    pub work: Rect,
    /// `GetDpiForMonitor(MDT_EFFECTIVE_DPI)` (96 when it fails).
    pub dpi: u32,
}

fn monitor_area(monitor: windows_sys::Win32::Graphics::Gdi::HMONITOR) -> Option<MonitorArea> {
    if monitor.is_null() {
        return None;
    }
    let empty = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    let mut info = MONITORINFO {
        cbSize: u32::try_from(core::mem::size_of::<MONITORINFO>()).unwrap_or(40),
        rcMonitor: empty,
        rcWork: empty,
        dwFlags: 0,
    };
    // SAFETY: `info` is writable with `cbSize` set; the handle came from `MonitorFrom*`.
    if unsafe { GetMonitorInfoW(monitor, &raw mut info) } == 0 {
        return None;
    }
    let (mut dpi_x, mut dpi_y) = (0_u32, 0_u32);
    // SAFETY: Writes two DWORDs for a monitor handle from `MonitorFrom*`.
    let hr = unsafe {
        windows_sys::Win32::UI::HiDpi::GetDpiForMonitor(
            monitor,
            windows_sys::Win32::UI::HiDpi::MDT_EFFECTIVE_DPI,
            &raw mut dpi_x,
            &raw mut dpi_y,
        )
    };
    Some(MonitorArea {
        work: Rect::from_win(&info.rcWork),
        dpi: if hr >= 0 && dpi_x >= 48 { dpi_x } else { 96 },
    })
}

/// The monitor a screen rectangle mostly lies on (`MonitorFromRect`,
/// `MONITOR_DEFAULTTONULL`): `None` when it touches no monitor (a saved place on a monitor that
/// is gone).
#[must_use]
pub fn monitor_for_rect(rect: Rect) -> Option<MonitorArea> {
    let raw = RECT {
        left: rect.x,
        top: rect.y,
        right: rect.x.saturating_add(rect.w),
        bottom: rect.y.saturating_add(rect.h),
    };
    // SAFETY: Reads a valid RECT; returns null for no monitor with this flag.
    let monitor = unsafe {
        windows_sys::Win32::Graphics::Gdi::MonitorFromRect(
            &raw const raw,
            windows_sys::Win32::Graphics::Gdi::MONITOR_DEFAULTTONULL,
        )
    };
    monitor_area(monitor)
}

/// Screen minus workspace coordinates: `WINDOWPLACEMENT` rectangles are relative to the primary
/// monitor's work area (a taskbar on the left or top moves them).
fn workspace_offset() -> (i32, i32) {
    // SAFETY: The primary monitor (never null with this flag).
    let primary = unsafe {
        windows_sys::Win32::Graphics::Gdi::MonitorFromPoint(
            POINT { x: 0, y: 0 },
            MONITOR_DEFAULTTOPRIMARY,
        )
    };
    let empty = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    let mut info = MONITORINFO {
        cbSize: u32::try_from(core::mem::size_of::<MONITORINFO>()).unwrap_or(40),
        rcMonitor: empty,
        rcWork: empty,
        dwFlags: 0,
    };
    // SAFETY: `info` is writable with `cbSize` set.
    if unsafe { GetMonitorInfoW(primary, &raw mut info) } == 0 {
        return (0, 0);
    }
    (
        info.rcWork.left.saturating_sub(info.rcMonitor.left),
        info.rcWork.top.saturating_sub(info.rcMonitor.top),
    )
}

impl Window {
    /// Where the window is ([`Placement`]; `GetWindowPlacement`, converted to screen pixels).
    #[must_use]
    pub fn placement(&self) -> Option<Placement> {
        let hwnd = self.live()?;
        let empty = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        let mut placement = windows_sys::Win32::UI::WindowsAndMessaging::WINDOWPLACEMENT {
            length: u32::try_from(core::mem::size_of::<
                windows_sys::Win32::UI::WindowsAndMessaging::WINDOWPLACEMENT,
            >())
            .unwrap_or(44),
            flags: 0,
            showCmd: 0,
            ptMinPosition: POINT { x: 0, y: 0 },
            ptMaxPosition: POINT { x: 0, y: 0 },
            rcNormalPosition: empty,
        };
        // SAFETY: `placement` is writable with `length` set; the window is ours and alive.
        if unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::GetWindowPlacement(
                hwnd,
                &raw mut placement,
            )
        } == 0
        {
            return None;
        }
        let show = i32::try_from(placement.showCmd).unwrap_or(0);
        let maximized = show == windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWMAXIMIZED
            || (show == windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWMINIMIZED
                && placement.flags
                    & windows_sys::Win32::UI::WindowsAndMessaging::WPF_RESTORETOMAXIMIZED
                    != 0);
        let (dx, dy) = workspace_offset();
        let mut rect = Rect::from_win(&placement.rcNormalPosition);
        rect.x = rect.x.saturating_add(dx);
        rect.y = rect.y.saturating_add(dy);
        Some(Placement {
            rect,
            maximized,
            dpi: self.dpi(),
        })
    }

    /// The work area and DPI of the monitor the window is on (nearest).
    #[must_use]
    pub fn monitor_area(&self) -> Option<MonitorArea> {
        let hwnd = self.live()?;
        // SAFETY: Returns the nearest monitor of our live window (never null with this flag).
        monitor_area(unsafe { MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) })
    }

    /// The outer size (pixels at `dpi`) of a client area `w`×`h` DIP
    /// (`AdjustWindowRectExForDpi` with the window's styles): the size the window has once on a
    /// monitor of that DPI.
    #[must_use]
    pub fn outer_size(&self, w: i32, h: i32, dpi: u32) -> (i32, i32) {
        let Some(hwnd) = self.live() else {
            return (w, h);
        };
        // SAFETY: Reads our live window's style word.
        let style = unsafe {
            GetWindowLongPtrW(hwnd, windows_sys::Win32::UI::WindowsAndMessaging::GWL_STYLE)
        };
        // SAFETY: Reads our live window's extended style word.
        let ex_style = unsafe {
            GetWindowLongPtrW(
                hwnd,
                windows_sys::Win32::UI::WindowsAndMessaging::GWL_EXSTYLE,
            )
        };
        let mut rect = RECT {
            left: 0,
            top: 0,
            right: scale(w, dpi),
            bottom: scale(h, dpi),
        };
        // SAFETY: `rect` is writable; the style values are our window's (low 32 bits).
        unsafe {
            AdjustWindowRectExForDpi(
                &raw mut rect,
                u32::try_from(style & 0xFFFF_FFFF).unwrap_or(0),
                0,
                u32::try_from(ex_style & 0xFFFF_FFFF).unwrap_or(0),
                dpi,
            )
        };
        (rect.right - rect.left, rect.bottom - rect.top)
    }

    /// Sets the window's outer rectangle (screen pixels). Onto a monitor of another DPI the
    /// window receives `WM_DPICHANGED` (its suggested rectangle is applied); setting the same
    /// rectangle again then sizes it at the new DPI.
    pub fn set_outer_rect(&self, rect: Rect) {
        let Some(hwnd) = self.live() else { return };
        // SAFETY: Positions and sizes our live window; no z-order or activation change.
        unsafe {
            SetWindowPos(
                hwnd,
                core::ptr::null_mut(),
                rect.x,
                rect.y,
                rect.w,
                rect.h,
                SWP_NOZORDER | SWP_NOACTIVATE,
            )
        };
    }

    /// Shows the window maximized (its restored rectangle stays for `복원`).
    pub fn show_maximized(&self) {
        let Some(hwnd) = self.live() else { return };
        // SAFETY: Shows our live window handle maximized.
        unsafe {
            ShowWindow(
                hwnd,
                windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWMAXIMIZED,
            )
        };
    }
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
    let Some(hwnd) = window.live() else {
        return Err(UiError::CaptureExclusionFailed);
    };
    if apply_exclusion(hwnd) {
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
    // The only pointer WM_NCCREATE may adopt during this call (restored afterwards, so a window
    // created from inside another window's creation keeps working).
    let previous = CREATING.with(|slot| slot.replace(raw_state.expose_provenance()));
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
    CREATING.with(|slot| slot.set(previous));
    if hwnd.is_null() {
        let error = WinError::last("CreateWindowExW");
        if !shared.adopted.get() {
            // SAFETY: The trampoline never adopted the box, so it is still exclusively ours.
            drop(unsafe { Box::from_raw(raw_state) });
        }
        return Err(UiError::Os(error));
    }
    if !shared.adopted.get() {
        // The window exists but never adopted its state (no registry entry): it would have no
        // handler and could not be destroyed through `Window`, so remove it now.
        // SAFETY: Destroys the window this thread just created.
        unsafe { DestroyWindow(hwnd) };
        // SAFETY: The trampoline never adopted the box, so it is still exclusively ours.
        drop(unsafe { Box::from_raw(raw_state) });
        return Err(UiError::Os(WinError::new(
            "CreateWindowExW",
            ERROR_INVALID_WINDOW_HANDLE,
        )));
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
        // No input context at all (spec/04 §4.6): the IME cannot compose into a secret window,
        // on top of the WM_IME_* blocking below. Best effort: a failure leaves the blocking.
        // SAFETY: Associates the NULL input context with our live window (flags 0).
        let _ = unsafe { ImmAssociateContextEx(hwnd, core::ptr::null_mut(), 0) };
        // The registry holds the box adopted at WM_NCCREATE; it must be the one created above.
        let state_ptr = registered_state(hwnd);
        if state_ptr.is_null() || state_ptr != raw_state {
            return Err(UiError::Os(WinError::new(
                "CreateWindowExW",
                ERROR_INVALID_WINDOW_HANDLE,
            )));
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
        deliver_synthesized(state_ptr, window.hwnd, &shared, &Msg::Create);
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
    let _ = call_handler(state, &view, msg);
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

/// `WM_DPICHANGED` carries the new DPI in both words of `wParam` (X and Y are always equal on
/// Windows); anything else is not a system-generated message and its `lParam` is not read.
const fn dpi_changed_wparam_valid(wparam: WPARAM) -> bool {
    let x = wparam & 0xFFFF;
    let y = (wparam >> 16) & 0xFFFF;
    x == y && x >= 48 && wparam <= 0xFFFF_FFFF
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
            let control: HWND = core::ptr::with_exposed_provenance_mut(lparam.cast_unsigned());
            let brush = super::controls::ctl_color(hdc, control);
            if brush.is_null() {
                // SAFETY: `wParam` is the child control's DC for this notification.
                unsafe { SetBkColor(hdc, 0x00FF_FFFF) };
                // SAFETY: Returns the shared stock white brush (never deleted).
                let white = unsafe { GetStockObject(WHITE_BRUSH) };
                return white.expose_provenance().cast_signed();
            }
            return brush.expose_provenance().cast_signed();
        }
        WM_DRAWITEM if super::controls::draw_item(hwnd, wparam, lparam) => return 1,
        // Over one of this window's buttons: the hand, and the button's hover fill.
        WM_SETCURSOR if super::controls::set_cursor(hwnd, wparam, lparam) => return 1,
        WM_TIMER if wparam == super::controls::HOVER_TIMER_ID => {
            super::controls::hover_tick(hwnd);
            return 0;
        }
        // Never erase: `PaintDc` fills its back buffer (white, like the class brush) and copies
        // it in one step, so an erase would only flash the background before every repaint.
        WM_ERASEBKGND => return 1,
        WM_PAINT => record_paint(&state.shared, hwnd),
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
        Some(message) => match call_handler(state, &view, &message) {
            Some(reply) => reply,
            None if msg == WM_PAINT => {
                // Sent from inside this window's own handler: painted when it returns.
                defer_paint(hwnd);
                return 0;
            }
            None => Reply::Default,
        },
        None => Reply::Default,
    };
    match reply {
        Reply::Handled(value) => value,
        Reply::Default if msg == WM_DPICHANGED => {
            let suggested: *const RECT = core::ptr::with_exposed_provenance(lparam.cast_unsigned());
            if !suggested.is_null() && dpi_changed_wparam_valid(wparam) {
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

/// Counts a `WM_PAINT` and its update rectangle ([`Window::take_paint_stats`]).
fn record_paint(shared: &Shared, hwnd: HWND) {
    let mut update = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    // SAFETY: Reads our live window's update rectangle into writable storage (no erase).
    if unsafe { GetUpdateRect(hwnd, &raw mut update, 0) } != 0 {
        shared
            .paints
            .set(shared.paints.get().record(Rect::from_win(&update)));
    }
}

/// `WM_NCCREATE`: adopts the state `create_window` is creating on this thread, and nothing else.
/// The `CREATESTRUCTW` in `lparam` is read only while such a creation is in progress, and its
/// `lpCreateParams` must be exactly that state ([`may_adopt`]); a forged `WM_NCCREATE` (sent to
/// an existing window, or with another pointer) is ignored.
fn adopt_on_nccreate(hwnd: HWND, lparam: LPARAM) {
    let creating = CREATING.with(Cell::get);
    let create: *const CREATESTRUCTW = core::ptr::with_exposed_provenance(lparam.cast_unsigned());
    if creating == 0 || create.is_null() {
        return;
    }
    // SAFETY: A creation is in progress on this thread, so this WM_NCCREATE comes from our own
    // CreateWindowExW call and lParam points to the CREATESTRUCTW of that creation.
    let params = unsafe { (*create).lpCreateParams }.expose_provenance();
    // SAFETY: Reads the pointer-sized user data of the window being created.
    let user_data = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) };
    let registered = !registered_state(hwnd).is_null();
    if !may_adopt(params, creating, user_data, registered) || !register_state(hwnd, params) {
        return;
    }
    CREATING.with(|slot| slot.set(0));
    // SAFETY: Marks the window as adopted in its user data (informational only; lookups use the
    // registry).
    unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, params.cast_signed()) };
    let state: *const WindowState = core::ptr::with_exposed_provenance(params);
    // SAFETY: `params` equals the live `Box<WindowState>` that `create_window` is creating.
    let state = unsafe { &*state };
    state.shared.adopted.set(true);
    state.shared.alive.set(true);
}

// SAFETY (contract): Windows calls this procedure on the window's thread with a live HWND. The
// only state pointer ever dereferenced is the `Box<WindowState>` registered for `hwnd` in this
// thread's registry (adopted at WM_NCCREATE from `create_window`'s creation slot); it is freed
// exactly once, at WM_NCDESTROY or, if a handler is running, after the outermost dispatch
// returns. `GWLP_USERDATA`, which other processes can overwrite, is never trusted.
unsafe extern "system" fn trampoline(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if msg == WM_NCCREATE {
        adopt_on_nccreate(hwnd, lparam);
        return default_proc(hwnd, msg, wparam, lparam);
    }
    let state_ptr = registered_state(hwnd);
    if state_ptr.is_null() {
        return default_proc(hwnd, msg, wparam, lparam);
    }
    if msg == WM_NCDESTROY {
        unregister_state(hwnd);
        // SAFETY: Clears the user data marker of our window.
        unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) };
        // SAFETY: The pointer is the live adopted state (unregistered above, freed below at most
        // once).
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

/// Lines one wheel notch scrolls (`SPI_GETWHEELSCROLLLINES`, default 3); `None` = one page
/// per notch (`WHEEL_PAGESCROLL`).
#[must_use]
pub fn wheel_scroll_lines() -> Option<u32> {
    let mut lines: u32 = 3;
    // SAFETY: Reads one UINT into `lines` (valid, writable); no setting changes (fWinIni 0).
    let ok = unsafe {
        SystemParametersInfoW(
            SPI_GETWHEELSCROLLLINES,
            0,
            (&raw mut lines).cast::<core::ffi::c_void>(),
            0,
        )
    };
    match (ok, lines) {
        (0, _) => Some(3),
        (_, u32::MAX) => None,
        (_, lines) => Some(lines),
    }
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
        // GetMessageW returns only posted messages (sent ones are dispatched inside it); a posted
        // pointer or lifecycle message is forged and must not reach a window procedure.
        if never_posted(message.message) {
            continue;
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
        // A held Enter is one press: the dialog manager would turn every repeat into `IDOK`.
        if dialog_root && repeated_enter(message.message, message.wParam, message.lParam) {
            continue;
        }
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

/// Whether a message is an auto-repeat `WM_KEYDOWN` of Enter (bit 30 of `lParam`: the key was
/// already down). A dialog root drops it (2026-11-12): Enter presses the focused button, and a
/// row button keeps the focus when its row goes away, so a held key would press the next row's.
fn repeated_enter(message: u32, wparam: usize, lparam: isize) -> bool {
    const VK_RETURN: usize = 0x0D;
    message == WM_KEYDOWN && wparam == VK_RETURN && lparam & (1 << 30) != 0
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

/// Most top-level windows of one class [`find_windows`] returns.
const MAX_FOUND_WINDOWS: usize = 16;

/// `FindWindowExW(NULL, after, class)` repeated + `GetWindowThreadProcessId`: every top-level
/// window of `class` (at most 16) with its poster and process id (second-instance hand-off,
/// spec/04 §1.1). Any process can register a class of this name, so the caller verifies the
/// process before trusting a window.
#[must_use]
pub fn find_windows(class: &'static str) -> Vec<(Poster, u32)> {
    let Ok(name) = to_wide(class, "FindWindowExW") else {
        return Vec::new();
    };
    let mut found = Vec::new();
    let mut after: HWND = core::ptr::null_mut();
    while found.len() < MAX_FOUND_WINDOWS {
        // SAFETY: `name` is NUL-terminated and live; null parent = top-level windows; `after`
        // is null or a window returned by the previous call; no title filter.
        let hwnd = unsafe {
            FindWindowExW(
                core::ptr::null_mut(),
                after,
                name.as_ptr(),
                core::ptr::null(),
            )
        };
        if hwnd.is_null() {
            break;
        }
        let mut pid = 0_u32;
        // SAFETY: `pid` is writable; the handle may belong to another process (read-only query).
        unsafe { GetWindowThreadProcessId(hwnd, &raw mut pid) };
        if pid != 0 {
            found.push((
                Poster {
                    hwnd: hwnd.expose_provenance(),
                },
                pid,
            ));
        }
        after = hwnd;
    }
    found
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;
    use std::rc::Rc;

    use super::{
        CaptureExclusion, ClassSpec, Handler, InputKind, Msg, Reply, Window, WindowKind,
        WindowSpec, create_window, dpi_changed_wparam_valid, exclusion_verified, may_adopt,
        never_posted, observed_input, register_class, registered_state, repeated_enter, run_loop,
        scale,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CREATESTRUCTW, GWLP_USERDATA, PostMessageW, PostQuitMessage, SendMessageW,
        SetWindowLongPtrW, WM_APP, WM_CHAR, WM_CLOSE, WM_DPICHANGED, WM_DRAWITEM, WM_GETMINMAXINFO,
        WM_KEYDOWN, WM_MOUSEMOVE, WM_NCCREATE, WM_NCDESTROY, WM_RBUTTONDOWN,
    };

    #[test]
    fn adoption_needs_the_creation_slot_and_a_fresh_window() {
        assert!(may_adopt(0x1000, 0x1000, 0, false));
        assert!(!may_adopt(0x2000, 0x1000, 0, false), "another pointer");
        assert!(!may_adopt(0x1000, 0, 0, false), "no creation in progress");
        assert!(!may_adopt(0, 0, 0, false), "null parameter");
        assert!(
            !may_adopt(0x1000, 0x1000, 0x1000, false),
            "user data already set"
        );
        assert!(!may_adopt(0x1000, 0x1000, 0, true), "already registered");
    }

    #[test]
    fn pointer_and_lifecycle_messages_are_never_posted() {
        for msg in [
            WM_NCCREATE,
            WM_NCDESTROY,
            WM_GETMINMAXINFO,
            WM_DPICHANGED,
            WM_DRAWITEM,
        ] {
            assert!(never_posted(msg), "{msg:#x}");
        }
        for msg in [WM_CLOSE, WM_APP, WM_CHAR, WM_KEYDOWN] {
            assert!(!never_posted(msg), "{msg:#x}");
        }
    }

    #[test]
    fn dpi_changed_needs_equal_dpi_words() {
        assert!(dpi_changed_wparam_valid(0x0090_0090));
        assert!(dpi_changed_wparam_valid(0x0060_0060));
        assert!(!dpi_changed_wparam_valid(0x0090_0060));
        assert!(!dpi_changed_wparam_valid(0));
        assert!(!dpi_changed_wparam_valid(0x1_0090_0090));
    }

    struct CountApp(Rc<Cell<u32>>);

    impl Handler for CountApp {
        fn on(&mut self, _window: &Window, msg: &Msg) -> Reply {
            if matches!(msg, Msg::App { .. }) {
                self.0.set(self.0.get() + 1);
            }
            Reply::Default
        }
    }

    /// A real hidden window on the test thread: a bogus `GWLP_USERDATA` (writable by any process
    /// on the desktop), a forged `WM_NCCREATE` and posted lifecycle messages never reach or replace
    /// its state.
    #[test]
    fn forged_messages_and_user_data_never_reach_the_state() {
        const CLASS: &str = "YourWalletV3UnitTestForged";
        register_class(&ClassSpec {
            name: CLASS,
            secret: false,
            capture: CaptureExclusion::Preferred,
        })
        .unwrap();
        let seen = Rc::new(Cell::new(0));
        let window = create_window(
            &WindowSpec::new(CLASS, WindowKind::HiddenTopLevel),
            Box::new(CountApp(Rc::clone(&seen))),
        )
        .unwrap();
        let hwnd = window.hwnd().raw();
        let state = registered_state(hwnd);
        assert!(!state.is_null());

        // SAFETY: Overwrites the user data of our own test window with a bogus pointer value.
        unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0x0123_4560) };
        // SAFETY: Sends a plain-value application message to our own test window.
        unsafe { SendMessageW(hwnd, WM_APP + 1, 0, 0) };
        assert_eq!(seen.get(), 1);

        let forged = CREATESTRUCTW {
            lpCreateParams: core::ptr::with_exposed_provenance_mut(0x0DEA_D000),
            ..CREATESTRUCTW::default()
        };
        // SAFETY: `forged` is a live CREATESTRUCTW for the duration of this synchronous send.
        unsafe {
            SendMessageW(
                hwnd,
                WM_NCCREATE,
                0,
                (&raw const forged).expose_provenance().cast_signed(),
            )
        };
        assert_eq!(registered_state(hwnd), state);
        // SAFETY: Sends a plain-value application message to our own test window.
        unsafe { SendMessageW(hwnd, WM_APP + 1, 0, 0) };
        assert_eq!(seen.get(), 2);

        // Posted WM_NCDESTROY / WM_DRAWITEM are dropped by the loop; WM_APP still arrives.
        // SAFETY: Posts plain values to our own test window.
        unsafe { PostMessageW(hwnd, WM_NCDESTROY, 0, 0) };
        // SAFETY: Posts plain values (a bogus "pointer") to our own test window.
        unsafe { PostMessageW(hwnd, WM_DRAWITEM, 7, 0x0DEA_D000) };
        // SAFETY: Posts a plain-value application message to our own test window.
        unsafe { PostMessageW(hwnd, WM_APP + 2, 0, 0) };
        // SAFETY: Posts WM_QUIT to this thread's queue (retrieved after the messages above).
        unsafe { PostQuitMessage(0) };
        assert_eq!(run_loop(&mut |_, _| {}), 0);
        assert!(window.is_alive());
        assert_eq!(registered_state(hwnd), state);
        assert_eq!(seen.get(), 3);

        drop(window);
        assert!(registered_state(hwnd).is_null());
    }

    #[test]
    fn only_a_repeated_enter_key_down_is_dropped() {
        // Scan code 0x1C, repeat count 1; bit 30 = the key was already down.
        let first = 0x001C_0001_isize;
        let repeat = first | (1 << 30);
        assert!(repeated_enter(WM_KEYDOWN, 0x0D, repeat));
        assert!(!repeated_enter(WM_KEYDOWN, 0x0D, first));
        assert!(!repeated_enter(WM_KEYDOWN, 0x20, repeat));
        assert!(!repeated_enter(WM_CHAR, 0x0D, repeat));
    }

    /// Records, for every `WM_KEYDOWN`, the physical-input checks the approval window uses.
    struct KeyProbe(Rc<core::cell::RefCell<Vec<(u16, bool, bool)>>>);

    impl Handler for KeyProbe {
        fn on(&mut self, _window: &Window, msg: &Msg) -> Reply {
            if let Msg::KeyDown { vk, .. } = msg {
                self.0.borrow_mut().push((
                    *vk,
                    crate::input::is_down_in_message(*vk),
                    crate::input::injected(),
                ));
            }
            Reply::Default
        }
    }

    /// Security review L5: a `WM_KEYDOWN(VK_RETURN)` posted or sent by a program (no keyboard
    /// input) reads "not down" in the message's key state, so the approval window's Enter check
    /// (`is_down_in_message && !injected`) refuses it.
    #[test]
    fn posted_and_sent_enter_are_not_physical() {
        const CLASS: &str = "YourWalletV3UnitTestKeyProbe";
        const VK_RETURN: u16 = 0x0D;
        register_class(&ClassSpec {
            name: CLASS,
            secret: false,
            capture: CaptureExclusion::Preferred,
        })
        .unwrap();
        let seen = Rc::new(core::cell::RefCell::new(Vec::new()));
        let window = create_window(
            &WindowSpec::new(CLASS, WindowKind::HiddenTopLevel),
            Box::new(KeyProbe(Rc::clone(&seen))),
        )
        .unwrap();
        let hwnd = window.hwnd().raw();
        // SAFETY: Sends a plain-value key message to our own test window.
        unsafe { SendMessageW(hwnd, WM_KEYDOWN, usize::from(VK_RETURN), 0x001C_0001) };
        // SAFETY: Posts a plain-value key message to our own test window.
        unsafe { PostMessageW(hwnd, WM_KEYDOWN, usize::from(VK_RETURN), 0x001C_0001) };
        // SAFETY: Posts WM_QUIT to this thread's queue (retrieved after the message above).
        unsafe { PostQuitMessage(0) };
        assert_eq!(run_loop(&mut |_, _| {}), 0);
        let seen = seen.borrow();
        assert_eq!(seen.len(), 2, "{seen:?}");
        for (vk, down, injected) in seen.iter() {
            assert_eq!(*vk, VK_RETURN);
            assert!(!*down, "a synthetic Enter must not read as pressed");
            assert!(!*injected);
        }
        drop(window);
    }

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
