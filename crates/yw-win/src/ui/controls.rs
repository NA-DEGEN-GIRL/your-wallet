#![allow(unsafe_code)]
//! Standard child controls for non-secret values (spec/01 §7.7): push buttons, check boxes, radio
//! buttons, single-line edits (optionally `ES_PASSWORD` for RPC tokens) and static labels.
//! Notifications arrive as [`super::Msg::Command`]. Wallet secrets never go into these controls.
//!
//! Push buttons are owner-drawn (`BS_OWNERDRAW`) from a [`ButtonStyle`] the app passes in (the
//! app's design tokens, spec/04 §1.6); the parent's wndproc paints them on `WM_DRAWITEM` and
//! colors check boxes, radios and read-only edits with the control's backdrop (the card or window
//! color under it) on `WM_CTLCOLORSTATIC`/`WM_CTLCOLORBTN`.

use core::cell::RefCell;
use core::fmt;
use std::collections::HashMap;
use std::rc::Rc;

use windows_sys::Win32::Foundation::{ERROR_INVALID_WINDOW_HANDLE, HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    CreatePen, CreateSolidBrush, DT_CENTER, DT_NOPREFIX, DT_SINGLELINE, DT_VCENTER, DeleteObject,
    DrawTextW, FillRect, HBRUSH, HDC, HFONT, InvalidateRect, PS_SOLID, RoundRect, SelectObject,
    SetBkColor, SetBkMode, SetTextColor, TRANSPARENT,
};
use windows_sys::Win32::UI::Controls::{
    BST_CHECKED, BST_UNCHECKED, DRAWITEMSTRUCT, EM_SETLIMITTEXT, ODS_DISABLED, ODS_FOCUS,
    ODS_NOFOCUSRECT, ODS_SELECTED, ODT_BUTTON,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, IsWindowEnabled, SetFocus};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BM_GETCHECK, BM_SETCHECK, BS_AUTOCHECKBOX, BS_AUTORADIOBUTTON, BS_MULTILINE, BS_OWNERDRAW,
    CreateWindowExW, DestroyWindow, ES_AUTOHSCROLL, ES_PASSWORD, ES_READONLY, GetWindowTextLengthW,
    GetWindowTextW, HMENU, MoveWindow, SW_HIDE, SW_SHOW, SendMessageW, SetWindowTextW, ShowWindow,
    WM_GETFONT, WM_SETFONT, WS_CHILD, WS_EX_CLIENTEDGE, WS_GROUP, WS_TABSTOP, WS_VISIBLE,
};

use super::paint::{Color, Font, Rect};
use super::window::Window;
use crate::error::WinError;
use crate::mem::{WipeBuf, wipe_u16};
use crate::wide::to_wide;

const SS_NOPREFIX: u32 = 0x80;

/// Colors and shape of an owner-drawn push button (the app's design tokens, spec/04 §1.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ButtonStyle {
    /// Fill.
    pub fill: Color,
    /// Label.
    pub text: Color,
    /// 1 px outline.
    pub border: Color,
    /// Fill while pressed.
    pub pressed: Color,
    /// Fill when disabled.
    pub disabled_fill: Color,
    /// Label when disabled.
    pub disabled_text: Color,
    /// Outline when disabled.
    pub disabled_border: Color,
    /// Keyboard focus ring.
    pub focus: Color,
    /// Corner radius in DIP (0 = square).
    pub radius: i32,
}

/// Paint state of one control: the button style (owner-drawn buttons) and the backdrop color,
/// plus the parent and command id it was created with (to recognize its `WM_DRAWITEM`).
#[derive(Clone, Copy, Debug)]
struct ControlPaint {
    style: Option<ButtonStyle>,
    backdrop: Color,
    parent: usize,
    id: u16,
}

thread_local! {
    /// Child control hwnd → paint state (UI thread only; removed when the control is dropped).
    static PAINTS: RefCell<HashMap<usize, ControlPaint>> = RefCell::new(HashMap::new());
    /// Solid brushes by color for `WM_CTLCOLOR*` replies (a handful of theme colors, kept for
    /// the process lifetime because the system uses the brush after the reply).
    static BRUSHES: RefCell<HashMap<u32, usize>> = RefCell::new(HashMap::new());
}

/// Default backdrop of a new control (white).
const DEFAULT_BACKDROP: Color = Color(0x00FF_FFFF);

fn cached_brush(color: Color) -> HBRUSH {
    let key = color.colorref();
    BRUSHES.with(|brushes| {
        let Ok(mut brushes) = brushes.try_borrow_mut() else {
            return core::ptr::null_mut();
        };
        if let Some(handle) = brushes.get(&key) {
            return core::ptr::with_exposed_provenance_mut(*handle);
        }
        // SAFETY: Creates a solid brush; it is kept in the cache for the process lifetime.
        let brush = unsafe { CreateSolidBrush(key) };
        if !brush.is_null() {
            brushes.insert(key, brush.expose_provenance());
        }
        brush
    })
}

fn paint_of(hwnd: HWND) -> Option<ControlPaint> {
    PAINTS.with(|paints| {
        paints
            .try_borrow()
            .ok()
            .and_then(|paints| paints.get(&hwnd.expose_provenance()).copied())
    })
}

/// `WM_CTLCOLORSTATIC` / `WM_CTLCOLORBTN` of a parent: the control's backdrop (white if the
/// control is not ours). Returns the brush to hand back to the system.
pub(crate) fn ctl_color(hdc: HDC, control: HWND) -> HBRUSH {
    let backdrop = paint_of(control).map_or(DEFAULT_BACKDROP, |paint| paint.backdrop);
    // SAFETY: `hdc` is the control's DC for this notification.
    unsafe { SetBkColor(hdc, backdrop.colorref()) };
    cached_brush(backdrop)
}

/// Fills `rect` with a rounded rectangle of `fill` outlined by `border` (GDI pen and brush are
/// created and deleted here; the DC's previous objects are restored).
pub(crate) fn round_rect(hdc: HDC, rect: &RECT, radius: i32, fill: Color, border: Color) {
    // SAFETY: Creates a 1 px solid pen; deleted below.
    let pen = unsafe { CreatePen(PS_SOLID, 1, border.colorref()) };
    // SAFETY: Creates a solid brush; deleted below.
    let brush = unsafe { CreateSolidBrush(fill.colorref()) };
    if pen.is_null() || brush.is_null() {
        if !pen.is_null() {
            // SAFETY: The pen was created above and is not selected.
            unsafe { DeleteObject(pen) };
        }
        if !brush.is_null() {
            // SAFETY: The brush was created above and is not selected.
            unsafe { DeleteObject(brush) };
        }
        return;
    }
    // SAFETY: Selects our pen into the live DC; the previous pen is restored below.
    let old_pen = unsafe { SelectObject(hdc, pen) };
    // SAFETY: Selects our brush into the live DC; the previous brush is restored below.
    let old_brush = unsafe { SelectObject(hdc, brush) };
    let diameter = radius.saturating_mul(2);
    // SAFETY: Draws on the live DC with plain coordinates.
    unsafe {
        RoundRect(
            hdc,
            rect.left,
            rect.top,
            rect.right,
            rect.bottom,
            diameter,
            diameter,
        )
    };
    if !old_pen.is_null() {
        // SAFETY: Restores the DC's previous pen.
        unsafe { SelectObject(hdc, old_pen) };
    }
    if !old_brush.is_null() {
        // SAFETY: Restores the DC's previous brush.
        unsafe { SelectObject(hdc, old_brush) };
    }
    // SAFETY: The pen is no longer selected.
    unsafe { DeleteObject(pen) };
    // SAFETY: The brush is no longer selected.
    unsafe { DeleteObject(brush) };
}

/// The owner-drawn button created under `parent` with command `id` (its hwnd), if any.
fn owner_drawn_button(parent: HWND, id: usize) -> Option<usize> {
    let parent = parent.expose_provenance();
    PAINTS.with(|paints| {
        paints.try_borrow().ok().and_then(|paints| {
            paints.iter().find_map(|(hwnd, paint)| {
                (paint.style.is_some() && paint.parent == parent && usize::from(paint.id) == id)
                    .then_some(*hwnd)
            })
        })
    })
}

/// `WM_DRAWITEM` of `parent` for one of our owner-drawn buttons. `false` when the item is not
/// ours (the caller then uses the default processing). `lParam` is dereferenced only when
/// `wParam` names one of our owner-drawn buttons of this parent, and the structure must then
/// describe exactly that button.
pub(crate) fn draw_item(parent: HWND, wparam: usize, lparam: isize) -> bool {
    let Some(button) = owner_drawn_button(parent, wparam) else {
        return false;
    };
    let item: *const DRAWITEMSTRUCT = core::ptr::with_exposed_provenance(lparam.cast_unsigned());
    if item.is_null() {
        return false;
    }
    // SAFETY: For WM_DRAWITEM (sent by our own button control on this thread), lParam points to
    // a DRAWITEMSTRUCT valid for this message.
    let item = unsafe { &*item };
    if item.CtlType != ODT_BUTTON
        || usize::try_from(item.CtlID).ok() != Some(wparam)
        || item.hwndItem.expose_provenance() != button
    {
        return false;
    }
    let Some(ControlPaint {
        style: Some(style),
        backdrop,
        ..
    }) = paint_of(item.hwndItem)
    else {
        return false;
    };
    let hdc = item.hDC;
    let rect = item.rcItem;
    let disabled = item.itemState & ODS_DISABLED != 0;
    let pressed = item.itemState & ODS_SELECTED != 0;
    let focused = item.itemState & ODS_FOCUS != 0 && item.itemState & ODS_NOFOCUSRECT == 0;
    let backdrop_brush = cached_brush(backdrop);
    if !backdrop_brush.is_null() {
        // SAFETY: `hdc` and `rect` come from the DRAWITEMSTRUCT; the brush is cached.
        unsafe { FillRect(hdc, &raw const rect, backdrop_brush) };
    }
    // SAFETY: Queries the DPI of our control window.
    let dpi = match unsafe { windows_sys::Win32::UI::HiDpi::GetDpiForWindow(item.hwndItem) } {
        0 => 96,
        value => value,
    };
    let radius = super::window::scale(style.radius, dpi);
    let (fill, text, border) = if disabled {
        (
            style.disabled_fill,
            style.disabled_text,
            style.disabled_border,
        )
    } else if pressed {
        (style.pressed, style.text, style.border)
    } else {
        (style.fill, style.text, style.border)
    };
    round_rect(hdc, &rect, radius, fill, border);
    if focused && !disabled {
        let inset = super::window::scale(3, dpi);
        let ring = RECT {
            left: rect.left.saturating_add(inset),
            top: rect.top.saturating_add(inset),
            right: rect.right.saturating_sub(inset),
            bottom: rect.bottom.saturating_sub(inset),
        };
        round_rect(
            hdc,
            &ring,
            radius.saturating_sub(inset).max(0),
            fill,
            style.focus,
        );
    }
    // SAFETY: Reads the font handle of our control (no pointers).
    let font = unsafe { SendMessageW(item.hwndItem, WM_GETFONT, 0, 0) };
    let font: HFONT = core::ptr::with_exposed_provenance_mut(font.cast_unsigned());
    let old_font = if font.is_null() {
        core::ptr::null_mut()
    } else {
        // SAFETY: Selects the control's live font; restored below.
        unsafe { SelectObject(hdc, font) }
    };
    // SAFETY: Plain DC state changes on the live DC.
    unsafe { SetBkMode(hdc, i32::try_from(TRANSPARENT).unwrap_or(1)) };
    // SAFETY: Plain DC state change on the live DC.
    unsafe { SetTextColor(hdc, text.colorref()) };
    // SAFETY: Queries the label length of our control.
    let len = unsafe { GetWindowTextLengthW(item.hwndItem) };
    let len = usize::try_from(len).unwrap_or(0).min(512);
    let mut buffer = vec![0_u16; len.saturating_add(1)];
    let capacity = i32::try_from(buffer.len()).unwrap_or(0);
    // SAFETY: `buffer` is writable for `capacity` units including the terminator.
    let copied = unsafe { GetWindowTextW(item.hwndItem, buffer.as_mut_ptr(), capacity) };
    let mut text_rect = rect;
    if let Ok(count) = i32::try_from(usize::try_from(copied).unwrap_or(0).min(len))
        && count > 0
    {
        // SAFETY: `buffer` holds `count` units; DT_MODIFYSTRING is not set.
        unsafe {
            DrawTextW(
                hdc,
                buffer.as_ptr(),
                count,
                &raw mut text_rect,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
            )
        };
    }
    if !old_font.is_null() {
        // SAFETY: Restores the DC's previous font.
        unsafe { SelectObject(hdc, old_font) };
    }
    true
}

/// Kind of a child control.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlKind {
    /// An owner-drawn push button (`BS_OWNERDRAW`) in this style.
    Button(ButtonStyle),
    /// `BS_AUTOCHECKBOX`.
    CheckBox,
    /// `BS_AUTORADIOBUTTON`; the first button of a group sets `WS_GROUP`.
    Radio {
        /// Starts a new radio group.
        first_in_group: bool,
    },
    /// Single-line `EDIT`.
    Edit {
        /// `ES_PASSWORD` (masked; the edit refuses copy).
        password: bool,
        /// `ES_READONLY`.
        readonly: bool,
    },
    /// `STATIC` text with `SS_NOPREFIX`.
    Label,
}

/// A child control. Dropping it destroys the control while its parent is alive.
pub struct Control {
    hwnd: usize,
    id: u16,
    parent_alive: Rc<dyn Fn() -> bool>,
}

impl fmt::Debug for Control {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Control")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

fn styles(kind: ControlKind) -> (&'static str, u32, u32) {
    let base = WS_CHILD | WS_VISIBLE;
    let bits = |value: i32| u32::try_from(value).unwrap_or(0);
    match kind {
        ControlKind::Button(_) => ("BUTTON", base | WS_TABSTOP | bits(BS_OWNERDRAW), 0),
        ControlKind::CheckBox => (
            "BUTTON",
            base | WS_TABSTOP | bits(BS_AUTOCHECKBOX | BS_MULTILINE),
            0,
        ),
        ControlKind::Radio { first_in_group } => (
            "BUTTON",
            base | bits(BS_AUTORADIOBUTTON | BS_MULTILINE)
                | if first_in_group {
                    WS_GROUP | WS_TABSTOP
                } else {
                    0
                },
            0,
        ),
        ControlKind::Edit { password, readonly } => (
            "EDIT",
            base | WS_TABSTOP
                | bits(ES_AUTOHSCROLL)
                | if password { bits(ES_PASSWORD) } else { 0 }
                | if readonly { bits(ES_READONLY) } else { 0 },
            WS_EX_CLIENTEDGE,
        ),
        ControlKind::Label => ("STATIC", base | SS_NOPREFIX, 0),
    }
}

/// Creates a child control of `parent` with command `id`.
///
/// # Errors
///
/// [`WinError`] from `CreateWindowExW`.
pub fn create_control(
    parent: &Window,
    kind: ControlKind,
    id: u16,
    text: &str,
    rect: Rect,
) -> Result<Control, WinError> {
    let (class, style, ex_style) = styles(kind);
    let class = to_wide(class, "CreateWindowExW")?;
    let text = to_wide(text, "CreateWindowExW")?;
    let parent_id = parent.live_raw_id();
    if parent_id == 0 {
        return Err(WinError::new(
            "CreateWindowExW",
            ERROR_INVALID_WINDOW_HANDLE,
        ));
    }
    let parent_hwnd: HWND = core::ptr::with_exposed_provenance_mut(parent_id);
    let menu: HMENU = core::ptr::with_exposed_provenance_mut(usize::from(id));
    // SAFETY: Class and text are NUL-terminated and live; the parent is our live window; the
    // child id is passed in the menu slot as documented for WS_CHILD windows.
    let hwnd = unsafe {
        CreateWindowExW(
            ex_style,
            class.as_ptr(),
            text.as_ptr(),
            style,
            rect.x,
            rect.y,
            rect.w,
            rect.h,
            parent_hwnd,
            menu,
            core::ptr::null_mut(),
            core::ptr::null(),
        )
    };
    if hwnd.is_null() {
        return Err(WinError::last("CreateWindowExW"));
    }
    let style = match kind {
        ControlKind::Button(style) => Some(style),
        _ => None,
    };
    PAINTS.with(|paints| {
        if let Ok(mut paints) = paints.try_borrow_mut() {
            paints.insert(
                hwnd.expose_provenance(),
                ControlPaint {
                    style,
                    backdrop: DEFAULT_BACKDROP,
                    parent: parent_hwnd.expose_provenance(),
                    id,
                },
            );
        }
    });
    let alive = parent.alive_probe();
    Ok(Control {
        hwnd: hwnd.expose_provenance(),
        id,
        parent_alive: alive,
    })
}

impl Control {
    /// The control's handle while its parent window exists. A control is destroyed only with its
    /// parent or by its own `Drop`, so after the parent is gone the handle value may belong to an
    /// unrelated window: every method below then does nothing (or returns a neutral value).
    fn live(&self) -> Option<HWND> {
        (self.parent_alive)().then(|| core::ptr::with_exposed_provenance_mut(self.hwnd))
    }

    /// The command id.
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// Sets non-secret text.
    pub fn set_text(&self, text: &str) {
        let Some(hwnd) = self.live() else { return };
        if let Ok(wide) = to_wide(text, "SetWindowTextW") {
            // SAFETY: `wide` is NUL-terminated and live; the control is ours and alive.
            unsafe { SetWindowTextW(hwnd, wide.as_ptr()) };
        }
    }

    fn read_units(&self, max_units: usize) -> WipeBuf<u16> {
        let Some(hwnd) = self.live() else {
            return WipeBuf::with_capacity(0);
        };
        // SAFETY: Queries the text length of our live control.
        let len = unsafe { GetWindowTextLengthW(hwnd) };
        let len = usize::try_from(len).unwrap_or(0).min(max_units);
        let mut buffer = vec![0_u16; len.saturating_add(1)];
        let capacity = i32::try_from(buffer.len()).unwrap_or(0);
        // SAFETY: `buffer` is writable for `capacity` units including the terminator.
        let copied = unsafe { GetWindowTextW(hwnd, buffer.as_mut_ptr(), capacity) };
        let copied = usize::try_from(copied).unwrap_or(0).min(len);
        let mut out = WipeBuf::with_capacity(copied);
        let _ = out.extend_from_slice(buffer.get(..copied).unwrap_or(&[]));
        wipe_u16(&mut buffer);
        out
    }

    /// Non-secret text (at most `max_units` UTF-16 units; invalid UTF-16 becomes U+FFFD).
    #[must_use]
    pub fn text(&self, max_units: usize) -> String {
        String::from_utf16_lossy(self.read_units(max_units).as_slice())
    }

    /// Text that should not linger (RPC tokens): returned in a wiping buffer.
    #[must_use]
    pub fn text_wiping(&self, max_units: usize) -> WipeBuf<u16> {
        self.read_units(max_units)
    }

    /// Limits an edit to `units` characters.
    pub fn set_limit(&self, units: u32) {
        let Some(hwnd) = self.live() else { return };
        // SAFETY: Sends EM_SETLIMITTEXT with a plain value to our live control.
        unsafe {
            SendMessageW(
                hwnd,
                EM_SETLIMITTEXT,
                usize::try_from(units).unwrap_or(0),
                0,
            )
        };
    }

    /// Checks or unchecks a check box / radio button.
    pub fn set_checked(&self, checked: bool) {
        let Some(hwnd) = self.live() else { return };
        let state = if checked { BST_CHECKED } else { BST_UNCHECKED };
        // SAFETY: Sends BM_SETCHECK with a plain value to our live control.
        unsafe { SendMessageW(hwnd, BM_SETCHECK, usize::try_from(state).unwrap_or(0), 0) };
    }

    /// Whether a check box / radio button is checked.
    #[must_use]
    pub fn is_checked(&self) -> bool {
        let Some(hwnd) = self.live() else {
            return false;
        };
        // SAFETY: Sends BM_GETCHECK to our live control.
        let state = unsafe { SendMessageW(hwnd, BM_GETCHECK, 0, 0) };
        state == isize::try_from(BST_CHECKED).unwrap_or(1)
    }

    /// Enables or disables the control.
    pub fn enable(&self, enabled: bool) {
        let Some(hwnd) = self.live() else { return };
        // SAFETY: Changes the enabled state of our live control.
        unsafe { EnableWindow(hwnd, i32::from(enabled)) };
    }

    /// Whether the control is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        let Some(hwnd) = self.live() else {
            return false;
        };
        // SAFETY: Queries our live control.
        unsafe { IsWindowEnabled(hwnd) != 0 }
    }

    /// Shows or hides the control.
    pub fn show(&self, visible: bool) {
        let Some(hwnd) = self.live() else { return };
        // SAFETY: Shows or hides our live control.
        unsafe { ShowWindow(hwnd, if visible { SW_SHOW } else { SW_HIDE }) };
    }

    /// Moves and resizes the control.
    pub fn set_rect(&self, rect: Rect) {
        let Some(hwnd) = self.live() else { return };
        // SAFETY: Moves our live control within its parent.
        unsafe { MoveWindow(hwnd, rect.x, rect.y, rect.w, rect.h, 1) };
    }

    /// Sets the control font (`font` must outlive the control or be replaced first).
    pub fn set_font(&self, font: &Font) {
        let Some(hwnd) = self.live() else { return };
        let handle = font.raw().expose_provenance();
        // SAFETY: Sends WM_SETFONT with our font handle and redraw = TRUE to our live control.
        unsafe { SendMessageW(hwnd, WM_SETFONT, handle, 1) };
    }

    /// Gives the control keyboard focus.
    pub fn focus(&self) {
        let Some(hwnd) = self.live() else { return };
        // SAFETY: Sets focus to our live control.
        unsafe { SetFocus(hwnd) };
    }

    /// Sets the color under the control (card or window background) used to paint the corners of
    /// an owner-drawn button and the background of check boxes, radios and read-only edits.
    pub fn set_backdrop(&self, color: Color) {
        let Some(hwnd) = self.live() else { return };
        let changed = PAINTS.with(|paints| {
            let Ok(mut paints) = paints.try_borrow_mut() else {
                return false;
            };
            match paints.get_mut(&self.hwnd) {
                Some(paint) if paint.backdrop != color => {
                    paint.backdrop = color;
                    true
                }
                _ => false,
            }
        });
        if changed {
            // SAFETY: Invalidates our live control so it repaints with the new backdrop.
            unsafe { InvalidateRect(hwnd, core::ptr::null(), 1) };
        }
    }

    /// Replaces an owner-drawn button's style (same control, new colors).
    pub fn set_button_style(&self, style: ButtonStyle) {
        let Some(hwnd) = self.live() else { return };
        let changed = PAINTS.with(|paints| {
            let Ok(mut paints) = paints.try_borrow_mut() else {
                return false;
            };
            match paints.get_mut(&self.hwnd) {
                Some(paint) if paint.style.is_some() && paint.style != Some(style) => {
                    paint.style = Some(style);
                    true
                }
                _ => false,
            }
        });
        if changed {
            // SAFETY: Invalidates our live control so it repaints in the new style.
            unsafe { InvalidateRect(hwnd, core::ptr::null(), 1) };
        }
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        PAINTS.with(|paints| {
            if let Ok(mut paints) = paints.try_borrow_mut() {
                paints.remove(&self.hwnd);
            }
        });
        if let Some(hwnd) = self.live() {
            // SAFETY: The parent is alive, so this child handle is still ours.
            unsafe { DestroyWindow(hwnd) };
        }
    }
}
