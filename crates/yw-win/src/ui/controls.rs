#![allow(unsafe_code)]
//! Standard child controls for non-secret values (spec/01 §7.7): push buttons, check boxes, radio
//! buttons, single-line edits (optionally `ES_PASSWORD` for RPC tokens) and static labels.
//! Notifications arrive as [`super::Msg::Command`]. Wallet secrets never go into these controls.
//!
//! Push buttons are owner-drawn (`BS_OWNERDRAW`) from a [`ButtonStyle`] the app passes in (the
//! app's design tokens, spec/04 §1.6); the parent's wndproc paints them on `WM_DRAWITEM` and
//! colors check boxes, radios and read-only edits with the control's backdrop (the card or window
//! color under it) on `WM_CTLCOLORSTATIC`/`WM_CTLCOLORBTN`. A button may draw a [`ButtonFace`]
//! instead of its window text (2026-11-11: icon buttons and copyable address/hash lines; the
//! window text stays the accessible name) and show a tooltip ([`Control::set_tooltip`]). The
//! button under the pointer is drawn in a hover fill and the pointer over it is the hand
//! (2026-11-12, the parent's `WM_SETCURSOR`).

use core::cell::{Cell, RefCell};
use core::fmt;
use std::collections::HashMap;
use std::rc::Rc;

use windows_sys::Win32::Foundation::{ERROR_INVALID_WINDOW_HANDLE, HWND, POINT, RECT, SIZE};
use windows_sys::Win32::Graphics::Gdi::{
    CreatePen, CreateSolidBrush, DT_CENTER, DT_NOPREFIX, DT_SINGLELINE, DT_VCENTER, DeleteObject,
    DrawTextW, FillRect, GetTextExtentPoint32W, GetTextMetricsW, HBRUSH, HDC, HFONT,
    InvalidateRect, PS_SOLID, RoundRect, SelectObject, SetBkColor, SetBkMode, SetTextColor,
    TEXTMETRICW, TRANSPARENT, TextOutW,
};
use windows_sys::Win32::UI::Controls::{
    BST_CHECKED, BST_UNCHECKED, DRAWITEMSTRUCT, EM_SETLIMITTEXT, EM_SETSEL, ODS_DISABLED,
    ODS_FOCUS, ODS_NOFOCUSRECT, ODS_SELECTED, ODT_BUTTON, TOOLTIPS_CLASSW, TTF_IDISHWND,
    TTF_SUBCLASS, TTM_ADDTOOLW, TTM_DELTOOLW, TTM_SETMAXTIPWIDTH, TTM_UPDATETIPTEXTW,
    TTS_ALWAYSTIP, TTS_NOPREFIX, TTTOOLINFOW,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    EnableWindow, GetFocus, IsWindowEnabled, SetFocus,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BM_GETCHECK, BM_SETCHECK, BS_AUTOCHECKBOX, BS_AUTORADIOBUTTON, BS_MULTILINE, BS_OWNERDRAW,
    CW_USEDEFAULT, CreateWindowExW, DestroyWindow, ES_AUTOHSCROLL, ES_PASSWORD, ES_READONLY,
    GW_OWNER, GWL_STYLE, GetCursorPos, GetParent, GetWindow, GetWindowLongW, GetWindowTextLengthW,
    GetWindowTextW, HMENU, HTCLIENT, IDC_HAND, IsWindow, KillTimer, LoadCursorW, MoveWindow,
    SW_HIDE, SW_SHOW, SendMessageW, SetCursor, SetTimer, SetWindowTextW, ShowWindow, WM_GETFONT,
    WM_SETFONT, WS_CHILD, WS_EX_CLIENTEDGE, WS_EX_TOPMOST, WS_GROUP, WS_POPUP, WS_TABSTOP,
    WS_VISIBLE, WindowFromPoint,
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

/// A small picture drawn before an owner-drawn button's label (the app's chain badges): `size`
/// × `size` premultiplied `0xAARRGGBB` pixels, rows top-down, already at the control's DPI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ButtonIcon {
    /// Width and height in pixels.
    pub size: i32,
    /// Pixels.
    pub pixels: Vec<u32>,
}

/// One piece of a [`ButtonFace`] line: text in one font and color.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaceRun {
    text: Vec<u16>,
    /// The `HFONT` of a live [`Font`] (the caller keeps the font alive while the face is set,
    /// as for `WM_SETFONT`).
    font: usize,
    color: Color,
}

impl FaceRun {
    /// `text` drawn in `font` and `color`.
    #[must_use]
    pub fn new(text: &str, font: &Font, color: Color) -> Self {
        Self {
            text: text.encode_utf16().collect(),
            font: font.raw().expose_provenance(),
            color,
        }
    }
}

/// What an owner-drawn button draws instead of its window text (which stays its accessible
/// name): lines of runs on a common baseline each, the block vertically centered; each line
/// starts `left` pixels from the button's left edge, or is centered when `left` is `None`. A
/// disabled button draws every run in its style's disabled text color.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ButtonFace {
    /// Lines of runs.
    pub lines: Vec<Vec<FaceRun>>,
    /// Left padding in pixels (`None` = centered).
    pub left: Option<i32>,
    /// A run at the right end (the same padding from the right edge), vertically centered.
    pub trailing: Option<FaceRun>,
}

thread_local! {
    /// Child control hwnd → paint state (UI thread only; removed when the control is dropped).
    static PAINTS: RefCell<HashMap<usize, ControlPaint>> = RefCell::new(HashMap::new());
    /// Owner-drawn button hwnd → its icon (UI thread only; removed when the control is dropped).
    static ICONS: RefCell<HashMap<usize, ButtonIcon>> = RefCell::new(HashMap::new());
    /// The owner-drawn button under the pointer and its parent (`(0, 0)` = none): drawn in its
    /// hover fill ([`set_cursor`], [`hover_tick`]).
    static HOT: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    /// Owner-drawn button hwnd → its face (UI thread only; removed when the control is dropped).
    static FACES: RefCell<HashMap<usize, ButtonFace>> = RefCell::new(HashMap::new());
    /// Parent hwnd → its tooltip window (created on the first [`Control::set_tooltip`]; owned by
    /// the parent, so destroyed with it).
    static TIPS: RefCell<HashMap<usize, usize>> = RefCell::new(HashMap::new());
    /// Control hwnd → the parent whose tooltip lists it (removed with the control).
    static TIPPED: RefCell<HashMap<usize, usize>> = RefCell::new(HashMap::new());
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

/// Timer of a parent window while one of its buttons is hot: the pointer can leave the window
/// without another `WM_SETCURSOR`, so [`hover_tick`] looks where it is. Far from the app's ids.
pub(crate) const HOVER_TIMER_ID: usize = 0x5957_0001;
/// Period of [`HOVER_TIMER_ID`].
const HOVER_TICK_MS: u32 = 60;

/// The fill of a button under the pointer: two thirds of the way from its fill to its pressed
/// fill.
fn hover_fill(style: ButtonStyle) -> Color {
    let channel = |shift: u32| {
        let from = (style.fill.0 >> shift) & 0xFF;
        let to = (style.pressed.0 >> shift) & 0xFF;
        (from.saturating_add(to.saturating_mul(2)) / 3) << shift
    };
    Color(channel(16) | channel(8) | channel(0))
}

/// Makes button `hot` of `parent` the one under the pointer (`(0, 0)` = none): repaints the old
/// and the new one, and runs [`HOVER_TIMER_ID`] on the parent while there is one.
fn set_hot(hot: usize, parent: usize) {
    let (old, old_parent) = HOT.with(|cell| cell.replace((hot, parent)));
    if old == hot {
        return;
    }
    for button in [old, hot] {
        if button != 0 {
            let button: HWND = core::ptr::with_exposed_provenance_mut(button);
            // SAFETY: Invalidates one non-null window (ours; a handle that died meanwhile only
            // fails the call); no rectangle pointer.
            unsafe { InvalidateRect(button, core::ptr::null(), 0) };
        }
    }
    if old_parent != 0 && old_parent != parent {
        let old_parent: HWND = core::ptr::with_exposed_provenance_mut(old_parent);
        // SAFETY: Stops a timer of our window (fails harmlessly when it is gone).
        unsafe { KillTimer(old_parent, HOVER_TIMER_ID) };
    }
    if parent != 0 && old_parent != parent {
        let parent: HWND = core::ptr::with_exposed_provenance_mut(parent);
        // SAFETY: Starts a timer of our live window; no callback (it arrives as `WM_TIMER`).
        unsafe { SetTimer(parent, HOVER_TIMER_ID, HOVER_TICK_MS, None) };
    }
}

/// `WM_SETCURSOR` of `parent` (`wParam` = the window under the pointer, low word of `lParam` =
/// the hit test): over the client area of one of its enabled owner-drawn buttons the pointer is
/// the hand and the button becomes hot. `false` anywhere else (default processing).
pub(crate) fn set_cursor(parent: HWND, wparam: usize, lparam: isize) -> bool {
    let parent = parent.expose_provenance();
    let client = usize::try_from(HTCLIENT).ok() == Some(lparam.cast_unsigned() & 0xFFFF);
    let target: HWND = core::ptr::with_exposed_provenance_mut(wparam);
    let ours = client
        && paint_of(target).is_some_and(|paint| paint.style.is_some() && paint.parent == parent);
    if !ours {
        if HOT.get().1 == parent {
            set_hot(0, 0);
        }
        return false;
    }
    set_hot(wparam, parent);
    // SAFETY: Loads the shared system hand cursor (a null module and a predefined id).
    let hand = unsafe { LoadCursorW(core::ptr::null_mut(), IDC_HAND) };
    if hand.is_null() {
        return false;
    }
    // SAFETY: Sets the pointer to the shared system cursor loaded above.
    unsafe { SetCursor(hand) };
    true
}

/// [`HOVER_TIMER_ID`] of `parent`: the hot button stops being hot once the pointer is no longer
/// over it; the timer stops when no button of `parent` is hot.
pub(crate) fn hover_tick(parent: HWND) {
    let (hot, hot_parent) = HOT.get();
    if hot == 0 || hot_parent != parent.expose_provenance() {
        // SAFETY: Stops a timer of our live window.
        unsafe { KillTimer(parent, HOVER_TIMER_ID) };
        return;
    }
    let mut point = POINT { x: 0, y: 0 };
    // SAFETY: `point` is writable for the call.
    let known = unsafe { GetCursorPos(&raw mut point) } != 0;
    // SAFETY: A plain-value query of the window at a screen point.
    let under = unsafe { WindowFromPoint(point) };
    if !known || under.expose_provenance() != hot {
        set_hot(0, 0);
    }
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
    } else if HOT.get().0 == item.hwndItem.expose_provenance() {
        (hover_fill(style), style.text, style.border)
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
    let face = FACES.with(|faces| {
        faces
            .try_borrow()
            .ok()
            .and_then(|faces| faces.get(&item.hwndItem.expose_provenance()).cloned())
    });
    match face {
        Some(face) => {
            let icon = icon_of(item.hwndItem);
            let disabled = disabled.then_some(text);
            draw_face(hdc, rect, &face, icon.as_ref(), dpi, disabled);
        }
        None => draw_window_label(hdc, rect, item.hwndItem, dpi),
    }
    if !old_font.is_null() {
        // SAFETY: Restores the DC's previous font.
        unsafe { SelectObject(hdc, old_font) };
    }
    true
}

/// The icon of button `hwnd`.
fn icon_of(hwnd: HWND) -> Option<ButtonIcon> {
    ICONS.with(|icons| {
        icons
            .try_borrow()
            .ok()
            .and_then(|icons| icons.get(&hwnd.expose_provenance()).cloned())
    })
}

/// Draws button `hwnd`'s window text (and its icon) centered in `rect`.
fn draw_window_label(hdc: HDC, rect: RECT, hwnd: HWND, dpi: u32) {
    // SAFETY: Queries the label length of our control.
    let len = unsafe { GetWindowTextLengthW(hwnd) };
    let len = usize::try_from(len).unwrap_or(0).min(512);
    let mut buffer = vec![0_u16; len.saturating_add(1)];
    let capacity = i32::try_from(buffer.len()).unwrap_or(0);
    // SAFETY: `buffer` is writable for `capacity` units including the terminator.
    let copied = unsafe { GetWindowTextW(hwnd, buffer.as_mut_ptr(), capacity) };
    let count = usize::try_from(copied).unwrap_or(0).min(len);
    let icon = icon_of(hwnd);
    draw_label(
        hdc,
        rect,
        buffer.get(..count).unwrap_or(&[]),
        icon.as_ref(),
        dpi,
    );
}

/// Draws a button label centered in `rect` (font and color already selected), with the icon
/// before it when given (icon, gap, label centered together).
fn draw_label(hdc: HDC, rect: RECT, label: &[u16], icon: Option<&ButtonIcon>, dpi: u32) {
    let count = i32::try_from(label.len()).unwrap_or(0);
    let mut text_rect = rect;
    let mut flags = DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX;
    if let Some(icon) = icon {
        let gap = super::window::scale(6, dpi);
        let mut extent = SIZE { cx: 0, cy: 0 };
        if count > 0 {
            // SAFETY: `label` holds `count` units; `extent` is writable.
            unsafe { GetTextExtentPoint32W(hdc, label.as_ptr(), count, &raw mut extent) };
        }
        let label_w = if count > 0 {
            extent.cx.saturating_add(gap)
        } else {
            0
        };
        let width = rect.right.saturating_sub(rect.left);
        let height = rect.bottom.saturating_sub(rect.top);
        let total = icon.size.saturating_add(label_w);
        let left = rect
            .left
            .saturating_add((width.saturating_sub(total) / 2).max(0));
        let top = rect
            .top
            .saturating_add((height.saturating_sub(icon.size) / 2).max(0));
        let _ = super::paint::alpha_blit(hdc, left, top, icon.size, icon.size, &icon.pixels);
        text_rect.left = left.saturating_add(icon.size).saturating_add(gap);
        flags = DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX;
    }
    if count > 0 {
        // SAFETY: `label` holds `count` units; DT_MODIFYSTRING is not set.
        unsafe { DrawTextW(hdc, label.as_ptr(), count, &raw mut text_rect, flags) };
    }
}

/// Selects `run`'s font into `hdc` (GDI refuses a stale handle and keeps the current font) and
/// returns its `(width, height, ascent)` in pixels.
fn run_metrics(hdc: HDC, run: &FaceRun) -> (i32, i32, i32) {
    let font: HFONT = core::ptr::with_exposed_provenance_mut(run.font);
    // SAFETY: Selects a font handle into the live DC; the caller restores the DC's font.
    unsafe { SelectObject(hdc, font) };
    let mut metrics = TEXTMETRICW::default();
    // SAFETY: `metrics` is writable for the call.
    unsafe { GetTextMetricsW(hdc, &raw mut metrics) };
    let mut extent = SIZE { cx: 0, cy: 0 };
    let count = i32::try_from(run.text.len()).unwrap_or(0);
    if count > 0 {
        // SAFETY: `run.text` holds `count` units; `extent` is writable.
        unsafe { GetTextExtentPoint32W(hdc, run.text.as_ptr(), count, &raw mut extent) };
    }
    (extent.cx, metrics.tmHeight, metrics.tmAscent)
}

/// One measured line of a face: its runs with `(width, ascent)`, then the line's width, height
/// and ascent.
type MeasuredLine<'a> = (Vec<(&'a FaceRun, i32, i32)>, i32, i32, i32);

/// Draws `face` in `rect` (the caller restores the DC's font); `disabled` replaces every run's
/// color. A left-aligned face starts after `icon` (a drop-down entry's chain badge); a centered
/// one has none.
fn draw_face(
    hdc: HDC,
    rect: RECT,
    face: &ButtonFace,
    icon: Option<&ButtonIcon>,
    dpi: u32,
    disabled: Option<Color>,
) {
    let measured: Vec<MeasuredLine<'_>> = face
        .lines
        .iter()
        .map(|line| {
            let mut runs = Vec::with_capacity(line.len());
            let (mut width, mut ascent, mut descent) = (0_i32, 0_i32, 0_i32);
            for run in line {
                let (w, h, run_ascent) = run_metrics(hdc, run);
                width = width.saturating_add(w);
                ascent = ascent.max(run_ascent);
                descent = descent.max(h.saturating_sub(run_ascent));
                runs.push((run, w, run_ascent));
            }
            (runs, width, ascent.saturating_add(descent), ascent)
        })
        .collect();
    let total = measured
        .iter()
        .fold(0_i32, |sum, line| sum.saturating_add(line.2));
    let width = rect.right.saturating_sub(rect.left);
    let height = rect.bottom.saturating_sub(rect.top);
    let mut y = rect
        .top
        .saturating_add((height.saturating_sub(total) / 2).max(0));
    let mut indent = 0_i32;
    if let (Some(pad), Some(icon)) = (face.left, icon) {
        let top = rect
            .top
            .saturating_add((height.saturating_sub(icon.size) / 2).max(0));
        let left = rect.left.saturating_add(pad);
        let _ = super::paint::alpha_blit(hdc, left, top, icon.size, icon.size, &icon.pixels);
        indent = icon.size.saturating_add(super::window::scale(6, dpi));
    }
    for (runs, line_w, line_h, ascent) in measured {
        let mut x = face.left.map_or_else(
            || {
                rect.left
                    .saturating_add((width.saturating_sub(line_w) / 2).max(0))
            },
            |pad| rect.left.saturating_add(pad).saturating_add(indent),
        );
        let baseline = y.saturating_add(ascent);
        for (run, run_w, run_ascent) in runs {
            let font: HFONT = core::ptr::with_exposed_provenance_mut(run.font);
            // SAFETY: Selects a font handle into the live DC; the caller restores the DC's font.
            unsafe { SelectObject(hdc, font) };
            // SAFETY: Plain DC state change on the live DC.
            unsafe { SetTextColor(hdc, disabled.unwrap_or(run.color).colorref()) };
            let count = i32::try_from(run.text.len()).unwrap_or(0);
            if count > 0 {
                // SAFETY: `run.text` holds `count` units.
                unsafe {
                    TextOutW(
                        hdc,
                        x,
                        baseline.saturating_sub(run_ascent),
                        run.text.as_ptr(),
                        count,
                    )
                };
            }
            x = x.saturating_add(run_w);
        }
        y = y.saturating_add(line_h);
    }
    if let Some(run) = &face.trailing {
        let (run_w, run_h, _) = run_metrics(hdc, run);
        let x = rect
            .right
            .saturating_sub(face.left.unwrap_or(0))
            .saturating_sub(run_w);
        let top = rect
            .top
            .saturating_add((height.saturating_sub(run_h) / 2).max(0));
        // SAFETY: Plain DC state change on the live DC (the run's font is selected above).
        unsafe { SetTextColor(hdc, disabled.unwrap_or(run.color).colorref()) };
        let count = i32::try_from(run.text.len()).unwrap_or(0);
        if count > 0 {
            // SAFETY: `run.text` holds `count` units.
            unsafe { TextOutW(hdc, x, top, run.text.as_ptr(), count) };
        }
    }
}

/// The tooltip window of `parent`: the one created before while it is still a live window owned
/// by `parent`, else a new one.
fn tooltip_of(parent: HWND) -> Option<HWND> {
    let key = parent.expose_provenance();
    let known = TIPS.with(|tips| {
        tips.try_borrow()
            .ok()
            .and_then(|tips| tips.get(&key).copied())
    });
    if let Some(known) = known {
        let tip: HWND = core::ptr::with_exposed_provenance_mut(known);
        if tooltip_alive(tip, parent) {
            return Some(tip);
        }
    }
    // SAFETY: Creates a tooltip window owned by our live parent (the class name is a static
    // NUL-terminated string; no window name, menu or creation data).
    let tip = unsafe {
        CreateWindowExW(
            WS_EX_TOPMOST,
            TOOLTIPS_CLASSW,
            core::ptr::null(),
            WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            parent,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null(),
        )
    };
    if tip.is_null() {
        return None;
    }
    // SAFETY: A plain-value message to our tooltip: long tips wrap at 400 px.
    unsafe { SendMessageW(tip, TTM_SETMAXTIPWIDTH, 0, 400) };
    TIPS.with(|tips| {
        if let Ok(mut tips) = tips.try_borrow_mut() {
            tips.insert(key, tip.expose_provenance());
        }
    });
    Some(tip)
}

/// Whether `tip` is still a window owned by `parent` (a handle value can be reused after its
/// window is destroyed).
fn tooltip_alive(tip: HWND, parent: HWND) -> bool {
    // SAFETY: A plain query; a stale handle makes it return 0.
    let window = unsafe { IsWindow(tip) } != 0;
    // SAFETY: A plain query; a stale handle makes it return null.
    window && unsafe { GetWindow(tip, GW_OWNER) } == parent
}

/// The tool entry of control `hwnd` under `parent` (`text` is null for a removal).
fn tool_info(parent: HWND, hwnd: HWND, text: *mut u16) -> TTTOOLINFOW {
    TTTOOLINFOW {
        cbSize: u32::try_from(core::mem::size_of::<TTTOOLINFOW>()).unwrap_or(0),
        uFlags: TTF_IDISHWND | TTF_SUBCLASS,
        hwnd: parent,
        uId: hwnd.expose_provenance(),
        lpszText: text,
        ..TTTOOLINFOW::default()
    }
}

/// Removes control `hwnd`'s entry from its parent's tooltip while that tooltip still exists.
fn remove_tool(hwnd: usize) {
    let parent = TIPPED.with(|tipped| {
        tipped
            .try_borrow_mut()
            .ok()
            .and_then(|mut tipped| tipped.remove(&hwnd))
    });
    let Some(parent) = parent else {
        return;
    };
    let tip = TIPS.with(|tips| {
        tips.try_borrow()
            .ok()
            .and_then(|tips| tips.get(&parent).copied())
    });
    let Some(tip) = tip else {
        return;
    };
    let tip: HWND = core::ptr::with_exposed_provenance_mut(tip);
    let parent: HWND = core::ptr::with_exposed_provenance_mut(parent);
    if !tooltip_alive(tip, parent) {
        return;
    }
    let info = tool_info(
        parent,
        core::ptr::with_exposed_provenance_mut(hwnd),
        core::ptr::null_mut(),
    );
    // SAFETY: `info` lives for the call; the tooltip reads only its `hwnd` and `uId`.
    unsafe {
        SendMessageW(
            tip,
            TTM_DELTOOLW,
            0,
            (&raw const info).expose_provenance().cast_signed(),
        )
    };
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

    /// Whether the control has `WS_VISIBLE` (shown by [`Control::show`], whatever its parent).
    #[must_use]
    pub fn is_shown(&self) -> bool {
        let Some(hwnd) = self.live() else {
            return false;
        };
        // SAFETY: Reads the style of our live control.
        let style = unsafe { GetWindowLongW(hwnd, GWL_STYLE) };
        style.cast_unsigned() & WS_VISIBLE != 0
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
        // SAFETY: WM_GETFONT has no parameters and returns the control's current font handle.
        let current = unsafe { SendMessageW(hwnd, WM_GETFONT, 0, 0) };
        if current.cast_unsigned() == handle {
            // Unchanged: a WM_SETFONT with redraw would repaint (and flash) the control.
            return;
        }
        // SAFETY: Sends WM_SETFONT with our font handle and redraw = TRUE to our live control.
        unsafe { SendMessageW(hwnd, WM_SETFONT, handle, 1) };
    }

    /// Gives the control keyboard focus.
    pub fn focus(&self) {
        let Some(hwnd) = self.live() else { return };
        // SAFETY: Sets focus to our live control.
        unsafe { SetFocus(hwnd) };
    }

    /// Whether the control has the keyboard focus.
    #[must_use]
    pub fn has_focus(&self) -> bool {
        let Some(hwnd) = self.live() else {
            return false;
        };
        // SAFETY: Reads the thread's focus window.
        let focus = unsafe { GetFocus() };
        focus == hwnd
    }

    /// Selects an edit's whole text, as the dialog manager does when Tab reaches an edit.
    pub fn select_all(&self) {
        let Some(hwnd) = self.live() else { return };
        // SAFETY: Sends EM_SETSEL with plain values (0 to -1 = all text) to our live control.
        unsafe { SendMessageW(hwnd, EM_SETSEL, 0, -1) };
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

    /// Sets or clears the icon drawn before an owner-drawn button's label.
    pub fn set_icon(&self, icon: Option<ButtonIcon>) {
        let Some(hwnd) = self.live() else { return };
        let changed = ICONS.with(|icons| {
            let Ok(mut icons) = icons.try_borrow_mut() else {
                return false;
            };
            match icon {
                Some(icon) if icons.get(&self.hwnd) != Some(&icon) => {
                    icons.insert(self.hwnd, icon);
                    true
                }
                None => icons.remove(&self.hwnd).is_some(),
                Some(_) => false,
            }
        });
        if changed {
            // SAFETY: Invalidates our live control so it repaints with the new icon.
            unsafe { InvalidateRect(hwnd, core::ptr::null(), 1) };
        }
    }

    /// Sets or clears the face an owner-drawn button draws instead of its window text.
    pub fn set_face(&self, face: Option<ButtonFace>) {
        let Some(hwnd) = self.live() else { return };
        let changed = FACES.with(|faces| {
            let Ok(mut faces) = faces.try_borrow_mut() else {
                return false;
            };
            match face {
                Some(face) if faces.get(&self.hwnd) != Some(&face) => {
                    faces.insert(self.hwnd, face);
                    true
                }
                None => faces.remove(&self.hwnd).is_some(),
                Some(_) => false,
            }
        });
        if changed {
            // SAFETY: Invalidates our live control so it repaints with the new face.
            unsafe { InvalidateRect(hwnd, core::ptr::null(), 1) };
        }
    }

    /// Shows `text` (non-secret) as the control's tooltip while the pointer rests on it; `None`
    /// removes it. The parent's tooltip window keeps its own copy of the text.
    pub fn set_tooltip(&self, text: Option<&str>) {
        let Some(hwnd) = self.live() else { return };
        let registered = TIPPED.with(|tipped| {
            tipped
                .try_borrow()
                .is_ok_and(|tipped| tipped.contains_key(&self.hwnd))
        });
        let Some(text) = text else {
            if registered {
                remove_tool(self.hwnd);
            }
            return;
        };
        // SAFETY: Reads the parent of our live child control.
        let parent = unsafe { GetParent(hwnd) };
        if parent.is_null() {
            return;
        }
        let Some(tip) = tooltip_of(parent) else {
            return;
        };
        let Ok(mut wide) = to_wide(text, "TTM_ADDTOOLW") else {
            return;
        };
        let info = tool_info(parent, hwnd, wide.as_mut_ptr());
        let message = if registered {
            TTM_UPDATETIPTEXTW
        } else {
            TTM_ADDTOOLW
        };
        // SAFETY: `info` and the text it points to live for the call; the tooltip copies the
        // text.
        unsafe {
            SendMessageW(
                tip,
                message,
                0,
                (&raw const info).expose_provenance().cast_signed(),
            )
        };
        if !registered {
            TIPPED.with(|tipped| {
                if let Ok(mut tipped) = tipped.try_borrow_mut() {
                    tipped.insert(self.hwnd, parent.expose_provenance());
                }
            });
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
        if (self.parent_alive)() {
            remove_tool(self.hwnd);
        } else {
            TIPPED.with(|tipped| {
                if let Ok(mut tipped) = tipped.try_borrow_mut() {
                    tipped.remove(&self.hwnd);
                }
            });
        }
        if HOT.get().0 == self.hwnd {
            // The parent's hover timer stops itself at its next tick.
            HOT.set((0, 0));
        }
        FACES.with(|faces| {
            if let Ok(mut faces) = faces.try_borrow_mut() {
                faces.remove(&self.hwnd);
            }
        });
        PAINTS.with(|paints| {
            if let Ok(mut paints) = paints.try_borrow_mut() {
                paints.remove(&self.hwnd);
            }
        });
        ICONS.with(|icons| {
            if let Ok(mut icons) = icons.try_borrow_mut() {
                icons.remove(&self.hwnd);
            }
        });
        if let Some(hwnd) = self.live() {
            // SAFETY: The parent is alive, so this child handle is still ours.
            unsafe { DestroyWindow(hwnd) };
        }
    }
}
