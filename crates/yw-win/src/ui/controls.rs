#![allow(unsafe_code)]
//! Standard child controls for non-secret values (spec/01 §7.7): push buttons, check boxes, radio
//! buttons, single-line edits (optionally `ES_PASSWORD` for RPC tokens) and static labels.
//! Notifications arrive as [`super::Msg::Command`]. Wallet secrets never go into these controls.

use core::fmt;
use std::rc::Rc;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Controls::{BST_CHECKED, BST_UNCHECKED, EM_SETLIMITTEXT};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, IsWindowEnabled, SetFocus};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BM_GETCHECK, BM_SETCHECK, BS_AUTOCHECKBOX, BS_AUTORADIOBUTTON, BS_MULTILINE, BS_PUSHBUTTON,
    CreateWindowExW, DestroyWindow, ES_AUTOHSCROLL, ES_PASSWORD, ES_READONLY, GetWindowTextLengthW,
    GetWindowTextW, HMENU, MoveWindow, SW_HIDE, SW_SHOW, SendMessageW, SetWindowTextW, ShowWindow,
    WM_SETFONT, WS_CHILD, WS_EX_CLIENTEDGE, WS_GROUP, WS_TABSTOP, WS_VISIBLE,
};

use super::paint::{Font, Rect};
use super::window::Window;
use crate::error::WinError;
use crate::mem::{WipeBuf, wipe_u16};
use crate::wide::to_wide;

const SS_NOPREFIX: u32 = 0x80;

/// Kind of a child control.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlKind {
    /// `BS_PUSHBUTTON`.
    Button,
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
        ControlKind::Button => (
            "BUTTON",
            base | WS_TABSTOP | bits(BS_PUSHBUTTON | BS_MULTILINE),
            0,
        ),
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
    let parent_hwnd: HWND = core::ptr::with_exposed_provenance_mut(parent.raw_id());
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
    let alive = parent.alive_probe();
    Ok(Control {
        hwnd: hwnd.expose_provenance(),
        id,
        parent_alive: alive,
    })
}

impl Control {
    fn raw(&self) -> HWND {
        core::ptr::with_exposed_provenance_mut(self.hwnd)
    }

    /// The command id.
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// Sets non-secret text.
    pub fn set_text(&self, text: &str) {
        if let Ok(wide) = to_wide(text, "SetWindowTextW") {
            // SAFETY: `wide` is NUL-terminated and live; the control is ours.
            unsafe { SetWindowTextW(self.raw(), wide.as_ptr()) };
        }
    }

    fn read_units(&self, max_units: usize) -> WipeBuf<u16> {
        // SAFETY: Queries the text length of our control.
        let len = unsafe { GetWindowTextLengthW(self.raw()) };
        let len = usize::try_from(len).unwrap_or(0).min(max_units);
        let mut buffer = vec![0_u16; len.saturating_add(1)];
        let capacity = i32::try_from(buffer.len()).unwrap_or(0);
        // SAFETY: `buffer` is writable for `capacity` units including the terminator.
        let copied = unsafe { GetWindowTextW(self.raw(), buffer.as_mut_ptr(), capacity) };
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
        // SAFETY: Sends EM_SETLIMITTEXT with a plain value to our control.
        unsafe {
            SendMessageW(
                self.raw(),
                EM_SETLIMITTEXT,
                usize::try_from(units).unwrap_or(0),
                0,
            )
        };
    }

    /// Checks or unchecks a check box / radio button.
    pub fn set_checked(&self, checked: bool) {
        let state = if checked { BST_CHECKED } else { BST_UNCHECKED };
        // SAFETY: Sends BM_SETCHECK with a plain value to our control.
        unsafe {
            SendMessageW(
                self.raw(),
                BM_SETCHECK,
                usize::try_from(state).unwrap_or(0),
                0,
            )
        };
    }

    /// Whether a check box / radio button is checked.
    #[must_use]
    pub fn is_checked(&self) -> bool {
        // SAFETY: Sends BM_GETCHECK to our control.
        let state = unsafe { SendMessageW(self.raw(), BM_GETCHECK, 0, 0) };
        state == isize::try_from(BST_CHECKED).unwrap_or(1)
    }

    /// Enables or disables the control.
    pub fn enable(&self, enabled: bool) {
        // SAFETY: Changes the enabled state of our control.
        unsafe { EnableWindow(self.raw(), i32::from(enabled)) };
    }

    /// Whether the control is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        // SAFETY: Queries our control.
        unsafe { IsWindowEnabled(self.raw()) != 0 }
    }

    /// Shows or hides the control.
    pub fn show(&self, visible: bool) {
        // SAFETY: Shows or hides our control.
        unsafe { ShowWindow(self.raw(), if visible { SW_SHOW } else { SW_HIDE }) };
    }

    /// Moves and resizes the control.
    pub fn set_rect(&self, rect: Rect) {
        // SAFETY: Moves our control within its parent.
        unsafe { MoveWindow(self.raw(), rect.x, rect.y, rect.w, rect.h, 1) };
    }

    /// Sets the control font (`font` must outlive the control or be replaced first).
    pub fn set_font(&self, font: &Font) {
        let handle = font.raw().expose_provenance();
        // SAFETY: Sends WM_SETFONT with our font handle and redraw = TRUE.
        unsafe { SendMessageW(self.raw(), WM_SETFONT, handle, 1) };
    }

    /// Gives the control keyboard focus.
    pub fn focus(&self) {
        // SAFETY: Sets focus to our control.
        unsafe { SetFocus(self.raw()) };
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        if (self.parent_alive)() {
            // SAFETY: The parent is alive, so this child handle is still ours.
            unsafe { DestroyWindow(self.raw()) };
        }
    }
}
