//! Capture-resistant raw Win32 surfaces for the two one-shot recovery stages.

#![allow(unsafe_code)]

use core::cell::{Cell, RefCell};
use core::fmt::Write as _;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, COLOR_HIGHLIGHT, COLOR_WINDOW, COLOR_WINDOWFRAME, DRAW_TEXT_FORMAT, DT_LEFT,
    DT_NOPREFIX, DT_SINGLELINE, DT_VCENTER, DT_WORDBREAK, DrawTextW, EndPaint, FrameRect,
    GetSysColorBrush, HDC, InvalidateRect, PAINTSTRUCT, ScreenToClient, SetBkMode, TRANSPARENT,
    UpdateWindow,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::HiDpi::{
    AdjustWindowRectExForDpi, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForSystem,
    SetProcessDpiAwarenessContext,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, GetCapture, GetFocus, GetKeyState, ReleaseCapture, SetCapture, SetFocus,
    VK_CONTROL, VK_ESCAPE, VK_INSERT, VK_LBUTTON, VK_RETURN, VK_SHIFT, VK_SPACE, VK_TAB,
};
use windows::Win32::UI::WindowsAndMessaging::{
    BS_MULTILINE, BS_PUSHBUTTON, CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DefWindowProcW,
    DestroyWindow, DispatchMessageW, GWLP_USERDATA, GetCursorPos, GetForegroundWindow, GetMessageW,
    GetWindowDisplayAffinity, GetWindowLongPtrW, IDC_ARROW, IsChild, IsDialogMessageW, KillTimer,
    LoadCursorW, MA_ACTIVATEANDEAT, MSG, PostMessageW, PostQuitMessage, RegisterClassW,
    SPI_GETWORKAREA, SW_HIDE, SW_SHOWNORMAL, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS,
    SetForegroundWindow, SetTimer, SetWindowDisplayAffinity, SetWindowLongPtrW, SetWindowTextW,
    ShowWindow, SystemParametersInfoW, TranslateMessage, WDA_EXCLUDEFROMCAPTURE, WINDOW_EX_STYLE,
    WINDOW_STYLE, WM_ACTIVATEAPP, WM_APP, WM_CANCELMODE, WM_CAPTURECHANGED, WM_CHAR, WM_CLEAR,
    WM_CLOSE, WM_CONTEXTMENU, WM_COPY, WM_CUT, WM_DESTROY, WM_DROPFILES, WM_GETOBJECT, WM_GETTEXT,
    WM_GETTEXTLENGTH, WM_IME_CHAR, WM_IME_COMPOSITION, WM_IME_ENDCOMPOSITION, WM_IME_KEYDOWN,
    WM_IME_KEYUP, WM_IME_STARTCOMPOSITION, WM_KEYDOWN, WM_KEYUP, WM_KILLFOCUS, WM_LBUTTONDOWN,
    WM_LBUTTONUP, WM_MBUTTONDOWN, WM_MBUTTONUP, WM_MOUSEACTIVATE, WM_MOUSEMOVE, WM_NCDESTROY,
    WM_PAINT, WM_PASTE, WM_PRINT, WM_PRINTCLIENT, WM_RBUTTONDOWN, WM_RBUTTONUP, WM_SETTEXT,
    WM_SYSKEYDOWN, WM_TIMER, WM_UNDO, WNDCLASSW, WS_CAPTION, WS_CHILD, WS_CLIPCHILDREN,
    WS_EX_APPWINDOW, WS_EX_CONTROLPARENT, WS_EX_DLGMODALFRAME, WS_OVERLAPPED, WS_SYSMENU,
    WS_TABSTOP, WS_VISIBLE,
};
use windows::core::{PCWSTR, w};
use zeroize::Zeroizing;

use crate::SecretInputError;
use crate::recovery::{
    CHALLENGE_WORDS, MAX_BIP39_WORD_BYTES, RecoveryConfirmationInput, RecoveryOutcome,
    RecoveryRequest,
};

const CLASS_NAME: PCWSTR = w!("YourWalletRecoveryV1");
const TIMER_ID: usize = 1;
const TIMER_INTERVAL_MS: u32 = 50;
const ACKNOWLEDGEMENT_HOLD_MS: u64 = 2_000;
const SESSION_TIMEOUT_MS: u64 = 120_000;
const CLIENT_WIDTH: i32 = 820;
const CLIENT_HEIGHT: i32 = 680;
const BASE_DPI: i32 = 96;
const SCREEN_MARGIN: i32 = 16;
const CONTENT_MARGIN: i32 = 20;
const BUTTON_WIDTH: i32 = 220;
const BUTTON_HEIGHT: i32 = 42;
const WM_RECOVERY_CANCEL: u32 = WM_APP + 0x41;
const ADDRESS_TEXT_UNITS: usize = 42;

static PRESENTED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HoldSource {
    Pointer,
    Space,
}

#[derive(Clone, Copy, Debug, Default)]
struct HoldGate {
    active: Option<(HoldSource, u64)>,
}

impl HoldGate {
    fn begin(&mut self, source: HoldSource, now_ms: u64) {
        if self.active.is_none() {
            self.active = Some((source, now_ms));
        }
    }

    fn cancel(&mut self) {
        self.active = None;
    }

    fn source(self) -> Option<HoldSource> {
        self.active.map(|(source, _)| source)
    }

    fn complete(self, now_ms: u64) -> bool {
        self.active
            .is_some_and(|(_, started)| now_ms.saturating_sub(started) >= ACKNOWLEDGEMENT_HOLD_MS)
    }

    fn remaining_ms(self, now_ms: u64) -> u64 {
        self.active.map_or(ACKNOWLEDGEMENT_HOLD_MS, |(_, started)| {
            ACKNOWLEDGEMENT_HOLD_MS.saturating_sub(now_ms.saturating_sub(started))
        })
    }
}

const CONFIRM_FIELDS: usize = CHALLENGE_WORDS + 1;
const ADDRESS_FIELD: usize = CHALLENGE_WORDS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InputKind {
    Word,
    Address,
}

/// A fixed-capacity ASCII editor whose removed and dropped bytes are wiped.
///
/// The native window never owns this text. Keyboard events mutate only this
/// crate-owned buffer, and painting uses a short-lived zeroizing UTF-16 copy.
struct SecureAsciiBuffer {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
    kind: InputKind,
}

impl SecureAsciiBuffer {
    fn new(kind: InputKind, limit: usize) -> Result<Self, SecretInputError> {
        let bytes = Zeroizing::new(Vec::with_capacity(limit));
        if bytes.capacity() != limit {
            return Err(SecretInputError::NativeFailure);
        }
        Ok(Self { bytes, limit, kind })
    }

    fn push(&mut self, byte: u8) -> bool {
        if self.bytes.len() >= self.limit || !self.accepts(byte) {
            return false;
        }
        self.bytes.push(byte);
        true
    }

    fn backspace(&mut self) -> bool {
        let Some(index) = self.bytes.len().checked_sub(1) else {
            return false;
        };
        self.bytes[index] = 0;
        self.bytes.truncate(index);
        true
    }

    fn accepts(&self, byte: u8) -> bool {
        match self.kind {
            InputKind::Word => byte.is_ascii_lowercase(),
            InputKind::Address => match self.bytes.len() {
                0 => byte == b'0',
                1 => byte == b'x',
                _ => byte.is_ascii_hexdigit(),
            },
        }
    }

    fn as_str(&self) -> Result<&str, SecretInputError> {
        core::str::from_utf8(&self.bytes).map_err(|_| SecretInputError::NativeFailure)
    }

    fn to_zeroizing_string(&self) -> Result<Zeroizing<String>, SecretInputError> {
        let value = self.as_str()?;
        let mut output = Zeroizing::new(String::with_capacity(value.len()));
        output.push_str(value);
        if output.len() != value.len() || output.capacity() != value.len() {
            return Err(SecretInputError::NativeFailure);
        }
        Ok(output)
    }
}

struct DisplaySecretState {
    mnemonic: Zeroizing<String>,
    address: Zeroizing<String>,
    mnemonic_rect: RECT,
    address_rect: RECT,
}

struct ConfirmSecretState {
    fields: [SecureAsciiBuffer; CONFIRM_FIELDS],
    rectangles: [RECT; CONFIRM_FIELDS],
    active: usize,
}

impl ConfirmSecretState {
    fn new(rectangles: [RECT; CONFIRM_FIELDS]) -> Result<Self, SecretInputError> {
        Ok(Self {
            fields: [
                SecureAsciiBuffer::new(InputKind::Word, MAX_BIP39_WORD_BYTES)?,
                SecureAsciiBuffer::new(InputKind::Word, MAX_BIP39_WORD_BYTES)?,
                SecureAsciiBuffer::new(InputKind::Word, MAX_BIP39_WORD_BYTES)?,
                SecureAsciiBuffer::new(InputKind::Word, MAX_BIP39_WORD_BYTES)?,
                SecureAsciiBuffer::new(InputKind::Address, ADDRESS_TEXT_UNITS)?,
            ],
            rectangles,
            active: 0,
        })
    }

    fn handle_character(&mut self, byte: u8) -> bool {
        if byte == 8 {
            self.fields[self.active].backspace()
        } else {
            self.fields[self.active].push(byte)
        }
    }

    fn activate_at(&mut self, x: i32, y: i32) -> bool {
        let Some(index) = self
            .rectangles
            .iter()
            .position(|rectangle| point_in_rect(*rectangle, x, y))
        else {
            return false;
        };
        self.active = index;
        true
    }

    fn cycle(&mut self, backwards: bool) {
        self.active = if backwards {
            self.active
                .checked_sub(1)
                .unwrap_or(CONFIRM_FIELDS.saturating_sub(1))
        } else {
            self.active.saturating_add(1) % CONFIRM_FIELDS
        };
    }

    fn confirmation(&self) -> Result<RecoveryConfirmationInput, SecretInputError> {
        let words = [
            self.fields[0].to_zeroizing_string()?,
            self.fields[1].to_zeroizing_string()?,
            self.fields[2].to_zeroizing_string()?,
            self.fields[3].to_zeroizing_string()?,
        ];
        let address_text = self.fields[ADDRESS_FIELD].as_str()?;
        let address = parse_address(address_text).ok_or(SecretInputError::InvalidLength)?;
        RecoveryConfirmationInput::new(words, address).map_err(|_| SecretInputError::InvalidLength)
    }
}

enum WindowSecretState {
    Display(DisplaySecretState),
    Confirm(Box<ConfirmSecretState>),
}

impl WindowSecretState {
    fn paint(&self, window: HWND) -> Result<(), SecretInputError> {
        let mut paint = PAINTSTRUCT::default();
        // SAFETY: `paint` is exact writable storage and `window` is the live
        // top-level window currently handling WM_PAINT on its UI thread.
        let device = unsafe { BeginPaint(window, &raw mut paint) };
        if device.0.is_null() {
            return Err(last_error());
        }
        // SAFETY: The paint DC is live between BeginPaint and EndPaint.
        let _ = unsafe { SetBkMode(device, TRANSPARENT) };
        let result = match self {
            Self::Display(display) => paint_display(device, display),
            Self::Confirm(confirm) => paint_confirm(device, confirm),
        };
        // SAFETY: This exactly closes the successful BeginPaint above.
        let ended = unsafe { EndPaint(window, &raw const paint) }.as_bool();
        if !ended {
            return Err(last_error());
        }
        result
    }
}

fn paint_display(device: HDC, display: &DisplaySecretState) -> Result<(), SecretInputError> {
    frame_field(device, display.mnemonic_rect, false)?;
    draw_secret_text(
        device,
        display.mnemonic.as_str(),
        inset_rect(display.mnemonic_rect, 10)?,
        DT_LEFT | DT_WORDBREAK | DT_NOPREFIX,
    )?;
    frame_field(device, display.address_rect, false)?;
    draw_secret_text(
        device,
        display.address.as_str(),
        inset_rect(display.address_rect, 8)?,
        DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX,
    )
}

fn paint_confirm(device: HDC, confirm: &ConfirmSecretState) -> Result<(), SecretInputError> {
    for (index, (field, rectangle)) in confirm
        .fields
        .iter()
        .zip(confirm.rectangles.iter().copied())
        .enumerate()
    {
        frame_field(device, rectangle, index == confirm.active)?;
        let text_rect = inset_rect(rectangle, 8)?;
        if index < CHALLENGE_WORDS {
            let mut mask = Zeroizing::new(vec![0x2022_u16; field.bytes.len()]);
            draw_secret_units(
                device,
                &mut mask,
                text_rect,
                DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX,
            )?;
        } else {
            draw_secret_text(
                device,
                field.as_str()?,
                text_rect,
                DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX,
            )?;
        }
    }
    Ok(())
}

fn frame_field(device: HDC, rectangle: RECT, active: bool) -> Result<(), SecretInputError> {
    // SAFETY: System color brushes are process-independent and system-owned.
    let brush = unsafe {
        GetSysColorBrush(if active {
            COLOR_HIGHLIGHT
        } else {
            COLOR_WINDOWFRAME
        })
    };
    // SAFETY: The DC and rectangle are live for this synchronous paint.
    if unsafe { FrameRect(device, &raw const rectangle, brush) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

fn draw_secret_text(
    device: HDC,
    text: &str,
    rectangle: RECT,
    format: DRAW_TEXT_FORMAT,
) -> Result<(), SecretInputError> {
    let mut utf16 = secret_utf16(text);
    draw_secret_units(device, &mut utf16, rectangle, format)
}

fn draw_secret_units(
    device: HDC,
    utf16: &mut [u16],
    mut rectangle: RECT,
    format: DRAW_TEXT_FORMAT,
) -> Result<(), SecretInputError> {
    if utf16.is_empty() {
        return Ok(());
    }
    // SAFETY: The mutable UTF-16 slice and rectangle remain live for the
    // synchronous GDI draw and are zeroized by their caller where secret.
    if unsafe { DrawTextW(device, utf16, &raw mut rectangle, format) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

fn inset_rect(rectangle: RECT, amount: i32) -> Result<RECT, SecretInputError> {
    let inset = RECT {
        left: rectangle
            .left
            .checked_add(amount)
            .ok_or(SecretInputError::NativeFailure)?,
        top: rectangle
            .top
            .checked_add(amount / 2)
            .ok_or(SecretInputError::NativeFailure)?,
        right: rectangle
            .right
            .checked_sub(amount)
            .ok_or(SecretInputError::NativeFailure)?,
        bottom: rectangle
            .bottom
            .checked_sub(amount / 2)
            .ok_or(SecretInputError::NativeFailure)?,
    };
    if inset.left >= inset.right || inset.top >= inset.bottom {
        return Err(SecretInputError::NativeFailure);
    }
    Ok(inset)
}

struct WindowSecretContext {
    state: RefCell<WindowSecretState>,
    failed: Cell<bool>,
}

impl WindowSecretContext {
    fn new(state: WindowSecretState) -> Self {
        Self {
            state: RefCell::new(state),
            failed: Cell::new(false),
        }
    }

    fn fail_closed(&self, window: HWND) {
        self.failed.set(true);
        // SAFETY: Posting this private cancellation message retains no pointer.
        let _ = unsafe { PostMessageW(Some(window), WM_RECOVERY_CANCEL, WPARAM(0), LPARAM(0)) };
    }

    fn handle_character(&self, window: HWND, wparam: WPARAM) {
        let Ok(value) = u8::try_from(wparam.0) else {
            return;
        };
        let Ok(mut state) = self.state.try_borrow_mut() else {
            self.fail_closed(window);
            return;
        };
        let WindowSecretState::Confirm(confirm) = &mut *state else {
            return;
        };
        let changed = confirm.handle_character(value);
        let rectangle = confirm.rectangles[confirm.active];
        drop(state);
        if changed {
            // SAFETY: The custom field rectangle belongs to this live window.
            if !unsafe { InvalidateRect(Some(window), Some(&raw const rectangle), true) }.as_bool()
            {
                self.fail_closed(window);
            }
        }
    }

    fn activate_at(&self, window: HWND, lparam: LPARAM) -> bool {
        let (x, y) = lparam_point(lparam);
        let Ok(mut state) = self.state.try_borrow_mut() else {
            self.fail_closed(window);
            return false;
        };
        let WindowSecretState::Confirm(confirm) = &mut *state else {
            return false;
        };
        let previous = confirm.active;
        let activated = confirm.activate_at(x, y);
        let rectangles = if activated {
            Some((
                confirm.rectangles[previous],
                confirm.rectangles[confirm.active],
            ))
        } else {
            None
        };
        drop(state);
        if let Some((old, new)) = rectangles {
            // SAFETY: Both rectangles belong to this live custom editor.
            let old_ok =
                unsafe { InvalidateRect(Some(window), Some(&raw const old), true) }.as_bool();
            // SAFETY: Same as above.
            let new_ok =
                unsafe { InvalidateRect(Some(window), Some(&raw const new), true) }.as_bool();
            if !old_ok || !new_ok {
                self.fail_closed(window);
                return false;
            }
        }
        activated
    }
}

struct NativeSurface {
    window: HWND,
    secret_context: Option<Box<WindowSecretContext>>,
}

impl NativeSurface {
    fn new(window: HWND) -> Self {
        Self {
            window,
            secret_context: None,
        }
    }

    fn attach_secret_state(&mut self, state: WindowSecretState) -> Result<(), SecretInputError> {
        if self.secret_context.is_some() {
            return Err(SecretInputError::NativeFailure);
        }
        let mut context = Box::new(WindowSecretContext::new(state));
        let pointer = core::ptr::from_mut(&mut *context);
        let address =
            isize::try_from(pointer.addr()).map_err(|_| SecretInputError::NativeFailure)?;
        // SAFETY: The boxed context has a stable address for the entire interval
        // in which it is attached. Capture affinity was already set and read back
        // before callers may construct and attach this secret-bearing state.
        unsafe {
            let _ = SetWindowLongPtrW(self.window, GWLP_USERDATA, address);
        }
        // SAFETY: This only reads back the pointer-sized value just installed.
        if unsafe { GetWindowLongPtrW(self.window, GWLP_USERDATA) } != address {
            // SAFETY: Best-effort rollback leaves no reachable secret pointer.
            unsafe {
                let _ = SetWindowLongPtrW(self.window, GWLP_USERDATA, 0);
            }
            return Err(SecretInputError::NativeFailure);
        }
        self.secret_context = Some(context);
        // SAFETY: The hidden live window now has a valid attached state. Erasing
        // schedules the first custom paint but cannot paint until ShowWindow.
        if !unsafe { InvalidateRect(Some(self.window), None, true) }.as_bool() {
            return Err(last_error());
        }
        Ok(())
    }

    fn confirmation(&self) -> Result<RecoveryConfirmationInput, SecretInputError> {
        let context = self
            .secret_context
            .as_ref()
            .ok_or(SecretInputError::NativeFailure)?;
        if context.failed.get() {
            return Err(SecretInputError::NativeFailure);
        }
        let state = context
            .state
            .try_borrow()
            .map_err(|_| SecretInputError::NativeFailure)?;
        let WindowSecretState::Confirm(confirm) = &*state else {
            return Err(SecretInputError::NativeFailure);
        };
        confirm.confirmation()
    }

    fn cycle_confirm(&self, backwards: bool) -> Result<(), SecretInputError> {
        let context = self
            .secret_context
            .as_ref()
            .ok_or(SecretInputError::NativeFailure)?;
        let mut state = context
            .state
            .try_borrow_mut()
            .map_err(|_| SecretInputError::NativeFailure)?;
        let WindowSecretState::Confirm(confirm) = &mut *state else {
            return Err(SecretInputError::NativeFailure);
        };
        confirm.cycle(backwards);
        drop(state);
        // SAFETY: The live window owns the custom input rectangles.
        if !unsafe { InvalidateRect(Some(self.window), None, true) }.as_bool() {
            return Err(last_error());
        }
        Ok(())
    }
}

impl Drop for NativeSurface {
    fn drop(&mut self) {
        // SAFETY: The timer belongs to this UI-thread window. Failure during
        // teardown cannot turn the default cancellation into acceptance.
        let _ = unsafe { KillTimer(Some(self.window), TIMER_ID) };
        // Hide before destruction. The context remains live throughout every
        // synchronous hide message. Detach the pointer before zeroizing so even
        // a failed DestroyWindow cannot leave a dangling WNDPROC capability.
        // SAFETY: This module owns the live top-level one-shot window.
        let _ = unsafe { ShowWindow(self.window, SW_HIDE) };
        // SAFETY: This clears only pointer-sized window-owned storage.
        unsafe {
            let _ = SetWindowLongPtrW(self.window, GWLP_USERDATA, 0);
        }
        // SAFETY: Read back the value synchronously before dropping the Box.
        if unsafe { GetWindowLongPtrW(self.window, GWLP_USERDATA) } != 0 {
            // Continuing could expose a dangling pointer to later window
            // messages. This one-shot helper must terminate without diagnostics.
            std::process::abort();
        }
        let _ = self.secret_context.take();
        // SAFETY: No secret pointer remains attached to the hidden live window.
        let _ = unsafe { DestroyWindow(self.window) };
    }
}

struct DisplayControls {
    surface: NativeSurface,
    status: HWND,
    cancel: HWND,
    acknowledge: HWND,
}

struct ConfirmControls {
    surface: NativeSurface,
    status: HWND,
    cancel: HWND,
    submit: HWND,
}

pub(super) fn present(request: &RecoveryRequest) -> Result<RecoveryOutcome, SecretInputError> {
    if PRESENTED.swap(true, Ordering::AcqRel) {
        return Err(SecretInputError::NativeFailure);
    }
    // SAFETY: This dedicated helper sets its DPI mode before creating any UI.
    // Failure is safe to ignore because all dimensions are validated later.
    let _ = unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    match request {
        RecoveryRequest::Display(display) => {
            let controls = create_display(display)?;
            run_display_loop(&controls)
        }
        RecoveryRequest::Confirm(confirm) => {
            let controls = create_confirm(confirm)?;
            run_confirm_loop(&controls)
        }
    }
}

fn create_base_window(title: &str) -> Result<(NativeSurface, HINSTANCE, i32), SecretInputError> {
    // SAFETY: A null module name requests the current executable module.
    let module = unsafe { GetModuleHandleW(None) }.map_err(win_error)?;
    let instance = HINSTANCE(module.0);
    // SAFETY: The system arrow cursor is process-independent and system-owned.
    let cursor = unsafe { LoadCursorW(None, IDC_ARROW) }.map_err(win_error)?;
    // SAFETY: The returned system brush remains owned by Windows.
    let background = unsafe { GetSysColorBrush(COLOR_WINDOW) };
    let class = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        hCursor: cursor,
        hbrBackground: background,
        lpszClassName: CLASS_NAME,
        ..Default::default()
    };
    // SAFETY: The class and static class-name pointer are valid for the call.
    if unsafe { RegisterClassW(&raw const class) } == 0 {
        return Err(last_error());
    }

    // SAFETY: This returns the effective system DPI as an integer value.
    let dpi =
        i32::try_from(unsafe { GetDpiForSystem() }).map_err(|_| SecretInputError::NativeFailure)?;
    if !(48..=768).contains(&dpi) {
        return Err(SecretInputError::NativeFailure);
    }
    let window_style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN;
    let ex_style = WS_EX_APPWINDOW | WS_EX_CONTROLPARENT | WS_EX_DLGMODALFRAME;
    let window_rect = centered_window(dpi, window_style, ex_style)?;
    let title = secret_wide(title);
    // SAFETY: The class is registered, the title is live and NUL-terminated,
    // and no pointer from this call is retained by our procedure.
    let window = unsafe {
        CreateWindowExW(
            ex_style,
            CLASS_NAME,
            PCWSTR(title.as_ptr()),
            window_style,
            window_rect.x,
            window_rect.y,
            window_rect.width,
            window_rect.height,
            None,
            None,
            Some(instance),
            None,
        )
    }
    .map_err(win_error)?;
    let surface = NativeSurface::new(window);

    // Capture exclusion is installed while the top-level window is still
    // hidden and before any secret state can be attached or painted.
    // SAFETY: `window` is a live top-level HWND owned by this process.
    unsafe { SetWindowDisplayAffinity(window, WDA_EXCLUDEFROMCAPTURE) }.map_err(win_error)?;
    let mut affinity = 0_u32;
    // SAFETY: `affinity` is exact writable DWORD storage and the HWND is live.
    unsafe { GetWindowDisplayAffinity(window, &raw mut affinity) }.map_err(win_error)?;
    if affinity != WDA_EXCLUDEFROMCAPTURE.0 {
        return Err(SecretInputError::NativeFailure);
    }
    Ok((surface, instance, dpi))
}

#[allow(clippy::too_many_lines)]
fn create_display(
    request: &crate::recovery::RecoveryDisplayRequest,
) -> Result<DisplayControls, SecretInputError> {
    let title = Zeroizing::new(format!(
        "Your Wallet - {} - signed recovery helper",
        request.anti_phishing_phrase()
    ));
    let (mut surface, instance, dpi) = create_base_window(&title)?;
    let phrase = Zeroizing::new(format!(
        "Anti-phishing phrase: {}\r\nMatch this phrase before reading the recovery material.",
        request.anti_phishing_phrase()
    ));
    create_control(
        surface.window,
        instance,
        w!("STATIC"),
        &phrase,
        WS_CHILD | WS_VISIBLE,
        WINDOW_EX_STYLE(0),
        RectSpec::scaled(CONTENT_MARGIN, 18, CLIENT_WIDTH - 40, 48, dpi),
    )?;
    create_control(
        surface.window,
        instance,
        w!("STATIC"),
        "Write these words on paper, in order. Do not copy them to the clipboard, take a screenshot, or store them in cloud storage.",
        WS_CHILD | WS_VISIBLE,
        WINDOW_EX_STYLE(0),
        RectSpec::scaled(CONTENT_MARGIN, 76, CLIENT_WIDTH - 40, 58, dpi),
    )?;
    create_control(
        surface.window,
        instance,
        w!("STATIC"),
        &format!(
            "BIP-39 English recovery phrase ({} words)",
            request.word_count().get()
        ),
        WS_CHILD | WS_VISIBLE,
        WINDOW_EX_STYLE(0),
        RectSpec::scaled(CONTENT_MARGIN, 145, CLIENT_WIDTH - 40, 24, dpi),
    )?;
    create_control(
        surface.window,
        instance,
        w!("STATIC"),
        "First address (m/44'/60'/0'/0/0, no BIP-39 passphrase)",
        WS_CHILD | WS_VISIBLE,
        WINDOW_EX_STYLE(0),
        RectSpec::scaled(CONTENT_MARGIN, 478, CLIENT_WIDTH - 40, 24, dpi),
    )?;
    let status = create_control(
        surface.window,
        instance,
        w!("STATIC"),
        "Hold the acknowledgement control continuously for 2 seconds after writing the backup.",
        WS_CHILD | WS_VISIBLE,
        WINDOW_EX_STYLE(0),
        RectSpec::scaled(CONTENT_MARGIN, 552, CLIENT_WIDTH - 40, 46, dpi),
    )?;
    let cancel = create_control(
        surface.window,
        instance,
        w!("BUTTON"),
        "Cancel (Esc)",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | style(BS_PUSHBUTTON | BS_MULTILINE),
        WINDOW_EX_STYLE(0),
        RectSpec::scaled(340, 614, BUTTON_WIDTH, BUTTON_HEIGHT, dpi),
    )?;
    let acknowledge = create_control(
        surface.window,
        instance,
        w!("BUTTON"),
        "Hold to acknowledge - 2.0 s",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | style(BS_PUSHBUTTON | BS_MULTILINE),
        WINDOW_EX_STYLE(0),
        RectSpec::scaled(580, 614, BUTTON_WIDTH, BUTTON_HEIGHT, dpi),
    )?;
    let secret_state = WindowSecretState::Display(DisplaySecretState {
        mnemonic: owned_zeroizing_string(request.mnemonic())?,
        address: format_address(request.first_address())?,
        mnemonic_rect: RectSpec::scaled(CONTENT_MARGIN, 174, CLIENT_WIDTH - 40, 290, dpi)
            .as_rect()?,
        address_rect: RectSpec::scaled(CONTENT_MARGIN, 507, CLIENT_WIDTH - 40, 34, dpi)
            .as_rect()?,
    });
    surface.attach_secret_state(secret_state)?;
    arm_and_show(&surface, cancel)?;
    Ok(DisplayControls {
        surface,
        status,
        cancel,
        acknowledge,
    })
}

#[allow(clippy::too_many_lines)]
fn create_confirm(
    request: &crate::recovery::RecoveryConfirmRequest,
) -> Result<ConfirmControls, SecretInputError> {
    let title = Zeroizing::new(format!(
        "Your Wallet - {} - signed recovery confirmation",
        request.anti_phishing_phrase()
    ));
    let (mut surface, instance, dpi) = create_base_window(&title)?;
    let phrase = Zeroizing::new(format!(
        "Anti-phishing phrase: {}\r\nUse only the paper backup retained from the previous, closed window.",
        request.anti_phishing_phrase()
    ));
    create_control(
        surface.window,
        instance,
        w!("STATIC"),
        &phrase,
        WS_CHILD | WS_VISIBLE,
        WINDOW_EX_STYLE(0),
        RectSpec::scaled(CONTENT_MARGIN, 18, CLIENT_WIDTH - 40, 48, dpi),
    )?;
    create_control(
        surface.window,
        instance,
        w!("STATIC"),
        &format!(
            "Enter exactly four lowercase English words from the {}-word backup. Expected words and the address are not present in this request.",
            request.word_count().get()
        ),
        WS_CHILD | WS_VISIBLE,
        WINDOW_EX_STYLE(0),
        RectSpec::scaled(CONTENT_MARGIN, 78, CLIENT_WIDTH - 40, 52, dpi),
    )?;

    let mut field_rectangles = Vec::with_capacity(CONFIRM_FIELDS);
    for (index, position) in request.positions().into_iter().enumerate() {
        let top = 145_i32
            .checked_add(i32::try_from(index).unwrap_or(i32::MAX).saturating_mul(58))
            .ok_or(SecretInputError::NativeFailure)?;
        create_control(
            surface.window,
            instance,
            w!("STATIC"),
            &format!("Word #{position}"),
            WS_CHILD | WS_VISIBLE,
            WINDOW_EX_STYLE(0),
            RectSpec::scaled(CONTENT_MARGIN, top + 7, 180, 28, dpi),
        )?;
        field_rectangles.push(RectSpec::scaled(215, top, 565, 36, dpi).as_rect()?);
    }
    create_control(
        surface.window,
        instance,
        w!("STATIC"),
        "First address (full 0x-prefixed 20-byte address)",
        WS_CHILD | WS_VISIBLE,
        WINDOW_EX_STYLE(0),
        RectSpec::scaled(CONTENT_MARGIN, 390, CLIENT_WIDTH - 40, 25, dpi),
    )?;
    field_rectangles
        .push(RectSpec::scaled(CONTENT_MARGIN, 420, CLIENT_WIDTH - 40, 36, dpi).as_rect()?);
    let status = create_control(
        surface.window,
        instance,
        w!("STATIC"),
        "Clipboard, context menu, drag/drop, accessibility reads, and screen capture are blocked. This window expires in 120 seconds.",
        WS_CHILD | WS_VISIBLE,
        WINDOW_EX_STYLE(0),
        RectSpec::scaled(CONTENT_MARGIN, 470, CLIENT_WIDTH - 40, 55, dpi),
    )?;
    let cancel = create_control(
        surface.window,
        instance,
        w!("BUTTON"),
        "Cancel (Esc)",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | style(BS_PUSHBUTTON | BS_MULTILINE),
        WINDOW_EX_STYLE(0),
        RectSpec::scaled(340, 614, BUTTON_WIDTH, BUTTON_HEIGHT, dpi),
    )?;
    let submit = create_control(
        surface.window,
        instance,
        w!("BUTTON"),
        "Confirm paper backup",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | style(BS_PUSHBUTTON | BS_MULTILINE),
        WINDOW_EX_STYLE(0),
        RectSpec::scaled(580, 614, BUTTON_WIDTH, BUTTON_HEIGHT, dpi),
    )?;
    let rectangles: [RECT; CONFIRM_FIELDS] = field_rectangles
        .try_into()
        .map_err(|_| SecretInputError::NativeFailure)?;
    surface.attach_secret_state(WindowSecretState::Confirm(Box::new(
        ConfirmSecretState::new(rectangles)?,
    )))?;
    arm_and_show(&surface, surface.window)?;
    Ok(ConfirmControls {
        surface,
        status,
        cancel,
        submit,
    })
}

#[allow(clippy::too_many_lines)]
fn run_display_loop(controls: &DisplayControls) -> Result<RecoveryOutcome, SecretInputError> {
    let started = Instant::now();
    let mut hold = HoldGate::default();
    loop {
        let mut message = MSG::default();
        // SAFETY: `message` is initialized writable storage and this dedicated
        // UI thread accepts every message in its queue.
        let result = unsafe { GetMessageW(&raw mut message, None, 0, 0) }.0;
        if result == -1 {
            return Err(last_error());
        }
        if result == 0 {
            return Ok(RecoveryOutcome::DisplayCancelled);
        }
        let now_ms = elapsed_milliseconds(started);
        if message.message == WM_RECOVERY_CANCEL
            || session_must_cancel(controls.surface.window, &message, now_ms)
        {
            return Ok(RecoveryOutcome::DisplayCancelled);
        }
        match message.message {
            WM_TIMER if message.hwnd == controls.surface.window && message.wParam.0 == TIMER_ID => {
                if hold.source() == Some(HoldSource::Pointer) {
                    // SAFETY: These calls only query physical input and capture state.
                    let down = unsafe { GetAsyncKeyState(i32::from(VK_LBUTTON.0)) } < 0;
                    // SAFETY: This only queries the UI thread's capture HWND.
                    let captured = unsafe { GetCapture() } == controls.acknowledge;
                    if !down || !captured || !physical_pointer_inside(controls.acknowledge) {
                        hold.cancel();
                        release_capture_if_owned(controls.acknowledge);
                    }
                }
                if hold.source() == Some(HoldSource::Space) {
                    // SAFETY: This only queries current physical keyboard state.
                    let down = unsafe { GetAsyncKeyState(i32::from(VK_SPACE.0)) } < 0;
                    // SAFETY: This only reads the UI thread's current focus HWND.
                    let focused = unsafe { GetFocus() } == controls.acknowledge;
                    if !down || !focused {
                        hold.cancel();
                    }
                }
                if hold.complete(now_ms) {
                    release_capture_if_owned(controls.acknowledge);
                    return Ok(RecoveryOutcome::DisplayAcknowledged);
                }
                update_hold_status(controls, hold, now_ms)?;
                continue;
            }
            WM_LBUTTONDOWN if message.hwnd == controls.acknowledge => {
                // SAFETY: This only queries current physical pointer state.
                let physical = unsafe { GetAsyncKeyState(i32::from(VK_LBUTTON.0)) } < 0;
                if physical
                    && foreground_window() == controls.surface.window
                    && point_inside(controls.acknowledge, message.lParam)
                    && physical_pointer_inside(controls.acknowledge)
                {
                    // SAFETY: Both handles are live UI-thread controls.
                    unsafe {
                        let _ = SetFocus(Some(controls.acknowledge));
                        SetCapture(controls.acknowledge);
                    }
                    hold.begin(HoldSource::Pointer, now_ms);
                    update_hold_status(controls, hold, now_ms)?;
                }
                continue;
            }
            WM_MOUSEMOVE
                if message.hwnd == controls.acknowledge
                    && hold.source() == Some(HoldSource::Pointer)
                    && !point_inside(controls.acknowledge, message.lParam) =>
            {
                hold.cancel();
                release_capture_if_owned(controls.acknowledge);
                update_hold_status(controls, hold, now_ms)?;
            }
            WM_LBUTTONUP if message.hwnd == controls.acknowledge => {
                hold.cancel();
                release_capture_if_owned(controls.acknowledge);
                update_hold_status(controls, hold, now_ms)?;
                continue;
            }
            WM_LBUTTONUP
                if message.hwnd == controls.cancel
                    && point_inside(controls.cancel, message.lParam) =>
            {
                return Ok(RecoveryOutcome::DisplayCancelled);
            }
            WM_KEYDOWN => {
                let key = u16::try_from(message.wParam.0).unwrap_or(u16::MAX);
                if key == VK_ESCAPE.0 {
                    return Ok(RecoveryOutcome::DisplayCancelled);
                }
                if message.hwnd == controls.cancel
                    && matches!(key, value if value == VK_RETURN.0 || value == VK_SPACE.0)
                {
                    return Ok(RecoveryOutcome::DisplayCancelled);
                }
                if message.hwnd == controls.acknowledge
                    && key == VK_SPACE.0
                    && !key_is_repeat(message.lParam)
                {
                    // SAFETY: This only queries current physical keyboard state.
                    if unsafe { GetAsyncKeyState(i32::from(VK_SPACE.0)) } < 0 {
                        hold.begin(HoldSource::Space, now_ms);
                        update_hold_status(controls, hold, now_ms)?;
                    }
                    continue;
                }
                if message.hwnd == controls.acknowledge && key == VK_RETURN.0 {
                    continue;
                }
            }
            WM_KEYUP if message.hwnd == controls.acknowledge => {
                let key = u16::try_from(message.wParam.0).unwrap_or(u16::MAX);
                if key == VK_SPACE.0 {
                    hold.cancel();
                    update_hold_status(controls, hold, now_ms)?;
                    continue;
                }
            }
            WM_CAPTURECHANGED | WM_CANCELMODE if hold.source().is_some() => {
                hold.cancel();
                release_capture_if_owned(controls.acknowledge);
                update_hold_status(controls, hold, now_ms)?;
                continue;
            }
            _ => {}
        }
        dispatch_dialog_message(controls.surface.window, &message);
    }
}

fn run_confirm_loop(controls: &ConfirmControls) -> Result<RecoveryOutcome, SecretInputError> {
    let started = Instant::now();
    loop {
        let mut message = MSG::default();
        // SAFETY: `message` is initialized writable storage and this dedicated
        // UI thread accepts every message in its queue.
        let result = unsafe { GetMessageW(&raw mut message, None, 0, 0) }.0;
        if result == -1 {
            return Err(last_error());
        }
        if result == 0 {
            return Ok(RecoveryOutcome::ConfirmCancelled);
        }
        let now_ms = elapsed_milliseconds(started);
        if message.message == WM_RECOVERY_CANCEL
            || session_must_cancel(controls.surface.window, &message, now_ms)
        {
            return Ok(RecoveryOutcome::ConfirmCancelled);
        }
        let key = if message.message == WM_KEYDOWN {
            Some(u16::try_from(message.wParam.0).unwrap_or(u16::MAX))
        } else {
            None
        };
        if key == Some(VK_ESCAPE.0) {
            return Ok(RecoveryOutcome::ConfirmCancelled);
        }
        if message.message == WM_KEYDOWN
            && message.hwnd == controls.surface.window
            && key == Some(VK_TAB.0)
        {
            // SAFETY: This only queries current keyboard state.
            let backwards = unsafe { GetKeyState(i32::from(VK_SHIFT.0)) } < 0;
            controls.surface.cycle_confirm(backwards)?;
            continue;
        }
        let submit_requested = (message.message == WM_LBUTTONUP
            && message.hwnd == controls.submit
            && point_inside(controls.submit, message.lParam))
            || (message.message == WM_KEYDOWN && key == Some(VK_RETURN.0))
            || (message.message == WM_KEYUP
                && message.hwnd == controls.submit
                && u16::try_from(message.wParam.0).unwrap_or(u16::MAX) == VK_SPACE.0);
        if submit_requested {
            match controls.surface.confirmation() {
                Ok(confirmation) => return Ok(RecoveryOutcome::Confirmed(confirmation)),
                Err(SecretInputError::InvalidLength | SecretInputError::Malformed) => {
                    set_text(
                        controls.status,
                        "Enter four lowercase English words and one full 0x-prefixed address. Nothing was accepted.",
                    )?;
                    // SAFETY: The custom editor belongs to the live top-level window.
                    let _ = unsafe { SetFocus(Some(controls.surface.window)) };
                    // SAFETY: This only reads the UI thread's focus HWND.
                    if unsafe { GetFocus() } != controls.surface.window {
                        return Err(SecretInputError::NativeFailure);
                    }
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        if message.message == WM_LBUTTONUP
            && message.hwnd == controls.cancel
            && point_inside(controls.cancel, message.lParam)
        {
            return Ok(RecoveryOutcome::ConfirmCancelled);
        }
        if message.hwnd == controls.cancel
            && ((message.message == WM_KEYDOWN
                && matches!(key, Some(value) if value == VK_RETURN.0))
                || (message.message == WM_KEYUP
                    && u16::try_from(message.wParam.0).unwrap_or(u16::MAX) == VK_SPACE.0))
        {
            return Ok(RecoveryOutcome::ConfirmCancelled);
        }
        dispatch_dialog_message(controls.surface.window, &message);
    }
}

fn session_must_cancel(window: HWND, message: &MSG, now_ms: u64) -> bool {
    if now_ms >= SESSION_TIMEOUT_MS {
        return true;
    }
    if message.message == WM_ACTIVATEAPP && message.wParam.0 == 0 {
        return true;
    }
    if message.message == WM_KILLFOCUS {
        let Ok(address) = usize::try_from(message.lParam.0) else {
            return true;
        };
        let next = HWND(core::ptr::with_exposed_provenance_mut(address));
        // SAFETY: `window` is live. A null, foreign, or unrelated focus target
        // means this one-shot surface lost focus and must cancel.
        if next.is_invalid() || (next != window && !unsafe { IsChild(window, next) }.as_bool()) {
            return true;
        }
    }
    if message.message == WM_TIMER && message.hwnd == window && message.wParam.0 == TIMER_ID {
        return foreground_window() != window;
    }
    false
}

fn update_hold_status(
    controls: &DisplayControls,
    hold: HoldGate,
    now_ms: u64,
) -> Result<(), SecretInputError> {
    let remaining = hold.remaining_ms(now_ms);
    let whole = remaining / 1_000;
    let tenth = (remaining % 1_000) / 100;
    let session_remaining = SESSION_TIMEOUT_MS
        .saturating_sub(now_ms)
        .saturating_add(999)
        / 1_000;
    let (status, label) = if hold.source().is_some() {
        (
            format!(
                "Keep holding continuously for {whole}.{tenth} more seconds. The window expires in {session_remaining} seconds."
            ),
            format!("Keep holding - {whole}.{tenth} s"),
        )
    } else {
        (
            format!(
                "Hold continuously for 2 seconds after writing the backup. The window expires in {session_remaining} seconds."
            ),
            "Hold to acknowledge - 2.0 s".to_owned(),
        )
    };
    set_text(controls.status, &status)?;
    set_text(controls.acknowledge, &label)
}

fn parse_address(value: &str) -> Option<[u8; 20]> {
    let hexadecimal = value.strip_prefix("0x")?;
    if hexadecimal.len() != 40 || !hexadecimal.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut address = [0_u8; 20];
    for (index, pair) in hexadecimal.as_bytes().chunks_exact(2).enumerate() {
        address[index] = hex_nibble(pair[0])?.checked_mul(16)? | hex_nibble(pair[1])?;
    }
    Some(address)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn format_address(address: [u8; 20]) -> Result<Zeroizing<String>, SecretInputError> {
    let mut output = Zeroizing::new(String::with_capacity(ADDRESS_TEXT_UNITS));
    output.push_str("0x");
    for byte in address {
        write!(&mut *output, "{byte:02x}").map_err(|_| SecretInputError::NativeFailure)?;
    }
    if output.len() != ADDRESS_TEXT_UNITS || output.capacity() != ADDRESS_TEXT_UNITS {
        return Err(SecretInputError::NativeFailure);
    }
    Ok(output)
}

fn arm_and_show(surface: &NativeSurface, initial_focus: HWND) -> Result<(), SecretInputError> {
    if surface.secret_context.is_none() {
        return Err(SecretInputError::NativeFailure);
    }
    // SAFETY: The timer targets the live hidden top-level window and uses no callback.
    if unsafe { SetTimer(Some(surface.window), TIMER_ID, TIMER_INTERVAL_MS, None) } == 0 {
        return Err(last_error());
    }
    // SAFETY: All HWNDs are live, capture exclusion is already verified, and
    // the selected focus control is a child of this top-level window.
    unsafe {
        let _ = ShowWindow(surface.window, SW_SHOWNORMAL);
        if !UpdateWindow(surface.window).as_bool() {
            return Err(last_error());
        }
        if !SetForegroundWindow(surface.window).as_bool() {
            return Err(SecretInputError::NativeFailure);
        }
        let _ = SetFocus(Some(initial_focus));
    }
    // SAFETY: This only reads this UI thread's current focus HWND.
    let focused = unsafe { GetFocus() };
    if foreground_window() != surface.window || focused != initial_focus {
        return Err(SecretInputError::NativeFailure);
    }
    Ok(())
}

fn create_control(
    parent: HWND,
    instance: HINSTANCE,
    class: PCWSTR,
    text: &str,
    window_style: WINDOW_STYLE,
    ex_style: WINDOW_EX_STYLE,
    rectangle: RectSpec,
) -> Result<HWND, SecretInputError> {
    let text = secret_wide(text);
    // SAFETY: The system class is static, the text is live/NUL-terminated, and
    // parent/instance are live handles belonging to this UI thread.
    unsafe {
        CreateWindowExW(
            ex_style,
            class,
            PCWSTR(text.as_ptr()),
            window_style,
            rectangle.x,
            rectangle.y,
            rectangle.width,
            rectangle.height,
            Some(parent),
            None,
            Some(instance),
            None,
        )
    }
    .map_err(win_error)
}

fn set_text(control: HWND, text: &str) -> Result<(), SecretInputError> {
    let text = secret_wide(text);
    // SAFETY: `control` is live and text is NUL-terminated for this call.
    unsafe { SetWindowTextW(control, PCWSTR(text.as_ptr())) }.map_err(win_error)
}

fn dispatch_dialog_message(window: HWND, message: &MSG) {
    // SAFETY: The message came from GetMessage. Dialog translation enables
    // keyboard traversal; unhandled messages retain their original target.
    if !unsafe { IsDialogMessageW(window, &raw const *message) }.as_bool() {
        // SAFETY: The initialized message is dispatched synchronously with its
        // exact original fields.
        unsafe {
            let _ = TranslateMessage(&raw const *message);
            DispatchMessageW(&raw const *message);
        }
    }
}

fn release_capture_if_owned(control: HWND) {
    // SAFETY: Capture state is thread-local and owns no caller memory.
    if unsafe { GetCapture() } == control {
        // SAFETY: The current thread owns capture for this control.
        let _ = unsafe { ReleaseCapture() };
    }
}

fn point_inside(control: HWND, lparam: LPARAM) -> bool {
    let (x, y) = lparam_point(lparam);
    let mut rectangle = RECT::default();
    // SAFETY: The rectangle is writable and the control remains live.
    unsafe { windows::Win32::UI::WindowsAndMessaging::GetClientRect(control, &raw mut rectangle) }
        .is_ok()
        && point_in_rect(rectangle, x, y)
}

fn physical_pointer_inside(control: HWND) -> bool {
    let mut point = POINT::default();
    // SAFETY: `point` is exact writable storage for the physical cursor position.
    if unsafe { GetCursorPos(&raw mut point) }.is_err() {
        return false;
    }
    // SAFETY: The control is live and `point` remains writable for conversion.
    if !unsafe { ScreenToClient(control, &raw mut point) }.as_bool() {
        return false;
    }
    let mut rectangle = RECT::default();
    // SAFETY: The rectangle is writable and the control remains live.
    unsafe { windows::Win32::UI::WindowsAndMessaging::GetClientRect(control, &raw mut rectangle) }
        .is_ok()
        && point_in_rect(rectangle, point.x, point.y)
}

fn lparam_point(lparam: LPARAM) -> (i32, i32) {
    let packed = lparam.0.to_le_bytes();
    (
        i32::from(i16::from_le_bytes([packed[0], packed[1]])),
        i32::from(i16::from_le_bytes([packed[2], packed[3]])),
    )
}

const fn point_in_rect(rectangle: RECT, x: i32, y: i32) -> bool {
    x >= rectangle.left && y >= rectangle.top && x < rectangle.right && y < rectangle.bottom
}

fn centered_window(
    dpi: i32,
    window_style: WINDOW_STYLE,
    ex_style: WINDOW_EX_STYLE,
) -> Result<RectSpec, SecretInputError> {
    let client_width = scale(CLIENT_WIDTH, dpi);
    let client_height = scale(CLIENT_HEIGHT, dpi);
    let mut outer = RECT {
        left: 0,
        top: 0,
        right: client_width,
        bottom: client_height,
    };
    // SAFETY: `outer` is exact writable storage and styles are fixed locally.
    unsafe {
        AdjustWindowRectExForDpi(
            &raw mut outer,
            window_style,
            false,
            ex_style,
            u32::try_from(dpi).map_err(|_| SecretInputError::NativeFailure)?,
        )
    }
    .map_err(win_error)?;
    let width = outer
        .right
        .checked_sub(outer.left)
        .ok_or(SecretInputError::NativeFailure)?;
    let height = outer
        .bottom
        .checked_sub(outer.top)
        .ok_or(SecretInputError::NativeFailure)?;
    let mut work_area = RECT::default();
    // SAFETY: `work_area` is initialized writable storage for this read-only query.
    unsafe {
        SystemParametersInfoW(
            SPI_GETWORKAREA,
            0,
            Some((&raw mut work_area).cast()),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
    }
    .map_err(win_error)?;
    let work_width = work_area
        .right
        .checked_sub(work_area.left)
        .ok_or(SecretInputError::NativeFailure)?;
    let work_height = work_area
        .bottom
        .checked_sub(work_area.top)
        .ok_or(SecretInputError::NativeFailure)?;
    let margin = scale(SCREEN_MARGIN, dpi);
    if width.saturating_add(margin.saturating_mul(2)) > work_width
        || height.saturating_add(margin.saturating_mul(2)) > work_height
    {
        return Err(SecretInputError::NativeFailure);
    }
    Ok(RectSpec {
        x: work_area.left + (work_width - width) / 2,
        y: work_area.top + (work_height - height) / 2,
        width,
        height,
    })
}

#[derive(Clone, Copy, Debug)]
struct RectSpec {
    x: i32,
    y: i32,
    width: i32,
    height: i32,
}

impl RectSpec {
    const fn scaled(x: i32, y: i32, width: i32, height: i32, dpi: i32) -> Self {
        Self {
            x: scale(x, dpi),
            y: scale(y, dpi),
            width: scale(width, dpi),
            height: scale(height, dpi),
        }
    }

    fn as_rect(self) -> Result<RECT, SecretInputError> {
        Ok(RECT {
            left: self.x,
            top: self.y,
            right: self
                .x
                .checked_add(self.width)
                .ok_or(SecretInputError::NativeFailure)?,
            bottom: self
                .y
                .checked_add(self.height)
                .ok_or(SecretInputError::NativeFailure)?,
        })
    }
}

const fn scale(value: i32, dpi: i32) -> i32 {
    value.saturating_mul(dpi) / BASE_DPI
}

const fn style(value: i32) -> WINDOW_STYLE {
    WINDOW_STYLE(u32::from_ne_bytes(value.to_ne_bytes()))
}

fn secret_wide(text: &str) -> Zeroizing<Vec<u16>> {
    Zeroizing::new(text.encode_utf16().chain([0]).collect())
}

fn secret_utf16(text: &str) -> Zeroizing<Vec<u16>> {
    Zeroizing::new(text.encode_utf16().collect())
}

fn owned_zeroizing_string(text: &str) -> Result<Zeroizing<String>, SecretInputError> {
    let mut output = Zeroizing::new(String::with_capacity(text.len()));
    output.push_str(text);
    if output.len() != text.len() || output.capacity() != text.len() {
        return Err(SecretInputError::NativeFailure);
    }
    Ok(output)
}

fn elapsed_milliseconds(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

const fn key_is_repeat(lparam: LPARAM) -> bool {
    lparam.0 & (1_isize << 30) != 0
}

fn foreground_window() -> HWND {
    // SAFETY: This only queries the current foreground HWND.
    unsafe { GetForegroundWindow() }
}

fn last_error() -> SecretInputError {
    SecretInputError::Io(io::Error::last_os_error())
}

#[allow(clippy::needless_pass_by_value)]
fn win_error(error: windows::core::Error) -> SecretInputError {
    SecretInputError::Io(io::Error::from_raw_os_error(error.code().0))
}

fn window_secret_context(window: HWND) -> Option<&'static WindowSecretContext> {
    // SAFETY: This only reads pointer-sized window-owned storage. The returned
    // pointer is installed from a Box before showing the window and remains live
    // until NativeSurface synchronously detaches it during teardown.
    let value = unsafe { GetWindowLongPtrW(window, GWLP_USERDATA) };
    let address = usize::try_from(value).ok()?;
    if address == 0 {
        return None;
    }
    let pointer = core::ptr::with_exposed_provenance::<WindowSecretContext>(address);
    // SAFETY: `attach_secret_state` installed this exact stable Box pointer and
    // NativeSurface keeps the Box alive through all window-procedure calls.
    Some(unsafe { &*pointer })
}

const fn is_blocked_secret_message(message: u32) -> bool {
    matches!(
        message,
        WM_GETTEXT
            | WM_GETTEXTLENGTH
            | WM_GETOBJECT
            | WM_PRINT
            | WM_PRINTCLIENT
            | WM_COPY
            | WM_CUT
            | WM_PASTE
            | WM_CLEAR
            | WM_UNDO
            | WM_CONTEXTMENU
            | WM_DROPFILES
            | WM_RBUTTONDOWN
            | WM_RBUTTONUP
            | WM_MBUTTONDOWN
            | WM_MBUTTONUP
            | WM_IME_STARTCOMPOSITION
            | WM_IME_COMPOSITION
            | WM_IME_ENDCOMPOSITION
            | WM_IME_CHAR
            | WM_IME_KEYDOWN
            | WM_IME_KEYUP
    )
}

const fn blocks_window_message(message: u32, secret_state_attached: bool) -> bool {
    is_blocked_secret_message(message) || (secret_state_attached && message == WM_SETTEXT)
}

fn focus_target_is_foreign(window: HWND, lparam: LPARAM) -> bool {
    let Ok(address) = usize::try_from(lparam.0) else {
        return true;
    };
    let next = HWND(core::ptr::with_exposed_provenance_mut(address));
    // SAFETY: This only queries the live top-level window's child relationship.
    next.is_invalid() || (next != window && !unsafe { IsChild(window, next) }.as_bool())
}

// SAFETY: The only stored pointer is the Box owned by NativeSurface and its
// lifetime strictly encloses the HWND lifetime. Secret extraction, printing,
// clipboard, context-menu, drag/drop, accessibility, and IME messages are
// rejected; the procedure never delegates secret text to an OS control.
unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_MOUSEACTIVATE && foreground_window() != window {
        return LRESULT(isize::try_from(MA_ACTIVATEANDEAT).unwrap_or(2));
    }
    let context = window_secret_context(window);
    if blocks_window_message(message, context.is_some()) {
        return LRESULT(0);
    }
    if matches!(message, WM_KEYDOWN | WM_SYSKEYDOWN | WM_CHAR) {
        // SAFETY: These calls only query current keyboard state.
        let control_down = unsafe { GetKeyState(i32::from(VK_CONTROL.0)) } < 0;
        // SAFETY: Same read-only input-state query.
        let shift_down = unsafe { GetKeyState(i32::from(VK_SHIFT.0)) } < 0;
        let key = u16::try_from(wparam.0).unwrap_or(u16::MAX);
        if control_down || (shift_down && key == VK_INSERT.0) {
            return LRESULT(0);
        }
    }
    match message {
        WM_PAINT => {
            let Some(context) = context else {
                // SAFETY: No secret state is attached during hidden creation.
                return unsafe { DefWindowProcW(window, message, wparam, lparam) };
            };
            let Ok(state) = context.state.try_borrow() else {
                context.fail_closed(window);
                return LRESULT(0);
            };
            let result = state.paint(window);
            drop(state);
            if result.is_err() {
                context.fail_closed(window);
            }
            LRESULT(0)
        }
        WM_CHAR => {
            if let Some(context) = context {
                context.handle_character(window, wparam);
            }
            LRESULT(0)
        }
        WM_LBUTTONDOWN => {
            if let Some(context) = context
                && context.activate_at(window, lparam)
            {
                // SAFETY: The custom editor is the live top-level window.
                let _ = unsafe { SetFocus(Some(window)) };
                // SAFETY: This only reads the UI thread's focus HWND.
                if unsafe { GetFocus() } != window {
                    context.fail_closed(window);
                }
            }
            LRESULT(0)
        }
        WM_ACTIVATEAPP if wparam.0 == 0 => {
            if let Some(context) = context {
                context.fail_closed(window);
            }
            LRESULT(0)
        }
        WM_KILLFOCUS if focus_target_is_foreign(window, lparam) => {
            if let Some(context) = context {
                context.fail_closed(window);
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            // SAFETY: The OS supplied this live HWND; posting never borrows data.
            let _ = unsafe { PostMessageW(Some(window), WM_RECOVERY_CANCEL, WPARAM(0), LPARAM(0)) };
            LRESULT(0)
        }
        WM_DESTROY => {
            // SAFETY: Posting quit retains no pointer and ends this one-shot loop.
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        WM_NCDESTROY => {
            // SAFETY: Clear the borrowed pointer before the HWND ceases to exist;
            // NativeSurface retains and later drops the owning Box.
            unsafe {
                let _ = SetWindowLongPtrW(window, GWLP_USERDATA, 0);
                DefWindowProcW(window, message, wparam, lparam)
            }
        }
        _ => {
            // SAFETY: Unhandled messages are delegated unchanged.
            unsafe { DefWindowProcW(window, message, wparam, lparam) }
        }
    }
}

#[cfg(test)]
mod tests {
    use windows::Win32::Foundation::{HWND, LPARAM, RECT, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{
        MSG, WM_ACTIVATEAPP, WM_CONTEXTMENU, WM_COPY, WM_CUT, WM_DROPFILES, WM_GETOBJECT,
        WM_GETTEXT, WM_GETTEXTLENGTH, WM_KILLFOCUS, WM_PASTE, WM_PRINT, WM_PRINTCLIENT, WM_SETTEXT,
        WM_TIMER,
    };

    use super::{
        ACKNOWLEDGEMENT_HOLD_MS, ADDRESS_FIELD, CHALLENGE_WORDS, CONFIRM_FIELDS,
        ConfirmSecretState, HoldGate, HoldSource, InputKind, SESSION_TIMEOUT_MS, SecureAsciiBuffer,
        blocks_window_message, format_address, is_blocked_secret_message, key_is_repeat,
        parse_address, session_must_cancel,
    };

    #[test]
    fn acknowledgement_requires_one_continuous_two_second_hold() {
        let mut gate = HoldGate::default();
        gate.begin(HoldSource::Pointer, 100);
        assert!(!gate.complete(100 + ACKNOWLEDGEMENT_HOLD_MS - 1));
        gate.cancel();
        gate.begin(HoldSource::Pointer, 1_000);
        gate.begin(HoldSource::Pointer, 2_999);
        assert!(!gate.complete(2_999));
        assert!(gate.complete(3_000));
        assert!(key_is_repeat(LPARAM(1_isize << 30)));
        assert!(!key_is_repeat(LPARAM(0)));
    }

    #[test]
    fn custom_ascii_buffers_are_bounded_and_never_need_window_text() {
        let mut word = SecureAsciiBuffer::new(InputKind::Word, 8)
            .unwrap_or_else(|_| unreachable!("headless buffer"));
        assert!(word.push(b'a'));
        assert!(!word.push(b'A'));
        assert!(word.backspace());
        assert!(word.as_str().is_ok_and(str::is_empty));
        assert_eq!(word.bytes.capacity(), 8);

        let mut address = SecureAsciiBuffer::new(InputKind::Address, 42)
            .unwrap_or_else(|_| unreachable!("headless buffer"));
        assert!(!address.push(b'1'));
        assert!(address.push(b'0'));
        assert!(!address.push(b'X'));
        assert!(address.push(b'x'));
        for byte in b"abcdef0123456789" {
            assert!(address.push(*byte));
        }
        assert_eq!(address.bytes.capacity(), 42);
    }

    #[test]
    fn headless_confirmation_state_collects_only_owned_zeroizing_buffers() {
        let rectangles = core::array::from_fn(|index| RECT {
            left: i32::try_from(index).unwrap_or(i32::MAX) * 10,
            top: 0,
            right: i32::try_from(index).unwrap_or(i32::MAX) * 10 + 9,
            bottom: 9,
        });
        let mut state =
            ConfirmSecretState::new(rectangles).unwrap_or_else(|_| unreachable!("headless state"));
        for (index, word) in ["apple", "breeze", "cedar", "dune"].into_iter().enumerate() {
            state.active = index;
            for byte in word.bytes() {
                assert!(state.handle_character(byte));
            }
        }
        state.active = ADDRESS_FIELD;
        for byte in b"0x4242424242424242424242424242424242424242" {
            assert!(state.handle_character(*byte));
        }
        let confirmation = state
            .confirmation()
            .unwrap_or_else(|_| unreachable!("valid headless confirmation"));
        let (words, address) = confirmation.into_parts();
        assert_eq!(words.len(), CHALLENGE_WORDS);
        assert_eq!(words[0].as_str(), "apple");
        assert_eq!(address, [0x42; 20]);
        assert_eq!(state.fields.len(), CONFIRM_FIELDS);
    }

    #[test]
    fn extraction_accessibility_print_and_clipboard_messages_are_blocked_headlessly() {
        for message in [
            WM_GETTEXT,
            WM_GETTEXTLENGTH,
            WM_GETOBJECT,
            WM_PRINT,
            WM_PRINTCLIENT,
            WM_COPY,
            WM_CUT,
            WM_PASTE,
            WM_CONTEXTMENU,
            WM_DROPFILES,
        ] {
            assert!(is_blocked_secret_message(message));
            assert!(blocks_window_message(message, true));
        }
        assert!(blocks_window_message(WM_SETTEXT, true));
        assert!(!blocks_window_message(WM_SETTEXT, false));
        assert!(!is_blocked_secret_message(WM_TIMER));
    }

    #[test]
    fn address_parser_requires_a_full_prefixed_twenty_byte_value() {
        let address = [0xabu8; 20];
        let text = format_address(address).unwrap_or_else(|_| unreachable!("format"));
        assert_eq!(parse_address(&text), Some(address));
        assert!(parse_address(&text[2..]).is_none());
        assert!(parse_address("0x12").is_none());
        assert!(parse_address("0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_none());
    }

    #[test]
    fn timeout_app_loss_and_focus_loss_cancel_without_presenting_ui() {
        let mut message = MSG::default();
        assert!(session_must_cancel(
            HWND::default(),
            &message,
            SESSION_TIMEOUT_MS
        ));
        message.message = WM_ACTIVATEAPP;
        message.wParam = WPARAM(0);
        assert!(session_must_cancel(HWND::default(), &message, 0));
        message.message = WM_KILLFOCUS;
        message.lParam = LPARAM(0);
        assert!(session_must_cancel(HWND::default(), &message, 0));
    }
}
