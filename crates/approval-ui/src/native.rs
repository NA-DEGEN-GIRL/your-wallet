//! Raw Win32 one-shot approval surface.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{COLOR_WINDOW, GetSysColorBrush, ScreenToClient, UpdateWindow};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{EM_SCROLLCARET, EM_SETLIMITTEXT, EM_SETSEL};
use windows::Win32::UI::HiDpi::{
    AdjustWindowRectExForDpi, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForSystem,
    SetProcessDpiAwarenessContext,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, GetCapture, GetFocus, ReleaseCapture, SetCapture, SetFocus, VK_ESCAPE,
    VK_LBUTTON, VK_RETURN, VK_SPACE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    BS_MULTILINE, BS_PUSHBUTTON, CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DefWindowProcW,
    DestroyWindow, DispatchMessageW, ES_AUTOVSCROLL, ES_MULTILINE, ES_READONLY, GetClientRect,
    GetForegroundWindow, GetMessageW, GetWindowTextLengthW, IDC_ARROW, IsChild, IsDialogMessageW,
    KillTimer, LoadCursorW, MA_ACTIVATEANDEAT, MSG, PostQuitMessage, RegisterClassW,
    SPI_GETWORKAREA, SW_SHOWNORMAL, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS, SendMessageW,
    SetForegroundWindow, SetTimer, SetWindowTextW, ShowWindow, SystemParametersInfoW,
    TranslateMessage, WINDOW_EX_STYLE, WINDOW_STYLE, WM_ACTIVATEAPP, WM_CANCELMODE,
    WM_CAPTURECHANGED, WM_CLOSE, WM_DESTROY, WM_KEYDOWN, WM_KEYUP, WM_KILLFOCUS, WM_LBUTTONDOWN,
    WM_LBUTTONUP, WM_MOUSEACTIVATE, WM_MOUSEMOVE, WM_TIMER, WNDCLASSW, WS_BORDER, WS_CAPTION,
    WS_CHILD, WS_CLIPCHILDREN, WS_EX_APPWINDOW, WS_EX_CLIENTEDGE, WS_EX_CONTROLPARENT,
    WS_EX_DLGMODALFRAME, WS_MINIMIZEBOX, WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
    WS_VSCROLL,
};
use windows::core::{PCWSTR, w};

use super::{
    ApprovalError, ApprovalInteraction, ApprovalRequest, Decision, HoldSource, InteractionEvent,
    InteractionStatus, RiskLevel, render_plain_text,
};

const TIMER_ID: usize = 1;
const TIMER_INTERVAL_MS: u32 = 50;
const BASE_DPI: i32 = 96;
const CLIENT_WIDTH: i32 = 820;
const CLIENT_HEIGHT: i32 = 710;
const MINIMUM_CLIENT_WIDTH: i32 = 520;
const MINIMUM_CLIENT_HEIGHT: i32 = 460;
const MARGIN: i32 = 20;
const PHRASE_TOP: i32 = 18;
const PHRASE_HEIGHT: i32 = 46;
const NOTICE_TOP: i32 = 70;
const NOTICE_HEIGHT: i32 = 54;
const DETAILS_TOP: i32 = 132;
const STATUS_HEIGHT: i32 = 48;
const BUTTON_WIDTH: i32 = 220;
const BUTTON_HEIGHT: i32 = 40;
const VERTICAL_GAP: i32 = 10;
const CLASS_NAME: PCWSTR = w!("YourWalletApprovalV2");

static PRESENTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
struct NativeControls {
    window: HWND,
    status: HWND,
    reject: HWND,
    approve: HWND,
}

pub(super) fn present(request: &ApprovalRequest) -> Result<Decision, ApprovalError> {
    let title = format!(
        "Your Wallet — {} — signed approval helper",
        request.anti_phishing_phrase()
    );
    present_with_title(request, &title)
}

#[cfg(all(
    target_arch = "x86_64",
    target_env = "msvc",
    debug_assertions,
    feature = "service-helper-rpc-probe-feasibility-test-hook"
))]
pub(super) fn present_service_probe(request: &ApprovalRequest) -> Result<Decision, ApprovalError> {
    present_with_title(request, "Service transport test — no signing")
}

fn present_with_title(request: &ApprovalRequest, title: &str) -> Result<Decision, ApprovalError> {
    if PRESENTED.swap(true, Ordering::AcqRel) {
        return Ok(Decision::Reject);
    }

    // SAFETY: This is a dedicated one-shot helper process in the intended
    // deployment. Failure only affects sizing and is safe to ignore.
    let _ = unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    let controls = create_window(request, title)?;
    run_loop(request, &controls)
}

#[allow(clippy::too_many_lines)]
fn create_window(request: &ApprovalRequest, title: &str) -> Result<NativeControls, ApprovalError> {
    let body = render_plain_text(request)?;
    let phrase = format!(
        "Anti-phishing phrase: {}\r\nMatch this phrase before reviewing the request.",
        request.anti_phishing_phrase()
    );
    let notice = match request.display().risk() {
        RiskLevel::Standard => {
            "Approval has no default action. Review every exact field, then explicitly approve or reject."
        }
        RiskLevel::High => {
            "HIGH RISK. Review every exact field, then continuously hold the approval control for 2 seconds."
        }
    };

    // SAFETY: A null module name requests the current executable module.
    let module = unsafe { GetModuleHandleW(None) }.map_err(win_error)?;
    let instance = HINSTANCE(module.0);
    // SAFETY: Loading the process-independent system arrow cursor needs no
    // caller-owned backing storage.
    let cursor = unsafe { LoadCursorW(None, IDC_ARROW) }.map_err(win_error)?;
    // SAFETY: This returns a system-owned brush that must not be deleted.
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
    // SAFETY: `class` and its static class-name pointer remain valid for this
    // synchronous registration call.
    if unsafe { RegisterClassW(&raw const class) } == 0 {
        return Err(last_error());
    }

    // SAFETY: The process DPI value has no borrowed lifetime.
    let dpi = i32::try_from(unsafe { GetDpiForSystem() }).map_err(|_| ApprovalError::Malformed)?;
    if !(48..=768).contains(&dpi) {
        return Err(ApprovalError::Malformed);
    }
    let window_style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN;
    let window_ex_style = WS_EX_APPWINDOW | WS_EX_CONTROLPARENT | WS_EX_DLGMODALFRAME;
    let layout = Layout::for_work_area(dpi, window_style, window_ex_style)?;
    let title_wide = wide(title);
    // SAFETY: Class name is static and title is NUL-terminated and live for the
    // call. No untrusted pointer is retained by our window procedure.
    let window = unsafe {
        CreateWindowExW(
            window_ex_style,
            CLASS_NAME,
            PCWSTR(title_wide.as_ptr()),
            window_style,
            layout.window.x,
            layout.window.y,
            layout.window.width,
            layout.window.height,
            None,
            None,
            Some(instance),
            None,
        )
    }
    .map_err(win_error)?;

    let phrase_control = create_control(
        window,
        instance,
        w!("STATIC"),
        &phrase,
        WS_CHILD | WS_VISIBLE,
        WINDOW_EX_STYLE(0),
        layout.phrase,
    )?;
    let notice_control = create_control(
        window,
        instance,
        w!("STATIC"),
        notice,
        WS_CHILD | WS_VISIBLE,
        WINDOW_EX_STYLE(0),
        layout.notice,
    )?;
    let details = create_control(
        window,
        instance,
        w!("EDIT"),
        "",
        WS_CHILD
            | WS_VISIBLE
            | WS_BORDER
            | WS_VSCROLL
            | WS_TABSTOP
            | style(ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL),
        WS_EX_CLIENTEDGE,
        layout.details,
    )?;
    let status = create_control(
        window,
        instance,
        w!("STATIC"),
        "Preparing trusted countdown…",
        WS_CHILD | WS_VISIBLE,
        WINDOW_EX_STYLE(0),
        layout.status,
    )?;
    let reject = create_control(
        window,
        instance,
        w!("BUTTON"),
        "Reject (Esc)",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | style(BS_PUSHBUTTON | BS_MULTILINE),
        WINDOW_EX_STYLE(0),
        layout.reject,
    )?;
    let approve = create_control(
        window,
        instance,
        w!("BUTTON"),
        "Approve exact request",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | style(BS_PUSHBUTTON | BS_MULTILINE),
        WINDOW_EX_STYLE(0),
        layout.approve,
    )?;

    let body_wide = wide(&body);
    let body_units = body_wide.len().saturating_sub(1);
    // SAFETY: The edit control belongs to this thread. The limit is raised
    // before assigning text so every UTF-16 unit can be retained.
    unsafe {
        SendMessageW(
            details,
            EM_SETLIMITTEXT,
            Some(WPARAM(body_units.saturating_add(1))),
            Some(LPARAM(0)),
        );
        SetWindowTextW(details, PCWSTR(body_wide.as_ptr()))
    }
    .map_err(win_error)?;
    // SAFETY: `details` is a live edit control created above.
    let assigned_units = unsafe { GetWindowTextLengthW(details) };
    if assigned_units < 0
        || usize::try_from(assigned_units).map_err(|_| ApprovalError::Malformed)? != body_units
    {
        return Err(ApprovalError::Malformed);
    }
    // SAFETY: The edit is live and read-only. Moving its zero-length selection
    // to the beginning guarantees the first exact fields, not the tail, are
    // initially visible; all remaining content stays reachable by scrolling.
    unsafe {
        SendMessageW(details, EM_SETSEL, Some(WPARAM(0)), Some(LPARAM(0)));
        SendMessageW(details, EM_SCROLLCARET, Some(WPARAM(0)), Some(LPARAM(0)));
    }

    let _ = (phrase_control, notice_control);
    // SAFETY: All handles are live controls on this UI thread.
    unsafe {
        let _ = ShowWindow(window, SW_SHOWNORMAL);
        let _ = UpdateWindow(window);
        let _ = SetForegroundWindow(window);
        let _ = SetFocus(Some(reject));
    }

    Ok(NativeControls {
        window,
        status,
        reject,
        approve,
    })
}

fn run_loop(
    request: &ApprovalRequest,
    controls: &NativeControls,
) -> Result<Decision, ApprovalError> {
    let started = Instant::now();
    let mut interaction = ApprovalInteraction::new(
        request.display().risk(),
        request.expires_after_milliseconds(),
        0,
    )?;
    update_status(request, controls, &interaction, 0)?;
    // SAFETY: The timer is associated with a live UI-thread window and sends
    // `WM_TIMER`; no callback pointer is supplied.
    if unsafe { SetTimer(Some(controls.window), TIMER_ID, TIMER_INTERVAL_MS, None) } == 0 {
        destroy(controls.window);
        return Err(last_error());
    }

    let mut decision = Decision::Reject;
    let mut deferred_error = None;
    loop {
        let mut message = MSG::default();
        // SAFETY: `message` points to initialized writable storage and all
        // messages for this thread are accepted.
        let result = unsafe { GetMessageW(&raw mut message, None, 0, 0) }.0;
        if result == -1 {
            deferred_error = Some(last_error());
            break;
        }
        if result == 0 {
            break;
        }
        let now_ms = elapsed_milliseconds(started);
        let handled = handle_message(request, controls, &mut interaction, &message, now_ms)?;
        match interaction.status() {
            InteractionStatus::Approved => {
                decision = Decision::Approve;
                destroy(controls.window);
                break;
            }
            InteractionStatus::Rejected => {
                destroy(controls.window);
                break;
            }
            InteractionStatus::Pending => {}
        }
        if handled {
            continue;
        }
        // SAFETY: `message` came from `GetMessageW`. Dialog translation enables
        // keyboard traversal among native controls without a default button.
        if !unsafe { IsDialogMessageW(controls.window, &raw const message) }.as_bool() {
            // SAFETY: The message remains initialized for these synchronous
            // calls, and dispatch targets its original live HWND.
            unsafe {
                let _ = TranslateMessage(&raw const message);
                DispatchMessageW(&raw const message);
            }
        }
    }

    // SAFETY: Killing an already-removed window timer is harmless; errors are
    // ignored because the window is closing and rejection is already default.
    let _ = unsafe { KillTimer(Some(controls.window), TIMER_ID) };
    if let Some(error) = deferred_error {
        return Err(error);
    }
    Ok(decision)
}

fn handle_message(
    request: &ApprovalRequest,
    controls: &NativeControls,
    interaction: &mut ApprovalInteraction,
    message: &MSG,
    now_ms: u64,
) -> Result<bool, ApprovalError> {
    match message.message {
        WM_TIMER if message.hwnd == controls.window && message.wParam.0 == TIMER_ID => {
            validate_live_hold(controls, interaction, now_ms);
            interaction.apply(now_ms, InteractionEvent::Tick);
            update_status(request, controls, interaction, now_ms)?;
            Ok(true)
        }
        WM_LBUTTONDOWN if message.hwnd == controls.approve => {
            // SAFETY: This only queries current physical pointer-button state.
            let physical_down = unsafe { GetAsyncKeyState(i32::from(VK_LBUTTON.0)) } < 0;
            let click_through = foreground_window() != controls.window;
            // SAFETY: The approval control is live on this UI thread.
            unsafe {
                let _ = SetFocus(Some(controls.approve));
                SetCapture(controls.approve);
            }
            interaction.apply(
                now_ms,
                InteractionEvent::PointerPressed {
                    inside: point_inside(controls.approve, message.lParam),
                    click_through,
                    physical_down,
                },
            );
            update_status(request, controls, interaction, now_ms)?;
            Ok(false)
        }
        WM_MOUSEMOVE if message.hwnd == controls.approve => {
            interaction.apply(
                now_ms,
                InteractionEvent::PointerMoved {
                    inside: point_inside(controls.approve, message.lParam),
                },
            );
            if interaction.hold_source() != Some(HoldSource::Pointer) {
                release_capture_if_owned(controls.approve);
            }
            update_status(request, controls, interaction, now_ms)?;
            Ok(false)
        }
        WM_LBUTTONUP if message.hwnd == controls.approve => {
            if point_inside(controls.approve, message.lParam) {
                // SAFETY: This only queries current physical pointer-button state.
                let physical_down = unsafe { GetAsyncKeyState(i32::from(VK_LBUTTON.0)) } < 0;
                interaction.apply(now_ms, InteractionEvent::PointerReleased { physical_down });
            } else {
                interaction.apply(now_ms, InteractionEvent::PointerMoved { inside: false });
            }
            release_capture_if_owned(controls.approve);
            update_status(request, controls, interaction, now_ms)?;
            Ok(false)
        }
        WM_LBUTTONUP if message.hwnd == controls.reject => {
            if point_inside(controls.reject, message.lParam) {
                interaction.apply(now_ms, InteractionEvent::RejectActivated);
            }
            Ok(false)
        }
        WM_KEYDOWN => handle_key_down(request, controls, interaction, message, now_ms),
        WM_KEYUP => handle_key_up(request, controls, interaction, message, now_ms),
        WM_ACTIVATEAPP if message.wParam.0 == 0 => {
            interaction.apply(now_ms, InteractionEvent::ForegroundLost);
            update_status(request, controls, interaction, now_ms)?;
            Ok(false)
        }
        WM_KILLFOCUS => {
            interaction.apply(now_ms, InteractionEvent::FocusLost);
            update_status(request, controls, interaction, now_ms)?;
            Ok(false)
        }
        WM_CAPTURECHANGED => {
            interaction.apply(now_ms, InteractionEvent::CaptureLost);
            update_status(request, controls, interaction, now_ms)?;
            Ok(false)
        }
        WM_CANCELMODE => {
            interaction.apply(now_ms, InteractionEvent::CancelMode);
            update_status(request, controls, interaction, now_ms)?;
            Ok(false)
        }
        WM_CLOSE if message.hwnd == controls.window => {
            interaction.apply(now_ms, InteractionEvent::RejectActivated);
            Ok(false)
        }
        _ => Ok(false),
    }
}

fn handle_key_down(
    request: &ApprovalRequest,
    controls: &NativeControls,
    interaction: &mut ApprovalInteraction,
    message: &MSG,
    now_ms: u64,
) -> Result<bool, ApprovalError> {
    let key = u16::try_from(message.wParam.0).unwrap_or(u16::MAX);
    if key == VK_ESCAPE.0 {
        interaction.apply(now_ms, InteractionEvent::RejectActivated);
        return Ok(true);
    }
    if message.hwnd == controls.reject && key == VK_RETURN.0 {
        interaction.apply(now_ms, InteractionEvent::RejectActivated);
        return Ok(true);
    }
    if message.hwnd != controls.approve {
        return Ok(false);
    }
    if key == VK_RETURN.0 {
        if request.display().risk() == RiskLevel::Standard && !key_is_repeat(message.lParam) {
            interaction.apply(now_ms, InteractionEvent::ApproveActivated);
        }
        return Ok(true);
    }
    if key == VK_SPACE.0 {
        // SAFETY: This only queries current physical keyboard state.
        let physical_down = unsafe { GetAsyncKeyState(i32::from(VK_SPACE.0)) } < 0;
        interaction.apply(
            now_ms,
            InteractionEvent::SpacePressed {
                repeat: key_is_repeat(message.lParam),
                physical_down,
            },
        );
        update_status(request, controls, interaction, now_ms)?;
    }
    Ok(false)
}

fn handle_key_up(
    request: &ApprovalRequest,
    controls: &NativeControls,
    interaction: &mut ApprovalInteraction,
    message: &MSG,
    now_ms: u64,
) -> Result<bool, ApprovalError> {
    let key = u16::try_from(message.wParam.0).unwrap_or(u16::MAX);
    if message.hwnd == controls.reject && key == VK_SPACE.0 {
        interaction.apply(now_ms, InteractionEvent::RejectActivated);
        return Ok(false);
    }
    if message.hwnd != controls.approve || key != VK_SPACE.0 {
        return Ok(false);
    }
    // SAFETY: This only queries current physical keyboard state.
    let physical_down = unsafe { GetAsyncKeyState(i32::from(VK_SPACE.0)) } < 0;
    interaction.apply(now_ms, InteractionEvent::SpaceReleased { physical_down });
    update_status(request, controls, interaction, now_ms)?;
    Ok(false)
}

fn validate_live_hold(
    controls: &NativeControls,
    interaction: &mut ApprovalInteraction,
    now_ms: u64,
) {
    // SAFETY: These calls only query thread/global input state and live HWNDs.
    let foreground = unsafe { GetForegroundWindow() };
    if foreground != controls.window {
        interaction.apply(now_ms, InteractionEvent::ForegroundLost);
        return;
    }
    // SAFETY: `GetFocus` returns this UI thread's current focus HWND.
    let focus = unsafe { GetFocus() };
    // SAFETY: Both handles, when non-null, are live windows on this thread.
    let focus_is_in_window = focus == controls.window
        || focus == controls.approve
        || unsafe { IsChild(controls.window, focus) }.as_bool();
    if !focus_is_in_window || (interaction.hold_source().is_some() && focus != controls.approve) {
        interaction.apply(now_ms, InteractionEvent::FocusLost);
        return;
    }

    if interaction.hold_source() == Some(HoldSource::Pointer) {
        // SAFETY: Input-state and capture queries do not borrow caller memory.
        let down = unsafe { GetAsyncKeyState(i32::from(VK_LBUTTON.0)) } < 0;
        // SAFETY: This only queries capture state for the UI thread.
        let captured = unsafe { GetCapture() } == controls.approve;
        if !down {
            interaction.apply(
                now_ms,
                InteractionEvent::PointerReleased {
                    physical_down: false,
                },
            );
        } else if !captured {
            interaction.apply(now_ms, InteractionEvent::CaptureLost);
        } else if !cursor_inside(controls.approve) {
            interaction.apply(now_ms, InteractionEvent::PointerMoved { inside: false });
            release_capture_if_owned(controls.approve);
        }
    }
    if interaction.hold_source() == Some(HoldSource::Space) {
        // SAFETY: This only queries physical keyboard state.
        let down = unsafe { GetAsyncKeyState(i32::from(VK_SPACE.0)) } < 0;
        if !down || focus != controls.approve {
            interaction.apply(now_ms, InteractionEvent::FocusLost);
        }
    }

    if interaction.is_blocked(HoldSource::Pointer) {
        // SAFETY: This only queries physical pointer-button state.
        if unsafe { GetAsyncKeyState(i32::from(VK_LBUTTON.0)) } >= 0 {
            interaction.apply(
                now_ms,
                InteractionEvent::PointerReleased {
                    physical_down: false,
                },
            );
        }
    }
    if interaction.is_blocked(HoldSource::Space) {
        // SAFETY: This only queries physical keyboard state.
        if unsafe { GetAsyncKeyState(i32::from(VK_SPACE.0)) } >= 0 {
            interaction.apply(
                now_ms,
                InteractionEvent::SpaceReleased {
                    physical_down: false,
                },
            );
        }
    }
}

fn update_status(
    request: &ApprovalRequest,
    controls: &NativeControls,
    interaction: &ApprovalInteraction,
    now_ms: u64,
) -> Result<(), ApprovalError> {
    let lifetime_seconds = interaction
        .lifetime_remaining_ms(now_ms)
        .saturating_add(999)
        / 1_000;
    let (status, approve_label) = match request.display().risk() {
        RiskLevel::Standard => (
            format!("No default approval. This prompt expires in {lifetime_seconds} seconds."),
            "Approve exact request".to_owned(),
        ),
        RiskLevel::High => {
            if let Some(remaining) = interaction.hold_remaining_ms(now_ms) {
                let whole = remaining / 1_000;
                let tenth = (remaining % 1_000) / 100;
                (
                    format!(
                        "Keep holding continuously. {whole}.{tenth} seconds remain; prompt expires in {lifetime_seconds} seconds."
                    ),
                    format!("Keep holding — {whole}.{tenth} s"),
                )
            } else if interaction.is_blocked(HoldSource::Pointer)
                || interaction.is_blocked(HoldSource::Space)
            {
                (
                    format!(
                        "Release the held input before trying again. Prompt expires in {lifetime_seconds} seconds."
                    ),
                    "Release, then hold for 2 seconds".to_owned(),
                )
            } else {
                (
                    format!(
                        "High risk: hold the button or Space continuously for 2 seconds. Prompt expires in {lifetime_seconds} seconds."
                    ),
                    "Hold to approve — 2.0 s".to_owned(),
                )
            }
        }
    };
    set_text(controls.status, &status)?;
    set_text(controls.approve, &approve_label)
}

fn create_control(
    parent: HWND,
    instance: HINSTANCE,
    class: PCWSTR,
    text: &str,
    window_style: WINDOW_STYLE,
    ex_style: WINDOW_EX_STYLE,
    rect: RectSpec,
) -> Result<HWND, ApprovalError> {
    let text_wide = wide(text);
    // SAFETY: Class is a static system class. Text is NUL-terminated and lives
    // through the call. Parent and instance are live handles owned by this UI.
    unsafe {
        CreateWindowExW(
            ex_style,
            class,
            PCWSTR(text_wide.as_ptr()),
            window_style,
            rect.x,
            rect.y,
            rect.width,
            rect.height,
            Some(parent),
            None,
            Some(instance),
            None,
        )
    }
    .map_err(win_error)
}

fn set_text(control: HWND, text: &str) -> Result<(), ApprovalError> {
    let wide = wide(text);
    // SAFETY: `control` is live and `wide` is NUL-terminated for this call.
    unsafe { SetWindowTextW(control, PCWSTR(wide.as_ptr())) }.map_err(win_error)
}

fn point_inside(control: HWND, lparam: LPARAM) -> bool {
    let packed = lparam.0.to_le_bytes();
    let x = i32::from(i16::from_le_bytes([packed[0], packed[1]]));
    let y = i32::from(i16::from_le_bytes([packed[2], packed[3]]));
    let mut rectangle = RECT::default();
    // SAFETY: `rectangle` is writable and `control` is live.
    unsafe { GetClientRect(control, &raw mut rectangle) }.is_ok()
        && x >= rectangle.left
        && y >= rectangle.top
        && x < rectangle.right
        && y < rectangle.bottom
}

fn cursor_inside(control: HWND) -> bool {
    let mut point = POINT::default();
    let mut rectangle = RECT::default();
    // SAFETY: Both output structures are initialized writable storage and the
    // control handle is live. Failure is treated as outside/reset.
    // SAFETY: Both output structures are initialized writable storage and the
    // control handle is live for these synchronous calls.
    let cursor_result =
        unsafe { windows::Win32::UI::WindowsAndMessaging::GetCursorPos(&raw mut point) };
    // SAFETY: `point` is initialized and writable; `control` is live.
    let client_result = unsafe { ScreenToClient(control, &raw mut point) };
    // SAFETY: `rectangle` is initialized writable storage; `control` is live.
    let rectangle_result = unsafe { GetClientRect(control, &raw mut rectangle) };
    if cursor_result.is_err() || !client_result.as_bool() || rectangle_result.is_err() {
        return false;
    }
    point.x >= rectangle.left
        && point.y >= rectangle.top
        && point.x < rectangle.right
        && point.y < rectangle.bottom
}

fn release_capture_if_owned(control: HWND) {
    // SAFETY: Capture is thread-local state and no borrowed memory is involved.
    if unsafe { GetCapture() } == control {
        // SAFETY: Releasing capture is valid after a successful `SetCapture`.
        let _ = unsafe { ReleaseCapture() };
    }
}

fn destroy(window: HWND) {
    release_capture_if_owned(window);
    // SAFETY: The handle was created by this module. Destruction is one-shot;
    // an already-destroyed handle merely fails and rejection remains default.
    let _ = unsafe { DestroyWindow(window) };
}

fn elapsed_milliseconds(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

const fn key_is_repeat(lparam: LPARAM) -> bool {
    lparam.0 & (1_isize << 30) != 0
}

const fn scale(value: i32, dpi: i32) -> i32 {
    value.saturating_mul(dpi) / BASE_DPI
}

const fn style(value: i32) -> WINDOW_STYLE {
    WINDOW_STYLE(u32::from_ne_bytes(value.to_ne_bytes()))
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

fn last_error() -> ApprovalError {
    ApprovalError::Io(io::Error::last_os_error())
}

#[allow(clippy::needless_pass_by_value)]
fn win_error(error: windows::core::Error) -> ApprovalError {
    ApprovalError::Io(io::Error::from_raw_os_error(error.code().0))
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
}

#[derive(Debug)]
struct Layout {
    window: RectSpec,
    phrase: RectSpec,
    notice: RectSpec,
    details: RectSpec,
    status: RectSpec,
    reject: RectSpec,
    approve: RectSpec,
}

impl Layout {
    fn for_work_area(
        dpi: i32,
        window_style: WINDOW_STYLE,
        ex_style: WINDOW_EX_STYLE,
    ) -> Result<Self, ApprovalError> {
        let mut work_area = RECT::default();
        // SAFETY: `work_area` is initialized writable storage. This read-only
        // system query does not retain the pointer.
        unsafe {
            SystemParametersInfoW(
                SPI_GETWORKAREA,
                0,
                Some((&raw mut work_area).cast()),
                SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
            )
        }
        .map_err(win_error)?;
        Self::for_rectangle(work_area, dpi, window_style, ex_style)
    }

    #[allow(clippy::too_many_lines)]
    fn for_rectangle(
        work_area: RECT,
        dpi: i32,
        window_style: WINDOW_STYLE,
        ex_style: WINDOW_EX_STYLE,
    ) -> Result<Self, ApprovalError> {
        let work_width = work_area
            .right
            .checked_sub(work_area.left)
            .ok_or(ApprovalError::Malformed)?;
        let work_height = work_area
            .bottom
            .checked_sub(work_area.top)
            .ok_or(ApprovalError::Malformed)?;
        let screen_margin = scale(16, dpi);
        let available_outer_width = work_width
            .checked_sub(screen_margin.saturating_mul(2))
            .ok_or(ApprovalError::Malformed)?;
        let available_outer_height = work_height
            .checked_sub(screen_margin.saturating_mul(2))
            .ok_or(ApprovalError::Malformed)?;

        let desired_client_width = scale(CLIENT_WIDTH, dpi);
        let desired_client_height = scale(CLIENT_HEIGHT, dpi);
        let desired_outer = adjusted_outer(
            desired_client_width,
            desired_client_height,
            dpi,
            window_style,
            ex_style,
        )?;
        let desired_outer_width = rect_width(desired_outer)?;
        let desired_outer_height = rect_height(desired_outer)?;
        let frame_width = desired_outer_width
            .checked_sub(desired_client_width)
            .ok_or(ApprovalError::Malformed)?;
        let frame_height = desired_outer_height
            .checked_sub(desired_client_height)
            .ok_or(ApprovalError::Malformed)?;
        let client_width = desired_client_width.min(
            available_outer_width
                .checked_sub(frame_width)
                .ok_or(ApprovalError::Malformed)?,
        );
        let client_height = desired_client_height.min(
            available_outer_height
                .checked_sub(frame_height)
                .ok_or(ApprovalError::Malformed)?,
        );
        if client_width < scale(MINIMUM_CLIENT_WIDTH, dpi)
            || client_height < scale(MINIMUM_CLIENT_HEIGHT, dpi)
        {
            return Err(ApprovalError::Malformed);
        }

        let actual_outer =
            adjusted_outer(client_width, client_height, dpi, window_style, ex_style)?;
        let outer_width = rect_width(actual_outer)?;
        let outer_height = rect_height(actual_outer)?;
        let window_x = work_area
            .left
            .checked_add((work_width - outer_width) / 2)
            .ok_or(ApprovalError::Malformed)?;
        let window_y = work_area
            .top
            .checked_add((work_height - outer_height) / 2)
            .ok_or(ApprovalError::Malformed)?;

        let margin = scale(MARGIN, dpi);
        let gap = scale(VERTICAL_GAP, dpi);
        let button_height = scale(BUTTON_HEIGHT, dpi);
        let button_top = client_height
            .checked_sub(margin)
            .and_then(|value| value.checked_sub(button_height))
            .ok_or(ApprovalError::Malformed)?;
        let status_height = scale(STATUS_HEIGHT, dpi);
        let status_top = button_top
            .checked_sub(gap)
            .and_then(|value| value.checked_sub(status_height))
            .ok_or(ApprovalError::Malformed)?;
        let details_top = scale(DETAILS_TOP, dpi);
        let details_height = status_top
            .checked_sub(gap)
            .and_then(|value| value.checked_sub(details_top))
            .ok_or(ApprovalError::Malformed)?;
        if details_height < scale(180, dpi) {
            return Err(ApprovalError::Malformed);
        }
        let content_width = client_width
            .checked_sub(margin.saturating_mul(2))
            .ok_or(ApprovalError::Malformed)?;
        let button_gap = scale(16, dpi);
        let button_width = scale(BUTTON_WIDTH, dpi).min(
            content_width
                .checked_sub(button_gap)
                .ok_or(ApprovalError::Malformed)?
                / 2,
        );
        let approve_x = client_width
            .checked_sub(margin)
            .and_then(|value| value.checked_sub(button_width))
            .ok_or(ApprovalError::Malformed)?;
        let reject_x = approve_x
            .checked_sub(button_gap)
            .and_then(|value| value.checked_sub(button_width))
            .ok_or(ApprovalError::Malformed)?;

        Ok(Self {
            window: RectSpec {
                x: window_x,
                y: window_y,
                width: outer_width,
                height: outer_height,
            },
            phrase: RectSpec::scaled(
                MARGIN,
                PHRASE_TOP,
                CLIENT_WIDTH - 2 * MARGIN,
                PHRASE_HEIGHT,
                dpi,
            )
            .with_width(content_width),
            notice: RectSpec::scaled(
                MARGIN,
                NOTICE_TOP,
                CLIENT_WIDTH - 2 * MARGIN,
                NOTICE_HEIGHT,
                dpi,
            )
            .with_width(content_width),
            details: RectSpec {
                x: margin,
                y: details_top,
                width: content_width,
                height: details_height,
            },
            status: RectSpec {
                x: margin,
                y: status_top,
                width: content_width,
                height: status_height,
            },
            reject: RectSpec {
                x: reject_x,
                y: button_top,
                width: button_width,
                height: button_height,
            },
            approve: RectSpec {
                x: approve_x,
                y: button_top,
                width: button_width,
                height: button_height,
            },
        })
    }
}

impl RectSpec {
    const fn with_width(mut self, width: i32) -> Self {
        self.width = width;
        self
    }
}

fn adjusted_outer(
    client_width: i32,
    client_height: i32,
    dpi: i32,
    window_style: WINDOW_STYLE,
    ex_style: WINDOW_EX_STYLE,
) -> Result<RECT, ApprovalError> {
    let mut rectangle = RECT {
        left: 0,
        top: 0,
        right: client_width,
        bottom: client_height,
    };
    // SAFETY: `rectangle` is initialized writable storage and the style values
    // are fixed local constants.
    unsafe {
        AdjustWindowRectExForDpi(
            &raw mut rectangle,
            window_style,
            false,
            ex_style,
            u32::try_from(dpi).map_err(|_| ApprovalError::Malformed)?,
        )
    }
    .map_err(win_error)?;
    Ok(rectangle)
}

fn rect_width(rectangle: RECT) -> Result<i32, ApprovalError> {
    rectangle
        .right
        .checked_sub(rectangle.left)
        .ok_or(ApprovalError::Malformed)
}

fn rect_height(rectangle: RECT) -> Result<i32, ApprovalError> {
    rectangle
        .bottom
        .checked_sub(rectangle.top)
        .ok_or(ApprovalError::Malformed)
}

// SAFETY: This procedure stores no caller pointers and delegates all messages
// except fail-closed close/destruction and click-through activation handling.
unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_MOUSEACTIVATE && foreground_window() != window {
        return LRESULT(isize::try_from(MA_ACTIVATEANDEAT).unwrap_or(2));
    }
    match message {
        WM_CLOSE => {
            // SAFETY: The OS supplied this live top-level HWND.
            let _ = unsafe { DestroyWindow(window) };
            return LRESULT(0);
        }
        WM_DESTROY => {
            // SAFETY: Posting a quit message uses no caller-owned memory.
            unsafe { PostQuitMessage(0) };
            return LRESULT(0);
        }
        _ => {}
    }
    // SAFETY: Unhandled messages are delegated with exactly the original
    // parameters supplied by Windows.
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}

fn foreground_window() -> HWND {
    // SAFETY: This only queries the current foreground HWND.
    unsafe { GetForegroundWindow() }
}

#[cfg(test)]
mod tests {
    use windows::Win32::Foundation::RECT;
    use windows::Win32::UI::WindowsAndMessaging::{
        ES_MULTILINE, ES_READONLY, WS_CAPTION, WS_CLIPCHILDREN, WS_EX_APPWINDOW,
        WS_EX_CONTROLPARENT, WS_EX_DLGMODALFRAME, WS_MINIMIZEBOX, WS_OVERLAPPED, WS_SYSMENU,
        WS_VSCROLL,
    };

    use super::{Layout, scale, style};

    #[test]
    fn details_surface_is_scrollable_and_read_only() {
        let edit_styles = style(ES_MULTILINE | ES_READONLY) | WS_VSCROLL;
        assert_ne!(edit_styles.0 & WS_VSCROLL.0, 0);
        assert_ne!(edit_styles.0 & style(ES_MULTILINE).0, 0);
        assert_ne!(edit_styles.0 & style(ES_READONLY).0, 0);
    }

    #[test]
    fn adaptive_layout_stays_inside_work_area() -> Result<(), super::ApprovalError> {
        let window_style =
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN;
        let ex_style = WS_EX_APPWINDOW | WS_EX_CONTROLPARENT | WS_EX_DLGMODALFRAME;
        let work_area = RECT {
            left: 0,
            top: 0,
            right: 1_920,
            bottom: 1_080,
        };
        let layout = Layout::for_rectangle(work_area, 144, window_style, ex_style)?;
        let safe_margin = scale(16, 144);
        assert!(layout.window.x >= safe_margin);
        assert!(layout.window.y >= safe_margin);
        assert!(layout.window.x + layout.window.width <= work_area.right - safe_margin);
        assert!(layout.window.y + layout.window.height <= work_area.bottom - safe_margin);
        assert!(layout.details.height > 0);
        assert!(layout.details.y + layout.details.height < layout.status.y);
        assert!(layout.status.y + layout.status.height < layout.approve.y);
        Ok(())
    }

    #[test]
    fn undersized_work_area_fails_closed() {
        let window_style =
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN;
        let ex_style = WS_EX_APPWINDOW | WS_EX_CONTROLPARENT | WS_EX_DLGMODALFRAME;
        let result = Layout::for_rectangle(
            RECT {
                left: 0,
                top: 0,
                right: 400,
                bottom: 300,
            },
            96,
            window_style,
            ex_style,
        );
        assert!(result.is_err());
    }
}
