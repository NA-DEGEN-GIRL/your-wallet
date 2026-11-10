//! Real-clipboard regression for the secret-copy auto-clear (spec/04 §4.7–§4.8), run on a
//! non-interactive window station so the user's clipboard is never touched. The process switches
//! window station, so this file holds exactly one test (its own test binary).
//!
//! Regression (adversarial PoC): `CloseClipboard` adds the synthesized text formats and bumps the
//! sequence number after a secret copy, so the sequence-based auto-clear never removed it.
//!
//! Test setup (2026-11-10): a window station created without a name is the logon session's
//! service window station (`Service-0x…$`) — every process of this session that asks for an
//! alternate station (sandboxes, another run of this test) gets the same one and so the same
//! clipboard, and only administrators may name their own. So two runs of this test at once (the
//! gates of two checkouts) take turns through a session-wide mutex, and a clipboard another
//! process holds open for a moment (`ClipError::Busy` after the product's own 5 × 20 ms) is asked
//! again for up to 5 s. The assertions on the product calls are unchanged.
#![allow(unsafe_code, missing_docs)]

use core::ffi::c_void;
use std::time::{Duration, Instant};

use yw_win::clipboard::{self, ClipError};
use yw_win::ui::{
    self, CaptureExclusion, ClassSpec, Handler, Msg, Reply, Window, WindowKind, WindowSpec,
};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateMutexW(attributes: *const c_void, initial_owner: i32, name: *const u16)
    -> *mut c_void;
    fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
    fn ReleaseMutex(mutex: *mut c_void) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
}

/// How long a clipboard another process holds open is asked again.
const BUSY_PATIENCE: Duration = Duration::from_secs(5);

/// This test's turn on the session's shared service window station (see the module note),
/// released when dropped on the thread that took it.
struct SessionTurn(*mut c_void);

impl SessionTurn {
    fn take() -> Result<Self, String> {
        let name: Vec<u16> = "Local\\yw-win-clipboard-winsta-test\0"
            .encode_utf16()
            .collect();
        // SAFETY: Opens or creates a named mutex; `name` is NUL-terminated.
        let mutex = unsafe { CreateMutexW(core::ptr::null(), 0, name.as_ptr()) };
        if mutex.is_null() {
            return Err("CreateMutexW".to_owned());
        }
        // SAFETY: Waits on the mutex handle just opened. WAIT_OBJECT_0 (0) or WAIT_ABANDONED
        // (0x80, an earlier run ended without releasing it): this thread owns it now.
        match unsafe { WaitForSingleObject(mutex, 120_000) } {
            0 | 0x80 => Ok(Self(mutex)),
            other => {
                // SAFETY: Closes the handle opened above.
                unsafe { CloseHandle(mutex) };
                Err(format!(
                    "another run of this test kept its turn (wait {other:#x})"
                ))
            }
        }
    }
}

impl Drop for SessionTurn {
    fn drop(&mut self) {
        // SAFETY: Releases the mutex this thread acquired in `take`.
        unsafe { ReleaseMutex(self.0) };
        // SAFETY: Closes the handle `take` opened; nothing uses it after this.
        unsafe { CloseHandle(self.0) };
    }
}

/// `op` again while the shared clipboard is held open by another process, for up to
/// [`BUSY_PATIENCE`]; any other result (and the last `Busy`) as it came.
fn patient<T>(mut op: impl FnMut() -> Result<T, ClipError>) -> Result<T, ClipError> {
    let deadline = Instant::now() + BUSY_PATIENCE;
    loop {
        match op() {
            Err(ClipError::Busy) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            other => return other,
        }
    }
}

#[link(name = "user32")]
unsafe extern "system" {
    fn CreateWindowStationW(
        name: *const u16,
        flags: u32,
        access: u32,
        attributes: *const c_void,
    ) -> *mut c_void;
    fn SetProcessWindowStation(station: *mut c_void) -> i32;
    fn CreateDesktopW(
        name: *const u16,
        device: *const u16,
        mode: *const c_void,
        flags: u32,
        access: u32,
        attributes: *const c_void,
    ) -> *mut c_void;
    fn SetThreadDesktop(desktop: *mut c_void) -> i32;
    fn OpenClipboard(owner: *mut c_void) -> i32;
    fn CloseClipboard() -> i32;
    fn EnumClipboardFormats(format: u32) -> u32;
}

struct Nop;
impl Handler for Nop {
    fn on(&mut self, _: &Window, _: &Msg) -> Reply {
        Reply::Default
    }
}

fn format_count() -> usize {
    let mut count = 0;
    let deadline = Instant::now() + BUSY_PATIENCE;
    // SAFETY: Opens the station's clipboard for the task (asked again while another process of
    // the session holds it, see the module note).
    while unsafe { OpenClipboard(core::ptr::null_mut()) } == 0 {
        if Instant::now() >= deadline {
            return usize::MAX;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut format = 0;
    loop {
        // SAFETY: Enumerates the formats of the clipboard opened above.
        format = unsafe { EnumClipboardFormats(format) };
        if format == 0 {
            break;
        }
        count += 1;
    }
    // SAFETY: Closes the clipboard opened above.
    unsafe { CloseClipboard() };
    count
}

fn enter_private_window_station() -> Result<(), String> {
    // SAFETY: Opens (or creates) the session's unnamed service window station with
    // WINSTA_ALL_ACCESS (0x37F); not the interactive WinSta0, so the user's clipboard is not it.
    let station = unsafe { CreateWindowStationW(core::ptr::null(), 0, 0x37F, core::ptr::null()) };
    if station.is_null() {
        return Err("CreateWindowStationW".to_owned());
    }
    // SAFETY: Switches this process to the window station just created.
    if unsafe { SetProcessWindowStation(station) } == 0 {
        return Err("SetProcessWindowStation".to_owned());
    }
    let name: Vec<u16> = "ywclipdesk\0".encode_utf16().collect();
    // SAFETY: Creates a desktop (GENERIC_ALL) on the private station; `name` is NUL-terminated.
    let desktop = unsafe {
        CreateDesktopW(
            name.as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            0,
            0x1000_0000,
            core::ptr::null(),
        )
    };
    if desktop.is_null() {
        return Err("CreateDesktopW".to_owned());
    }
    // SAFETY: Binds this (window-less) thread to the private desktop.
    if unsafe { SetThreadDesktop(desktop) } == 0 {
        return Err("SetThreadDesktop".to_owned());
    }
    Ok(())
}

#[test]
fn secret_copy_auto_clear_and_paste_clear_on_a_private_clipboard()
-> Result<(), Box<dyn std::error::Error>> {
    let _turn = SessionTurn::take()?;
    enter_private_window_station()?;
    let _ = ui::init();
    ui::register_class(&ClassSpec {
        name: "YwClipTestOwner",
        secret: false,
        capture: CaptureExclusion::Preferred,
    })?;
    let window = ui::create_window(
        &WindowSpec::new("YwClipTestOwner", WindowKind::HiddenTopLevel),
        Box::new(Nop),
    )?;
    let text: Vec<u16> = "abandon abandon about".encode_utf16().collect();

    // Auto-clear (30 s / lock path): our copy is removed.
    let clip = patient(|| clipboard::set_secret_text(&window, &text))?;
    assert!(format_count() >= 5, "exclusions + marker + text placed");
    assert_eq!(
        patient(|| clipboard::clear_secret(&window, &clip)),
        Ok(true)
    );
    assert_eq!(format_count(), 0, "clipboard emptied");
    assert!(patient(|| clipboard::read_text(&window, 4096)).is_err());

    // Someone else's copy after ours is kept.
    let clip = patient(|| clipboard::set_secret_text(&window, &text))?;
    patient(|| clipboard::set_text(&window, "0xabc"))?;
    assert_eq!(
        patient(|| clipboard::clear_secret(&window, &clip)),
        Ok(false)
    );
    assert_eq!(patient(|| clipboard::read_text(&window, 4096))?.0.len(), 5);

    // Paste path: read, then clear by the sequence read with it.
    let _ = patient(|| clipboard::set_secret_text(&window, &text))?;
    let (units, seq) = patient(|| clipboard::read_text(&window, 4096))?;
    assert_eq!(units.len(), text.len());
    assert_eq!(
        patient(|| clipboard::clear_if_unchanged(&window, seq)),
        Ok(true)
    );
    assert_eq!(format_count(), 0);
    Ok(())
}
