//! Real-clipboard regression for the secret-copy auto-clear (spec/04 §4.7–§4.8), run on a PRIVATE
//! window station so the user's clipboard is never touched. The process switches window station,
//! so this file holds exactly one test (its own test binary).
//!
//! Regression (adversarial PoC): `CloseClipboard` adds the synthesized text formats and bumps the
//! sequence number after a secret copy, so the sequence-based auto-clear never removed it.
#![allow(unsafe_code, missing_docs)]

use core::ffi::c_void;

use yw_win::clipboard;
use yw_win::ui::{
    self, CaptureExclusion, ClassSpec, Handler, Msg, Reply, Window, WindowKind, WindowSpec,
};

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
    // SAFETY: Opens the private station's clipboard for the task.
    if unsafe { OpenClipboard(core::ptr::null_mut()) } == 0 {
        return usize::MAX;
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
    // SAFETY: Creates an unnamed window station with WINSTA_ALL_ACCESS (0x37F).
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
    let clip = clipboard::set_secret_text(&window, &text)?;
    assert!(format_count() >= 5, "exclusions + marker + text placed");
    assert_eq!(clipboard::clear_secret(&window, &clip), Ok(true));
    assert_eq!(format_count(), 0, "clipboard emptied");
    assert!(clipboard::read_text(&window, 4096).is_err());

    // Someone else's copy after ours is kept.
    let clip = clipboard::set_secret_text(&window, &text)?;
    clipboard::set_text(&window, "0xabc")?;
    assert_eq!(clipboard::clear_secret(&window, &clip), Ok(false));
    assert_eq!(clipboard::read_text(&window, 4096)?.0.len(), 5);

    // Paste path: read, then clear by the sequence read with it.
    let _ = clipboard::set_secret_text(&window, &text)?;
    let (units, seq) = clipboard::read_text(&window, 4096)?;
    assert_eq!(units.len(), text.len());
    assert_eq!(clipboard::clear_if_unchanged(&window, seq), Ok(true));
    assert_eq!(format_count(), 0);
    Ok(())
}
