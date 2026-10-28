//! Raw Win32 GUI as a safe API (spec/01 §7.7): classes, windows, the wndproc trampoline, the
//! message loop, painting, standard controls and the custom secret text field.

#[cfg(debug_assertions)]
pub mod capture;
pub mod controls;
mod msg;
mod paint;
pub mod secure_text;
mod window;

pub use msg::{CaptureExclusion, CaptureOutcome, Msg, capture_outcome, is_blocked_secret_msg};
pub use paint::{Color, DrawFlags, Font, PaintDc, Rect};
pub use window::{
    ClassSpec, Handler, Hwnd, InputKind, MbKind, MbResult, Poster, Reply, UiError, Window,
    WindowKind, WindowSpec, create_window, exclude_from_capture, find_window, init, message_box,
    quit, register_class, run_loop, scale,
};
