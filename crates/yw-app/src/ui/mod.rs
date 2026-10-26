//! UI modules (spec/04 §1.8): the main window layout and screens, secret windows W01–W10, the
//! secret input buffers, the approval interaction/queue rules (the A01 window arrives with M4),
//! text layout and theme. The receive QR (`ui::qr`) arrives with M4.

pub mod approval;
pub mod interaction;
pub mod main_window;
pub mod screens;
pub mod secret;
pub mod secure_field;
pub mod text_layout;
pub mod theme;
