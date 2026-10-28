//! UI modules (spec/04 §1.8): the main window layout and screens, secret windows W01–W10, the
//! secret input buffers, the approval interaction/queue rules and the A01 content model, the
//! receive QR, text layout and theme. The A01 window itself is `crate::app_approval`.

pub mod approval;
pub mod approval_view;
pub mod interaction;
pub mod main_window;
pub mod qr;
pub mod screens;
pub mod screens_btc;
pub mod screens_evm;
pub mod screens_sites;
pub mod screens_sol;
pub mod secret;
pub mod secure_field;
pub mod text_layout;
pub mod theme;
