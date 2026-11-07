//! UI modules (spec/04 §1.8): the main window layout and screens, secret windows W01–W10, the
//! secret input buffers, the approval interaction/queue rules and the A01 content model, the
//! receive QR, text layout and theme. The A01 window itself is `crate::app_approval`.

pub mod approval;
pub mod approval_view;
pub mod badge;
pub mod command_ids;
pub mod interaction;
pub mod main_window;
pub mod qr;
pub mod screens;
pub mod screens_book;
pub mod screens_btc;
pub mod screens_evm;
pub mod screens_hypercore;
pub mod screens_keys;
pub mod screens_llm;
pub mod screens_mnemonics;
pub mod screens_reset;
pub mod screens_sites;
pub mod screens_sol;
pub mod screens_walletconnect;
pub mod screens_yubikey;
pub mod screens_zec;
pub mod secret;
pub mod secure_field;
pub mod text_layout;
pub mod theme;
// DEV ONLY: needs `yw_win::ui::capture`, which exists only with debug assertions, so the tour is
// left out of `cargo test --release` (and never part of a release binary).
// (Two attributes rather than `all(test, debug_assertions)`, so clippy still sees a test module.)
#[cfg(test)]
#[cfg(debug_assertions)]
mod tour;
