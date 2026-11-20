//! UI modules (spec/04 §1.8): the main window layout and screens, secret windows W01–W10, the
//! secret input buffers, the approval interaction/queue rules and the A01 content model, the
//! receive QR, text layout and theme. The A01 window itself is `crate::app_approval`.
//!
//! (2026-11-17, spec/15 §11.4 S2: the approval queue and interaction rules, the approval texts,
//! the text layout and the secret input buffers moved to yw-engine, and in E2 the chain badge;
//! they are re-exported here under their old names until S4 (2026-11-18: was S3–S4).)

pub use yw_engine::approval;
pub use yw_engine::approval::{interaction, layout as text_layout, text as approval_text};
pub use yw_engine::secure_field;
// 2026-11-17 (S2 E2): the chain badge followed with `meta`.
pub use yw_engine::badge;
// 2026-11-17 (S2 E3): the A01 content model followed (engine `approval::view`).
pub use yw_engine::approval::view as approval_view;

pub mod approval_input;
pub mod cmd_table;
pub mod command_ids;
pub mod main_window;
pub mod qr;
pub mod removed;
pub mod screens;
pub mod screens_accounts;
pub mod screens_book;
pub mod screens_btc;
pub mod screens_evm;
pub mod screens_explorer;
pub mod screens_hypercore;
pub mod screens_keys;
pub mod screens_links;
pub mod screens_llm;
pub mod screens_mnemonics;
pub mod screens_received;
pub mod screens_reset;
pub mod screens_sites;
pub mod screens_sol;
pub mod screens_walletconnect;
pub mod screens_yubikey;
pub mod screens_zec;
pub mod secret;
pub mod theme;
// DEV ONLY: needs `yw_win::ui::capture`, which exists only with debug assertions, so the tour is
// left out of `cargo test --release` (and never part of a release binary).
// (Two attributes rather than `all(test, debug_assertions)`, so clippy still sees a test module.)
#[cfg(test)]
#[cfg(debug_assertions)]
mod tour;
// DEV ONLY (2026-11-18, S3 B5): the windowed form test, gated like the tour.
#[cfg(test)]
#[cfg(debug_assertions)]
mod tour_forms;
// DEV ONLY (2026-11-18, S4 A7): the windowed secret-session characterization, gated like the
// tour.
#[cfg(test)]
#[cfg(debug_assertions)]
pub(crate) mod tour_secrets;
