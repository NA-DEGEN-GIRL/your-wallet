//! UI modules (spec/04 §1.8): the main window layout and screens, secret windows W01–W10, the
//! approval window's input map, the receive QR and the theme. Since 2026-11-24 (spec/15 §11.4
//! S5-2) also `lower`, the neutral screen model (`yw_engine::screen::model`) lowered into the main
//! window's item list. Since 2026-11-24 (S5-5) the screens are built by yw-engine
//! (`yw_engine::screen::build`); the `screens*` modules here keep their control ids (`ids`) and
//! the tests that need an `App` (`removed` and `screens_accounts`, which had no ids, went). The
//! A01 window itself is `crate::app_approval`; the approval interaction/queue rules, the A01 content model, the text
//! layout and the secret input buffers are yw-engine's (below).
//!
//! (2026-11-17, spec/15 §11.4 S2: the approval queue and interaction rules, the approval texts,
//! the text layout and the secret input buffers moved to yw-engine, and in E2 the chain badge;
//! they were re-exported here under their old names (`approval`, `interaction`, `text_layout`,
//! `approval_text`, `secure_field`, `badge`, `approval_view`). 2026-11-23 (S4d E3a/E3b): yw-app
//! names them as `yw_engine::…`; only `approval` and `approval_view` stayed, for the bodies of
//! tests frozen at F-A. 2026-11-23 (spec/15 §11.4 S5-0): those two are gone with the S4 freeze.)

pub mod approval_input;
pub mod cmd_table;
pub mod command_ids;
pub mod lower;
pub mod main_window;
pub mod qr;
pub mod screens;
pub mod screens_book;
pub mod screens_btc;
pub mod screens_evm;
pub mod screens_explorer;
// 2026-11-22 (S4d E0c): the hidden-account rows' ids and render builder (were `app_hidden`'s).
pub mod screens_hidden;
pub mod screens_hypercore;
pub mod screens_keys;
pub mod screens_links;
pub mod screens_llm;
pub mod screens_mnemonics;
pub mod screens_received;
pub mod screens_reset;
// 2026-11-22 (S4d E0c): the side-file overlays' ids and render builders (were `app_sidecar`'s).
pub mod screens_sidecar;
pub mod screens_sites;
pub mod screens_sol;
pub mod screens_walletconnect;
pub mod screens_yubikey;
pub mod screens_zec;
pub mod secret;
// 2026-11-24 (spec/15 §11.4 S5-7): the secret windows' key and pointer map into the neutral
// `yw_engine::secret::input` events.
pub mod secret_input;
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
