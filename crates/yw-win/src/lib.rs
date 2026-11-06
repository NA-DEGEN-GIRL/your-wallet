//! yw-win: safe wrappers over `windows-sys` (D4, spec/01 §7).
//!
//! The only crate allowed to contain `unsafe`, and only in FFI modules whose first line is
//! `#![allow(unsafe_code)]`; every block carries a `// SAFETY:` comment and one unsafe operation
//! (spec/01 §5.1). No raw handle or pointer is exposed; handles close on drop.
//!
//! M3 provides `time`, `mem`, `file`, `dpapi`, `clipboard`, `http`, `session`, `process`
//! (single instance, process setup), `input` and `ui`. M5 adds `pipe` (the yw-host ↔ yw-app named
//! pipe) and the yw-host process helpers (`spawn_detached`, `StdIn`/`StdOut`,
//! `current_user_sid_string`; spec/05 §7.8). The `YubiKey` feature (spec/10 §4) adds `pcsc` (PC/SC
//! smart-card transport) and `cng` (one-block AES/3DES ECB for the PIV management key).

pub mod clipboard;
pub mod cng;
pub mod dpapi;
mod error;
pub mod file;
pub mod http;
pub mod image;
pub mod input;
pub mod mem;
pub mod pcsc;
pub mod pipe;
pub mod process;
pub mod security;
pub mod session;
pub mod time;
pub mod ui;
pub mod ws;
mod wide;

pub use error::WinError;
pub use process::{
    StdIn, StdOut, allow_set_foreground_window, current_user_sid_string, spawn_detached,
};
