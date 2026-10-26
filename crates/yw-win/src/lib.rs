//! yw-win: safe wrappers over `windows-sys` (D4, spec/01 §7).
//!
//! The only crate allowed to contain `unsafe`, and only in FFI modules whose first line is
//! `#![allow(unsafe_code)]`; every block carries a `// SAFETY:` comment and one unsafe operation
//! (spec/01 §5.1). No raw handle or pointer is exposed; handles close on drop.
//!
//! M3 provides `time`, `mem`, `file`, `dpapi`, `clipboard`, `http`, `session`, `process`
//! (single instance, process setup), `input` and `ui`. `pipe` and the yw-host process helpers
//! (`spawn_detached`, `StdIn`/`StdOut`, `current_user_sid_string`) arrive with M5.

pub mod clipboard;
pub mod dpapi;
mod error;
pub mod file;
pub mod http;
pub mod input;
pub mod mem;
pub mod process;
pub mod session;
pub mod time;
pub mod ui;
mod wide;

pub use error::WinError;
pub use process::allow_set_foreground_window;
