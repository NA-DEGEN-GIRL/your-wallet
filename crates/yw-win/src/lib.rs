//! yw-win: safe wrappers over `windows-sys`.
//!
//! The only crate allowed to contain `unsafe`, and only in FFI modules that start with
//! `#![allow(unsafe_code)]` (spec/01 §5.1, §7). The API is implemented from M3.
