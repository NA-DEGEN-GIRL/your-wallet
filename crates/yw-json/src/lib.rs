//! yw-json: strict RFC 8259 JSON parser, deterministic writer and the native messaging frame
//! codec.
//!
//! Zero dependencies (spec/01 §2.3). `parse` rejects a BOM, raw control characters,
//! lone surrogates, leading zeros, `+`, `NaN`/`Infinity`, trailing commas, duplicate keys
//! and trailing data, and enforces the [`Limits`] counting rules of spec/05 §2.9.
//! Numbers keep their validated source token (no `f64` conversion). [`frame`] is the
//! 4-byte little-endian length framing shared by native messaging and the yw-app pipe
//! (spec/05 §7.3).
#![forbid(unsafe_code)]
#![deny(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

pub mod frame;
mod parse;
mod value;
mod write;

pub use parse::{Limits, ParseError, parse};
pub use value::{Number, Object, Value};
pub use write::to_vec;
