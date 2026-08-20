//! Strict, bounded EIP-712 v4 validation and hashing.
//!
//! This crate rejects duplicate JSON keys and validates the source before
//! returning an opaque proof usable by signing authorization code.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

mod error;
mod json;
mod schema;

pub use error::{LimitKind, TypedDataError};
pub use schema::{ValidatedTypedDataV4, eip712_signing_digest, validate_typed_data_v4};
