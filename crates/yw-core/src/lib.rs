//! yw-core: platform-independent wallet core (keys, vault, chain encoding, policy).
//!
//! No network, GUI, file system, threads, clocks or `unsafe` (spec/01 §2.2, §5.1); the only OS
//! call is `getrandom` in `entropy`. Module names follow the spec/01 §2.2 table.
#![forbid(unsafe_code)]

pub mod approval;
pub mod bip32;
pub mod bip39;
pub mod codec;
pub mod entropy;
pub mod error;
pub mod evm;
pub mod hex;
pub mod journal;
pub mod password;
pub mod policy;
pub mod secret;
pub mod vault;
