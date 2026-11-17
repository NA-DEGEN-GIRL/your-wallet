//! Worker threads (spec/04 §1.2): `yw-key` owns the vault, `yw-rpc` the RPC calls. `yw-read-*`
//! (dApp reads) arrive with M5.

pub mod journal;
pub mod key;
pub mod rpc;
