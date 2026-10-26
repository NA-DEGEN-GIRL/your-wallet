//! yw-app library: GUI-free wallet application logic, tested through `tests/` (spec/09 §2.1).
//!
//! M2 provides only `rpc::evm`'s `eth_simulateV1` response parser (spec/09 §3.8); transport,
//! flows, UI and the browser bridge arrive with M3–M5 (spec/04 §1.8).
#![forbid(unsafe_code)]

pub mod rpc;
