//! `WalletConnect` v2 (spec/13): the engine part (session engine, store, Verify, QR decoding)
//! lives in `yw_engine::walletconnect` and is re-exported here; the relay worker stays here.
//! (2026-11-17, spec/15 §11.4 S2 E2: transitional facade until the worker moves in E3; before,
//! the whole module was in yw-app. The unit tests stay with the worker until then, because they
//! drive it through the browser dispatcher.)

pub use yw_engine::walletconnect::*;

pub mod worker;

#[cfg(test)]
mod tests;
