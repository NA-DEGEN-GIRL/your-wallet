//! The browser bridge (spec/05, M5): the engine part (envelope v1, dApp parameter rules, the
//! per-connection dispatcher, the read workers) lives in `yw_engine::browser` and is re-exported
//! here; the Windows named-pipe server stays here.
//! (2026-11-17, spec/15 §11.4 S2 E3: transitional facade until S3–S4 rewrite the callers;
//! before, the whole module was in yw-app.)

pub use yw_engine::browser::*;

pub mod server;
