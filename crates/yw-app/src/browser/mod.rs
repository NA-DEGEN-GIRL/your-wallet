//! The browser bridge (spec/05, M5): the engine part (envelope v1, dApp parameter rules, the
//! per-connection dispatcher, the read workers) lives in `yw_engine::browser`; the Windows
//! named-pipe server stays here.
//! (2026-11-17, spec/15 §11.4 S2 E3: before, the whole module was in yw-app, and this module
//! re-exported the engine part as a transitional facade (2026-11-18: until S4). 2026-11-23 (S4d
//! E3b): the re-export is gone; yw-app names `yw_engine::browser::…`.)

pub mod server;
