//! The WebSocket seam (spec/01 §2.3a, spec/13 §4).
//!
//! 2026-11-17 S2: moved from yw-app `walletconnect::worker::RelayLink` (which is now an alias of
//! [`WsLink`]); the Windows implementation for `yw_win::ws::WebSocket` lives in yw-win.

/// An open text WebSocket (the `WalletConnect` relay connection; an in-memory pair in tests).
pub trait WsLink: Send + Sync {
    /// Sends a text frame; `false` when the connection is gone.
    fn send(&self, text: &str) -> bool;
    /// Blocks for the next text frame; `None` when closed.
    fn receive(&self) -> Option<String>;
    /// Closes (a blocked receive returns `None`).
    fn abort(&self);
}
