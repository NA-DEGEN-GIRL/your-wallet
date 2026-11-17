//! yw-platform: the platform-neutral types and traits shared by the wallet app and its OS
//! layers (D4, spec/01 §2.4, §7.4).
//!
//! Zero dependencies and no `unsafe`; like yw-core it makes no OS call (its `clippy.toml` bans
//! time, file, network, thread and environment access). [`http`] holds the URL, timeout, response
//! and error types of the HTTP client, the request limits every platform enforces and the RPC
//! `Transport` seam; the client itself is per platform (Windows: `yw_win::http::Client`,
//! `WinHTTP`). [`clock`] holds the [`Clock`] trait of the pipelines (Windows implementation:
//! yw-app `system_clock::SystemClock`). [`ws`] holds the `WsLink` seam of the `WalletConnect`
//! relay socket (Windows implementation: `yw_win::ws::WebSocket`).
//!
//! 2026-11-17: split out of yw-win (`http` types) and yw-app (`flow::evm::Clock`) as the first
//! step of the Android port, so code that will be shared across platforms no longer names yw-win.
#![forbid(unsafe_code)]
#![deny(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

pub mod clock;
pub mod http;
pub mod ws;

pub use clock::Clock;
