//! yw-engine: the wallet application logic shared by every platform shell (D4, spec/01 §2.3b,
//! spec/15 §3.1). It depends on yw-core, yw-json and yw-platform only, never on yw-win or an OS
//! crate, and has no `unsafe`; its `clippy.toml` bans file, socket, process, wall-clock and
//! environment access (threads and `Instant` are allowed, spec/01 §5.1). The Windows app (yw-app)
//! re-exports the moved modules under their old paths until S3–S4.
//!
//! [`errors`] holds the user-visible error codes, [`text`] the shared text rules, [`network`] the
//! `NetworkId`, [`logging`] the log facade (the platform installs a `LogSink`), [`yubikey`] the
//! card operations over a `CardSource`, [`wallet_files`] the wallet file names, [`approval`] the
//! approval queue, interaction rules, texts and line breaking, [`secure_field`] the secret input
//! buffers and [`badge`] the chain badge. [`settings`], [`apikeys`] (the plaintext format; the
//! platform seals it), [`explorer`], [`token_view`] and [`meta`] hold the settings and wallet
//! metadata, [`explain`] the optional LLM explanation, [`rpc`], [`flow`], [`sol`], [`btc`],
//! [`zec`], [`received`] and [`hypercore`] the RPC pipelines and chain flows, and
//! [`walletconnect`] the `WalletConnect` session engine (the relay worker is still in yw-app).
//! [`catalogues`] lists the text catalogues of this crate (spec/14 §4).
//!
//! 2026-11-17 (spec/15 §11.4 S2, E1): created; these modules moved out of yw-app unchanged except
//! for their `use` paths. E2 added the settings, metadata, explain and pipeline modules.
#![forbid(unsafe_code)]

pub mod apikeys;
pub mod approval;
pub mod badge;
pub mod btc;
pub mod catalogues;
pub mod errors;
pub mod explain;
pub mod explorer;
pub mod flow;
pub mod hypercore;
pub mod logging;
pub mod meta;
pub mod network;
pub mod received;
pub mod rpc;
pub mod secure_field;
pub mod settings;
pub mod sol;
pub mod text;
pub mod token_view;
pub mod wallet_files;
pub mod walletconnect;
pub mod yubikey;
pub mod zec;
