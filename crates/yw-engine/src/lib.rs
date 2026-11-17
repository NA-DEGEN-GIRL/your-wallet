//! yw-engine: the wallet application logic shared by every platform shell (D4, spec/01 §2.3b,
//! spec/15 §3.1). It depends on yw-core, yw-json and yw-platform only, never on yw-win or an OS
//! crate, and has no `unsafe`; its `clippy.toml` bans file, socket, process, wall-clock and
//! environment access (threads and `Instant` are allowed, spec/01 §5.1). The Windows app (yw-app)
//! re-exports the moved modules under their old paths until S3–S4.
//!
//! [`errors`] holds the user-visible error codes, [`text`] the shared text rules, [`network`] the
//! `NetworkId`, [`logging`] the log facade (the platform installs a `LogSink`), [`yubikey`] the
//! card operations over a `CardSource`, [`wallet_files`] the wallet file names, [`approval`] the
//! approval queue, interaction rules, texts and line breaking, and [`secure_field`] the secret
//! input buffers. [`catalogues`] lists the text catalogues of this crate (spec/14 §4).
//!
//! 2026-11-17 (spec/15 §11.4 S2, E1): created; these modules moved out of yw-app unchanged except
//! for their `use` paths.
#![forbid(unsafe_code)]

pub mod approval;
pub mod catalogues;
pub mod errors;
pub mod logging;
pub mod network;
pub mod secure_field;
pub mod text;
pub mod wallet_files;
pub mod yubikey;
