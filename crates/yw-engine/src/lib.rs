//! yw-engine: the wallet application logic shared by every platform shell (D4, spec/01 §2.3b,
//! spec/15 §3.1). It depends on yw-core, yw-json and yw-platform only, never on yw-win or an OS
//! crate, and has no `unsafe`; its `clippy.toml` bans file, socket, process, wall-clock and
//! environment access (threads and `Instant` are allowed, spec/01 §5.1). The Windows app (yw-app)
//! re-exported the moved modules under their old paths (2026-11-18: until S3–S4); since S4d E3b
//! (2026-11-23) it names them here, and keeps only the entries that tests frozen through S4 name.
//!
//! [`errors`] holds the user-visible error codes, [`text`] the shared text rules, [`network`] the
//! `NetworkId`, [`logging`] the log facade (the platform installs a `LogSink`), [`yubikey`] the
//! card operations over a `CardSource`, [`wallet_files`] the wallet file names, [`approval`] the
//! approval queue, interaction rules, texts and line breaking, [`secure_field`] the secret input
//! buffers and [`badge`] the chain badge. [`settings`], [`apikeys`] (the plaintext format; the
//! platform seals it), [`explorer`], [`token_view`] and [`meta`] hold the settings and wallet
//! metadata, [`explain`] the optional LLM explanation, [`rpc`], [`flow`], [`sol`], [`btc`],
//! [`zec`], [`received`] and [`hypercore`] the RPC pipelines and chain flows, and
//! [`walletconnect`] the `WalletConnect` session engine and relay worker. [`browser`] holds the
//! dApp dispatcher (envelope v1, parameters, grants, read workers; the platform runs the
//! transport), [`events`] the worker and UI event types, [`workers`] the key, RPC and journal
//! workers, and `approval::view` the A01 content model. [`catalogues`] lists the text catalogues
//! of this crate (spec/14 §4). `testkit` (hidden) holds test helpers for the platform crates.
//! [`cmd`] holds the inputs a shell sends to the logic (`Cmd`, `Press`), [`effect`] what the
//! logic asks the shell to do (`Effect`) and [`form`] the plain edits' state and the credential
//! units captured with a press. [`app_store`] is the app's data-folder store (`AppStore`: the
//! settings file, the sealed API keys, the vault facts; the platform implements it). [`services`]
//! holds the platform factories the optional network workers start from (`Services`: the LLM
//! transport, the `WalletConnect` relay parts, the relay user agent's platform word). [`secret`]
//! holds the secret windows' kinds, flow step, effects and texts (never a secret). [`screen`]
//! holds plain screen data the logic and the shell share (the settings sections, the remembered
//! scroll places; since S4d E0a also the banner tone, the receive QR choice, the removal block's
//! data, the account sources and the EVM activity row). [`file_storage`] holds the wallet data
//! folder storage (`FileStorage`: the atomic commit, `.prev`, the set-aside copies, the link
//! refusal) over the platform's `yw_platform::files::Files` (2026-11-25, spec/15 §17 A2-4a).
//! [`protection`] holds the Android protection tier and the warning bands, pure decisions over the
//! device facts the shell passes in (2026-11-25, spec/15 §1.1, §8.2, §17 A2-5).
//!
//! 2026-11-17 (spec/15 §11.4 S2, E1): created; these modules moved out of yw-app unchanged except
//! for their `use` paths. E2 added the settings, metadata, explain and pipeline modules, E3 the
//! dispatcher, the `WalletConnect` worker, the events, the workers and the approval view (before
//! E3 the relay worker was still in yw-app). 2026-11-18 (spec/15 §11.4 S3 B1): `cmd`, `effect`
//! and `form` were added. 2026-11-20 (S4 P1): `app_store` was added; (S4 P2) `services`;
//! (S4 P7a1) `secret`; (S4 P10a) `screen`. 2026-11-22 (S4d E0a): the types, texts and pure helpers
//! the wallet code took from yw-app shell files moved into `screen`, `secret`, `meta`,
//! `wallet_files`, `text`, `badge`, `approval::flow` and `explain::config`. 2026-11-23 (S4d E0b):
//! `probe` (hidden) was added, the wallet code's test observation points.
//! 2026-11-23 (S4d E1): [`wallet`] was added: the wallet state `Wallet`, its handler families and
//! the approval flow, moved from yw-app (spec/15 §11.4 S4).
#![forbid(unsafe_code)]

pub mod apikeys;
pub mod app_store;
pub mod approval;
pub mod badge;
pub mod browser;
pub mod btc;
pub mod catalogues;
pub mod cmd;
pub mod effect;
pub mod errors;
pub mod events;
pub mod explain;
pub mod explorer;
// 2026-11-25 (spec/15 §17 A2-4a): the wallet data folder storage over `yw_platform::files`.
pub mod file_storage;
pub mod flow;
pub mod form;
pub mod hypercore;
pub mod logging;
pub mod meta;
pub mod network;
// 2026-11-23 (spec/15 §11.4 S4d E0b): the wallet code's test observation points (a sink only a
// test seam installs; source check `the_probe_is_installed_only_by_tests`).
#[doc(hidden)]
pub mod probe;
pub mod protection;
pub mod received;
pub mod rpc;
pub mod screen;
pub mod secret;
pub mod secure_field;
pub mod services;
pub mod settings;
pub mod sol;
#[doc(hidden)]
pub mod testkit;
pub mod text;
pub mod token_view;
pub mod wallet_files;
// 2026-11-23 (spec/15 §11.4 S4d E1): the wallet state, its handlers and the approval flow.
pub mod wallet;
pub mod walletconnect;
pub mod workers;
pub mod yubikey;
pub mod zec;
