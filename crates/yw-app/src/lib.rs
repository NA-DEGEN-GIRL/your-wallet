//! yw-app library: the wallet application. Window-free logic (settings, key files, storage,
//! state machines, RPC transport) is tested through `tests/` and unit tests (spec/09 §2.1); the
//! Win32 shell (`app`, `ui::main_window`, `ui::secret`) runs in the binary.
#![forbid(unsafe_code)]

// 2026-11-17 (spec/15 §11.4 S2, spec/01 §2.3b): these modules moved to yw-engine; the re-exports
// keep their `crate::…` paths until S4 rewrites the callers (transitional facade;
// 2026-11-18: was S3–S4).
pub use yw_engine::{errors, logging, network, text, wallet_files, yubikey};
// 2026-11-17 (S2 E2): settings, wallet metadata, explain and the RPC pipelines followed.
pub use yw_engine::{
    apikeys, btc, explain, explorer, flow, hypercore, meta, received, rpc, settings, sol,
    token_view, zec,
};
// 2026-11-17 (S2 E3): the dApp dispatcher, the `WalletConnect` worker, the events and the
// workers followed. `browser` is a local facade module that re-exports the engine part and keeps
// the Windows pipe server; before E3, `walletconnect` was one too (it kept the relay worker).
pub use yw_engine::{events, walletconnect, workers};

pub mod app;
pub mod app_approval;
pub mod app_book;
pub mod app_browser;
pub mod app_btc;
pub mod app_btc_commands;
pub mod app_btc_view;
pub mod app_card;
pub mod app_chain_sites;
pub mod app_effects;
pub mod app_evm;
pub mod app_evm_commands;
pub mod app_explorer;
pub mod app_extension;
pub mod app_hidden;
pub mod app_hypercore;
pub mod app_keys;
pub mod app_llm;
pub mod app_mnemonics;
pub mod app_received;
pub mod app_reset;
pub mod app_rpc_import;
pub mod app_scroll;
pub mod app_sidecar;
pub mod app_sol;
pub mod app_sol_commands;
pub mod app_sol_dapp;
pub mod app_tokens;
pub mod app_walletconnect;
pub mod app_yubikey;
pub mod app_zec;
pub mod approval_flow;
pub mod browser;
pub mod build_info;
pub mod card_pcsc;
pub mod catalogues;
pub mod explain_transport;
pub mod lock;
pub mod log_file;
pub mod shell_msg;
pub mod store;
pub mod system_clock;
pub mod ui;
pub mod window_state;
