//! yw-app library: the wallet application. Window-free logic (settings, key files, storage,
//! state machines, RPC transport) is tested through `tests/` and unit tests (spec/09 §2.1); the
//! Win32 shell (`app`, `ui::main_window`, `ui::secret`) runs in the binary.
#![forbid(unsafe_code)]

pub mod apikeys;
pub mod app;
pub mod app_approval;
pub mod app_browser;
pub mod app_btc;
pub mod app_btc_commands;
pub mod app_evm;
pub mod app_evm_commands;
pub mod app_keys;
pub mod app_llm;
pub mod app_sol;
pub mod app_sol_commands;
pub mod browser;
pub mod btc;
pub mod errors;
pub mod events;
pub mod explain;
pub mod flow;
pub mod lock;
pub mod logging;
pub mod meta;
pub mod network;
pub mod rpc;
pub mod settings;
pub mod sol;
pub mod store;
pub mod text;
pub mod ui;
pub mod workers;
