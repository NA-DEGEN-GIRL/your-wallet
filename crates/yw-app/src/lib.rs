//! yw-app library: the wallet application. Window-free logic (settings, key files, storage,
//! state machines, RPC transport) is tested through `tests/` and unit tests (spec/09 §2.1); the
//! Win32 shell (`app`, `ui::main_window`, `ui::secret`) runs in the binary.
#![forbid(unsafe_code)]

pub mod apikeys;
pub mod app;
pub mod app_approval;
pub mod app_evm;
pub mod app_evm_commands;
pub mod errors;
pub mod events;
pub mod flow;
pub mod lock;
pub mod logging;
pub mod meta;
pub mod network;
pub mod rpc;
pub mod settings;
pub mod store;
pub mod text;
pub mod ui;
pub mod workers;
