//! yw-app library: the wallet application. Window-free logic (settings, key files, storage,
//! state machines, RPC transport) is tested through `tests/` and unit tests (spec/09 §2.1); the
//! Win32 shell (`app`, `ui::main_window`, `ui::secret`) runs in the binary.
#![forbid(unsafe_code)]

// 2026-11-17 (spec/15 §11.4 S2, spec/01 §2.3b): modules moved to yw-engine were re-exported here
// under their `crate::…` paths (a transitional facade). 2026-11-23 (S4d E3a/E3b): yw-app `src` and
// `tests/` name `yw_engine::…` directly; the facade stayed only for the entries the bodies of the
// tests frozen at F-A named (`btc, errors, events, meta, workers` `#[doc(hidden)] pub`, `flow,
// network, sol, yubikey` `#[cfg(test)]`), with the S4d E1 test-path shims of the wallet modules
// (`app_browser`, `app_btc`, `app_card`, `app_evm`, `app_sol_dapp`). 2026-11-23 (spec/15 §11.4
// S5-0, §18 28: "S4 얼림이 끝난 뒤 첫 커밋"): all of them are gone; the frozen bodies name
// `yw_engine::…` (source check `the_s2_facade_and_test_shims_are_gone`).

pub mod app;
pub mod app_approval;
// 2026-11-23 (S4d E1, preflight O-9): the test holder of the dApp chain sites (its wallet code
// is `yw_engine::wallet::app_chain_sites`).
#[cfg(test)]
mod app_chain_sites;
pub mod app_effects;
pub mod app_extension;
pub mod app_rpc_import;
pub mod app_scroll;
pub mod app_store;
pub mod browser;
pub mod build_info;
pub mod card_pcsc;
pub mod catalogues;
pub mod explain_transport;
// 2026-11-22 (S4d E0c): `explorer.exe` for links and folders (was `app_explorer::Launcher`).
pub mod explorer_launcher;
pub mod log_file;
pub mod shell_msg;
pub mod store;
pub mod system_clock;
pub mod ui;
// 2026-11-22 (S4d E0c): the Windows `WalletConnect` platform parts (were `app_walletconnect`'s).
pub mod wc_platform;
pub mod window_state;
