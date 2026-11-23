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

// 2026-11-23 (spec/15 §11.4 S4d E1, preflight O-1 and critic C2; 주인 상시 결정(2026-11-21):
// 권고안, spec/15 §18 28): the wallet modules moved to `yw_engine::wallet`. The tests frozen at
// F-A (`app/tests/s4_flow/frozen-tests.txt`, never changed) and the pinned helpers of the
// chain-sites test holder name some of their items by the old yw-app paths, so these test-path
// shims keep exactly those names; they go in the first commit after the S4 freeze ends. Types,
// consts and texts only; no consent or secret step. `app_btc` is `#[doc(hidden)] pub` because
// the frozen integration test `tests/btc_app_flow.rs` sees the non-test library.
#[cfg(test)]
mod app_browser {
    pub(crate) use yw_engine::wallet::app_browser::{
        BrowserUi, GrantWrite, SignWaiter, SiteRows, SiteSigner,
    };
}
#[doc(hidden)]
pub mod app_btc {
    pub use yw_engine::wallet::app_btc::{
        ADDRESS_MODE_BUSY, BtcAction, BtcAddSource, NOT_SENT, REMOVE_BUSY_APPROVAL,
        REMOVE_BUSY_IN_FLIGHT,
    };
}
#[cfg(test)]
mod app_card {
    pub(crate) use yw_engine::wallet::app_card::{
        CardJobKind, T_CARD_SITE_GONE, T_CARD_SITE_REVOKED, T_CARD_TOUCH, approval_touches,
        touch_text,
    };
}
#[cfg(test)]
mod app_evm {
    pub(crate) use yw_engine::wallet::app_evm::QueuedItem;
}
#[cfg(test)]
mod app_sol_dapp {
    use yw_core::approval::Approved;
    use yw_engine::events::SignTicket;
    use yw_engine::wallet::app_card::PinBuffer;
    pub(crate) use yw_engine::wallet::app_sol_dapp::SolBroadcast;

    /// The frozen lock test's waiting send (critic C2 ii): the engine's `PendingDappSign` keeps
    /// its approval and PIN private, so the test builds this and the wallet's map converts it
    /// through `yw_engine::testkit::pending_dapp_sign`.
    pub(crate) struct PendingDappSign {
        pub(crate) ticket: SignTicket,
        pub(crate) approved: Box<Approved>,
        pub(crate) pin: Option<PinBuffer>,
        pub(crate) origin: String,
    }

    impl From<PendingDappSign> for yw_engine::wallet::app_sol_dapp::PendingDappSign {
        fn from(test: PendingDappSign) -> Self {
            yw_engine::testkit::pending_dapp_sign(test.ticket, test.approved, test.pin, test.origin)
        }
    }
}

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
