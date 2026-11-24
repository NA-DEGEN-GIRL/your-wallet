//! Every text catalogue of yw-engine with its module path (spec/14 §5). `scripts/i18n-scan.mjs`
//! checks that each `texts!` block of the source is listed here, and yw-app `tests/lang_spec.rs`
//! that each one is in the spec tables (`errors::text` in spec/04 §7 instead, D31).
//! (2026-11-17, spec/15 §11.4 S2: the catalogues of the modules that moved out of yw-app; before,
//! they were listed in yw-app `catalogues` as `yw_app::…`; E1 the approval, error and card texts,
//! E2 the settings, metadata, explain, RPC pipeline and `WalletConnect` engine texts, E3 the
//! `WalletConnect` worker and key/journal worker texts. 2026-11-20, S4 P7a1: the secret windows'
//! texts `secret::text`, before `yw_app::ui::secret_text`. 2026-11-22, S4d E0a: `screen::text`, the
//! banner tags, receive QR choices and source words the wallet code shares with the shell, before
//! in `yw_app::ui::{main_window, qr, screens_accounts}::text`. 2026-11-23, S4d E1: the wallet's
//! catalogues `wallet::…::text`, before `yw_app::app_*::text` and the wallet's half of
//! `yw_app::app::text`. 2026-11-24, S5-4: `screen::model::text`, the copy mark's texts, before in
//! `yw_app::ui::main_window::text`. 2026-11-24, S5-5: the screens' catalogues
//! `screen::build::…::text`, before `yw_app::ui::screens*::text` and `yw_app::ui::removed::text`
//! (`screens` became `core`), the `rpc.json` card's `screen::build::rpc_import::text` (before
//! `yw_app::app_rpc_import::text`), S23's `screen::extension::text` (before
//! `yw_app::app_extension::text`) and the receive note's `screen::qr::text` (before
//! `yw_app::ui::qr::text`), moved with the builders. 2026-11-25, spec/15 §17 A2-5: the Android
//! protection tier names and warning bands `protection::text`, new.)

use yw_core::lang::Entry;

/// The catalogues, in module path order.
#[must_use]
pub fn catalogues() -> Vec<(&'static str, &'static [Entry])> {
    CATALOGUES.to_vec()
}

const CATALOGUES: &[(&str, &[Entry])] = &[
    ("yw_engine::apikeys::text", crate::apikeys::text::ALL),
    ("yw_engine::approval::labels", crate::approval::labels::ALL),
    ("yw_engine::approval::text", crate::approval::text::ALL),
    ("yw_engine::btc::text", crate::btc::text::ALL),
    ("yw_engine::errors::text", crate::errors::text::ALL),
    ("yw_engine::explain::text", crate::explain::text::ALL),
    ("yw_engine::explorer::text", crate::explorer::text::ALL),
    (
        "yw_engine::flow::evm::form::text",
        crate::flow::evm::form::text::ALL,
    ),
    (
        "yw_engine::flow::evm::prepare",
        crate::flow::evm::prepare::ALL,
    ),
    (
        "yw_engine::flow::evm::user_chain::text",
        crate::flow::evm::user_chain::text::ALL,
    ),
    ("yw_engine::hypercore::text", crate::hypercore::text::ALL),
    ("yw_engine::meta::text", crate::meta::text::ALL),
    ("yw_engine::protection::text", crate::protection::text::ALL),
    (
        "yw_engine::received::btc::text",
        crate::received::btc::text::ALL,
    ),
    (
        "yw_engine::received::evm::text",
        crate::received::evm::text::ALL,
    ),
    (
        "yw_engine::received::hc::text",
        crate::received::hc::text::ALL,
    ),
    (
        "yw_engine::received::zec::text",
        crate::received::zec::text::ALL,
    ),
    ("yw_engine::rpc::text", crate::rpc::text::ALL),
    (
        "yw_engine::screen::build::book::text",
        crate::screen::build::book::text::ALL,
    ),
    (
        "yw_engine::screen::build::btc::text",
        crate::screen::build::btc::text::ALL,
    ),
    (
        "yw_engine::screen::build::core::text",
        crate::screen::build::core::text::ALL,
    ),
    (
        "yw_engine::screen::build::evm::text",
        crate::screen::build::evm::text::ALL,
    ),
    (
        "yw_engine::screen::build::explorer::text",
        crate::screen::build::explorer::text::ALL,
    ),
    (
        "yw_engine::screen::build::hypercore::text",
        crate::screen::build::hypercore::text::ALL,
    ),
    (
        "yw_engine::screen::build::keys::text",
        crate::screen::build::keys::text::ALL,
    ),
    (
        "yw_engine::screen::build::links::text",
        crate::screen::build::links::text::ALL,
    ),
    (
        "yw_engine::screen::build::llm::text",
        crate::screen::build::llm::text::ALL,
    ),
    (
        "yw_engine::screen::build::mnemonics::text",
        crate::screen::build::mnemonics::text::ALL,
    ),
    (
        "yw_engine::screen::build::received::text",
        crate::screen::build::received::text::ALL,
    ),
    (
        "yw_engine::screen::build::removed::text",
        crate::screen::build::removed::text::ALL,
    ),
    (
        "yw_engine::screen::build::reset::text",
        crate::screen::build::reset::text::ALL,
    ),
    (
        "yw_engine::screen::build::rpc_import::text",
        crate::screen::build::rpc_import::text::ALL,
    ),
    (
        "yw_engine::screen::build::sites::text",
        crate::screen::build::sites::text::ALL,
    ),
    (
        "yw_engine::screen::build::sol::text",
        crate::screen::build::sol::text::ALL,
    ),
    (
        "yw_engine::screen::build::walletconnect::text",
        crate::screen::build::walletconnect::text::ALL,
    ),
    (
        "yw_engine::screen::build::yubikey::text",
        crate::screen::build::yubikey::text::ALL,
    ),
    (
        "yw_engine::screen::build::zec::text",
        crate::screen::build::zec::text::ALL,
    ),
    (
        "yw_engine::screen::extension::text",
        crate::screen::extension::text::ALL,
    ),
    (
        "yw_engine::screen::model::text",
        crate::screen::model::text::ALL,
    ),
    ("yw_engine::screen::qr::text", crate::screen::qr::text::ALL),
    ("yw_engine::screen::text", crate::screen::text::ALL),
    ("yw_engine::secret::text", crate::secret::text::ALL),
    ("yw_engine::settings::text", crate::settings::text::ALL),
    (
        "yw_engine::wallet::app_book::text",
        crate::wallet::app_book::text::ALL,
    ),
    (
        "yw_engine::wallet::app_browser::text",
        crate::wallet::app_browser::text::ALL,
    ),
    (
        "yw_engine::wallet::app_btc::text",
        crate::wallet::app_btc::text::ALL,
    ),
    (
        "yw_engine::wallet::app_card::text",
        crate::wallet::app_card::text::ALL,
    ),
    (
        "yw_engine::wallet::app_chain_sites::text",
        crate::wallet::app_chain_sites::text::ALL,
    ),
    (
        "yw_engine::wallet::app_evm::text",
        crate::wallet::app_evm::text::ALL,
    ),
    (
        "yw_engine::wallet::app_explorer::text",
        crate::wallet::app_explorer::text::ALL,
    ),
    (
        "yw_engine::wallet::app_hidden::text",
        crate::wallet::app_hidden::text::ALL,
    ),
    (
        "yw_engine::wallet::app_hypercore::text",
        crate::wallet::app_hypercore::text::ALL,
    ),
    (
        "yw_engine::wallet::app_keys::text",
        crate::wallet::app_keys::text::ALL,
    ),
    (
        "yw_engine::wallet::app_llm::text",
        crate::wallet::app_llm::text::ALL,
    ),
    (
        "yw_engine::wallet::app_mnemonics::text",
        crate::wallet::app_mnemonics::text::ALL,
    ),
    (
        "yw_engine::wallet::app_reset::text",
        crate::wallet::app_reset::text::ALL,
    ),
    (
        "yw_engine::wallet::app_rpc_plan::text",
        crate::wallet::app_rpc_plan::text::ALL,
    ),
    (
        "yw_engine::wallet::app_sidecar::text",
        crate::wallet::app_sidecar::text::ALL,
    ),
    (
        "yw_engine::wallet::app_sol::text",
        crate::wallet::app_sol::text::ALL,
    ),
    (
        "yw_engine::wallet::app_sol_commands::text",
        crate::wallet::app_sol_commands::text::ALL,
    ),
    (
        "yw_engine::wallet::app_sol_dapp::text",
        crate::wallet::app_sol_dapp::text::ALL,
    ),
    (
        "yw_engine::wallet::app_tokens::text",
        crate::wallet::app_tokens::text::ALL,
    ),
    (
        "yw_engine::wallet::app_walletconnect::text",
        crate::wallet::app_walletconnect::text::ALL,
    ),
    (
        "yw_engine::wallet::app_yubikey::text",
        crate::wallet::app_yubikey::text::ALL,
    ),
    (
        "yw_engine::wallet::app_yubikey::connect::text",
        crate::wallet::app_yubikey::connect::text::ALL,
    ),
    (
        "yw_engine::wallet::app_yubikey::manage::text",
        crate::wallet::app_yubikey::manage::text::ALL,
    ),
    (
        "yw_engine::wallet::app_zec::text",
        crate::wallet::app_zec::text::ALL,
    ),
    ("yw_engine::wallet::text", crate::wallet::text::ALL),
    (
        "yw_engine::walletconnect::text",
        crate::walletconnect::text::ALL,
    ),
    (
        "yw_engine::walletconnect::worker::text",
        crate::walletconnect::worker::text::ALL,
    ),
    (
        "yw_engine::workers::journal::btc::text",
        crate::workers::journal::btc::text::ALL,
    ),
    (
        "yw_engine::workers::journal::zec::text",
        crate::workers::journal::zec::text::ALL,
    ),
    (
        "yw_engine::workers::key::text",
        crate::workers::key::text::ALL,
    ),
    ("yw_engine::yubikey::text", crate::yubikey::text::ALL),
    ("yw_engine::zec::rpc::text", crate::zec::rpc::text::ALL),
];
