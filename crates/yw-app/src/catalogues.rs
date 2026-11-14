//! Every text catalogue of yw-app with its module path (spec/14 §5). `scripts/i18n-scan.mjs`
//! checks that each `texts!` block of the source is listed here, and `tests/lang_spec.rs` that
//! each one is in the spec tables (`errors::text` in spec/04 §7 instead, D31). The screenshot
//! tour's scene texts (`ui::tour`, a test module) are not app texts and are not listed.

use yw_core::lang::Entry;

/// The catalogues, in module path order.
#[must_use]
pub fn catalogues() -> Vec<(&'static str, &'static [Entry])> {
    CATALOGUES.to_vec()
}

const CATALOGUES: &[(&str, &[Entry])] = &[
    ("yw_app::apikeys::text", crate::apikeys::text::ALL),
    ("yw_app::app::text", crate::app::text::ALL),
    ("yw_app::app_book::text", crate::app_book::text::ALL),
    ("yw_app::app_browser::text", crate::app_browser::text::ALL),
    ("yw_app::app_btc::text", crate::app_btc::text::ALL),
    ("yw_app::app_card::text", crate::app_card::text::ALL),
    (
        "yw_app::app_chain_sites::text",
        crate::app_chain_sites::text::ALL,
    ),
    ("yw_app::app_evm::text", crate::app_evm::text::ALL),
    ("yw_app::app_explorer::text", crate::app_explorer::text::ALL),
    (
        "yw_app::app_extension::text",
        crate::app_extension::text::ALL,
    ),
    ("yw_app::app_hidden::text", crate::app_hidden::text::ALL),
    (
        "yw_app::app_hypercore::text",
        crate::app_hypercore::text::ALL,
    ),
    ("yw_app::app_keys::text", crate::app_keys::text::ALL),
    ("yw_app::app_llm::text", crate::app_llm::text::ALL),
    (
        "yw_app::app_mnemonics::text",
        crate::app_mnemonics::text::ALL,
    ),
    ("yw_app::app_reset::text", crate::app_reset::text::ALL),
    (
        "yw_app::app_rpc_import::text",
        crate::app_rpc_import::text::ALL,
    ),
    ("yw_app::app_sidecar::text", crate::app_sidecar::text::ALL),
    ("yw_app::app_sol::text", crate::app_sol::text::ALL),
    (
        "yw_app::app_sol_commands::text",
        crate::app_sol_commands::text::ALL,
    ),
    ("yw_app::app_sol_dapp::text", crate::app_sol_dapp::text::ALL),
    ("yw_app::app_tokens::text", crate::app_tokens::text::ALL),
    (
        "yw_app::app_walletconnect::text",
        crate::app_walletconnect::text::ALL,
    ),
    (
        "yw_app::app_yubikey::connect::text",
        crate::app_yubikey::connect::text::ALL,
    ),
    (
        "yw_app::app_yubikey::manage::text",
        crate::app_yubikey::manage::text::ALL,
    ),
    ("yw_app::app_yubikey::text", crate::app_yubikey::text::ALL),
    ("yw_app::app_zec::text", crate::app_zec::text::ALL),
    ("yw_app::btc::text", crate::btc::text::ALL),
    (
        "yw_app::build_info::start_text",
        crate::build_info::start_text::ALL,
    ),
    ("yw_app::build_info::text", crate::build_info::text::ALL),
    ("yw_app::errors::text", crate::errors::text::ALL),
    ("yw_app::explain::text", crate::explain::text::ALL),
    ("yw_app::explorer::text", crate::explorer::text::ALL),
    (
        "yw_app::flow::evm::form::text",
        crate::flow::evm::form::text::ALL,
    ),
    ("yw_app::flow::evm::prepare", crate::flow::evm::prepare::ALL),
    (
        "yw_app::flow::evm::user_chain::text",
        crate::flow::evm::user_chain::text::ALL,
    ),
    ("yw_app::hypercore::text", crate::hypercore::text::ALL),
    ("yw_app::meta::text", crate::meta::text::ALL),
    (
        "yw_app::received::btc::text",
        crate::received::btc::text::ALL,
    ),
    (
        "yw_app::received::evm::text",
        crate::received::evm::text::ALL,
    ),
    ("yw_app::received::hc::text", crate::received::hc::text::ALL),
    (
        "yw_app::received::zec::text",
        crate::received::zec::text::ALL,
    ),
    ("yw_app::rpc::text", crate::rpc::text::ALL),
    ("yw_app::settings::text", crate::settings::text::ALL),
    ("yw_app::store::reset::text", crate::store::reset::text::ALL),
    (
        "yw_app::ui::approval::labels",
        crate::ui::approval::labels::ALL,
    ),
    ("yw_app::ui::approval_text", crate::ui::approval_text::ALL),
    (
        "yw_app::ui::main_window::text",
        crate::ui::main_window::text::ALL,
    ),
    ("yw_app::ui::qr::text", crate::ui::qr::text::ALL),
    ("yw_app::ui::removed::text", crate::ui::removed::text::ALL),
    ("yw_app::ui::screens::text", crate::ui::screens::text::ALL),
    (
        "yw_app::ui::screens_book::text",
        crate::ui::screens_book::text::ALL,
    ),
    (
        "yw_app::ui::screens_btc::text",
        crate::ui::screens_btc::text::ALL,
    ),
    (
        "yw_app::ui::screens_evm::text",
        crate::ui::screens_evm::text::ALL,
    ),
    (
        "yw_app::ui::screens_explorer::text",
        crate::ui::screens_explorer::text::ALL,
    ),
    (
        "yw_app::ui::screens_hypercore::text",
        crate::ui::screens_hypercore::text::ALL,
    ),
    (
        "yw_app::ui::screens_keys::text",
        crate::ui::screens_keys::text::ALL,
    ),
    (
        "yw_app::ui::screens_links::text",
        crate::ui::screens_links::text::ALL,
    ),
    (
        "yw_app::ui::screens_llm::text",
        crate::ui::screens_llm::text::ALL,
    ),
    (
        "yw_app::ui::screens_mnemonics::text",
        crate::ui::screens_mnemonics::text::ALL,
    ),
    (
        "yw_app::ui::screens_received::text",
        crate::ui::screens_received::text::ALL,
    ),
    (
        "yw_app::ui::screens_reset::text",
        crate::ui::screens_reset::text::ALL,
    ),
    (
        "yw_app::ui::screens_sites::text",
        crate::ui::screens_sites::text::ALL,
    ),
    (
        "yw_app::ui::screens_sol::text",
        crate::ui::screens_sol::text::ALL,
    ),
    (
        "yw_app::ui::screens_walletconnect::text",
        crate::ui::screens_walletconnect::text::ALL,
    ),
    (
        "yw_app::ui::screens_yubikey::text",
        crate::ui::screens_yubikey::text::ALL,
    ),
    (
        "yw_app::ui::screens_zec::text",
        crate::ui::screens_zec::text::ALL,
    ),
    ("yw_app::ui::secret_text", crate::ui::secret_text::ALL),
    (
        "yw_app::walletconnect::text",
        crate::walletconnect::text::ALL,
    ),
    (
        "yw_app::walletconnect::worker::text",
        crate::walletconnect::worker::text::ALL,
    ),
    (
        "yw_app::workers::journal::btc::text",
        crate::workers::journal::btc::text::ALL,
    ),
    (
        "yw_app::workers::journal::zec::text",
        crate::workers::journal::zec::text::ALL,
    ),
    ("yw_app::workers::key::text", crate::workers::key::text::ALL),
    ("yw_app::yubikey::text", crate::yubikey::text::ALL),
    ("yw_app::zec::rpc::text", crate::zec::rpc::text::ALL),
];
