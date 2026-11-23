//! Every text catalogue of yw-app with its module path (spec/14 §5). `scripts/i18n-scan.mjs`
//! checks that each `texts!` block of the source is listed here, and `tests/lang_spec.rs` that
//! each one is in the spec tables (`errors::text` in spec/04 §7 instead, D31). The screenshot
//! tour's scene texts (`ui::tour`, a test module) are not app texts and are not listed.
//! (2026-11-17, spec/15 §11.4 S2: the catalogues of modules moved to yw-engine are listed in
//! `yw_engine::catalogues` under their true path; E1 the approval, error and card texts, E2 the
//! settings, metadata, explain, RPC pipeline and `WalletConnect` engine texts, E3 the
//! `WalletConnect` worker and key/journal worker texts. 2026-11-20, S4 P7a1: the secret windows'
//! texts, before `yw_app::ui::secret_text`, are `yw_engine::secret::text`.)

use yw_core::lang::Entry;

/// The catalogues, in module path order.
#[must_use]
pub fn catalogues() -> Vec<(&'static str, &'static [Entry])> {
    CATALOGUES.to_vec()
}

const CATALOGUES: &[(&str, &[Entry])] = &[
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
    ("yw_app::app_rpc_plan::text", crate::app_rpc_plan::text::ALL),
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
    (
        "yw_app::build_info::start_text",
        crate::build_info::start_text::ALL,
    ),
    ("yw_app::build_info::text", crate::build_info::text::ALL),
    ("yw_app::store::reset::text", crate::store::reset::text::ALL),
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
];
