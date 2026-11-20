//! Every text catalogue of yw-engine with its module path (spec/14 §5). `scripts/i18n-scan.mjs`
//! checks that each `texts!` block of the source is listed here, and yw-app `tests/lang_spec.rs`
//! that each one is in the spec tables (`errors::text` in spec/04 §7 instead, D31).
//! (2026-11-17, spec/15 §11.4 S2: the catalogues of the modules that moved out of yw-app; before,
//! they were listed in yw-app `catalogues` as `yw_app::…`; E1 the approval, error and card texts,
//! E2 the settings, metadata, explain, RPC pipeline and `WalletConnect` engine texts, E3 the
//! `WalletConnect` worker and key/journal worker texts. 2026-11-20, S4 P7a1: the secret windows'
//! texts `secret::text`, before `yw_app::ui::secret_text`.)

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
    ("yw_engine::secret::text", crate::secret::text::ALL),
    ("yw_engine::settings::text", crate::settings::text::ALL),
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
