//! Every text catalogue of yw-engine with its module path (spec/14 §5). `scripts/i18n-scan.mjs`
//! checks that each `texts!` block of the source is listed here, and yw-app `tests/lang_spec.rs`
//! that each one is in the spec tables (`errors::text` in spec/04 §7 instead, D31).
//! (2026-11-17, spec/15 §11.4 S2: the catalogues of the modules that moved out of yw-app; before,
//! they were listed in yw-app `catalogues` as `yw_app::…`.)

use yw_core::lang::Entry;

/// The catalogues, in module path order.
#[must_use]
pub fn catalogues() -> Vec<(&'static str, &'static [Entry])> {
    CATALOGUES.to_vec()
}

const CATALOGUES: &[(&str, &[Entry])] = &[
    ("yw_engine::approval::labels", crate::approval::labels::ALL),
    ("yw_engine::approval::text", crate::approval::text::ALL),
    ("yw_engine::errors::text", crate::errors::text::ALL),
    ("yw_engine::yubikey::text", crate::yubikey::text::ALL),
];
