//! Every text catalogue of yw-app with its module path (spec/14 §5). `scripts/i18n-scan.mjs`
//! checks that each `texts!` block of the source is listed here, and `tests/lang_spec.rs` that
//! each one is in the spec tables (`errors::text` in spec/04 §7 instead, D31). The screenshot
//! tour's scene texts (`ui::tour`, a test module) are not app texts and are not listed.
//! (2026-11-17, spec/15 §11.4 S2: the catalogues of modules moved to yw-engine are listed in
//! `yw_engine::catalogues` under their true path; E1 the approval, error and card texts, E2 the
//! settings, metadata, explain, RPC pipeline and `WalletConnect` engine texts, E3 the
//! `WalletConnect` worker and key/journal worker texts. 2026-11-20, S4 P7a1: the secret windows'
//! texts, before `yw_app::ui::secret_text`, are `yw_engine::secret::text`. 2026-11-23, S4d E1: the
//! catalogues of the wallet modules, before `yw_app::app_*::text` and the wallet's half of
//! `yw_app::app::text`, are `yw_engine::wallet::…::text`. 2026-11-23, spec/15 §11.4 S5-0 (S5 plan
//! critic C6, O-13): `yw_app::app::text` names the shell's own block `crate::app::text::ALL`;
//! from E1 until S5-0 it named `yw_engine::wallet::text::ALL`, which the engine lists under its
//! own name too, so the six shell texts were in no table. 2026-11-24, spec/15 §11.4 S5-5: the
//! screens' catalogues, before `yw_app::ui::screens*::text` and `yw_app::ui::removed::text`, are
//! `yw_engine::screen::build::…::text` (`screens` became `core`), the `rpc.json` card's, before
//! `yw_app::app_rpc_import::text`, `yw_engine::screen::build::rpc_import::text`, S23's, before
//! `yw_app::app_extension::text`, `yw_engine::screen::extension::text`, and the receive note's,
//! before `yw_app::ui::qr::text`, `yw_engine::screen::qr::text`: each moved with the builders that
//! draw it, its wording unchanged; `T_PASSWORD_OLD_COPIES` left this crate's `app::text` for
//! `yw_engine::screen::build::core::text`.)

use yw_core::lang::Entry;

/// The catalogues, in module path order.
#[must_use]
pub fn catalogues() -> Vec<(&'static str, &'static [Entry])> {
    CATALOGUES.to_vec()
}

const CATALOGUES: &[(&str, &[Entry])] = &[
    ("yw_app::app::text", crate::app::text::ALL),
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
];
