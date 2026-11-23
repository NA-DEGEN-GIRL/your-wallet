//! The screen builders (spec/15 §11.2, §11.3, §11.4 S5-5): every main-window screen S01–S23 as
//! the neutral model ([`crate::screen::model::Item`]), built from the wallet state and the facts
//! the platform shell is asked ([`ScreenFacts`]). The one entry is [`crate::wallet::Wallet::screen`];
//! a shell lowers the list it returns into its own controls (Windows: yw-app `ui::lower`).
//!
//! 2026-11-24 (spec/15 §11.4 S5-5): moved here from yw-app's render files (`ui/screens*.rs`,
//! `ui/removed.rs`, where they were `impl App` builders; S5-3 made them ask the shell only through
//! the facts and S5-4 made them name presses and fields instead of control ids). The bodies are
//! unchanged: they were `impl App` blocks reaching the wallet through `App`'s `Deref`; here they
//! are `impl Screen<'_>` blocks reaching it through [`Screen`]'s, a read-only view (`&Wallet`), so
//! a builder cannot change wallet state but through the two drawn-row cells the S13 page and the
//! `WalletConnect` panel refill (source check `the_screen_writes_no_wallet_state`). The module
//! names are the yw-app files' without `screens_` (`screens.rs` is [`core`]); each keeps its text
//! catalogue, registered at its engine path (`yw_engine::catalogues`). The control ids stay in
//! yw-app (`ui::screens*::ids`, `ui::cmd_table`), which alone gives a control its id.
//!
//! The module is crate-private: no shell builds a [`Screen`] or calls a builder but through
//! [`crate::wallet::Wallet::screen`]. yw-app tests that draw one part of a screen reach the
//! builders, their pure helpers and texts through `crate::testkit` (`screen`, `ScreenTestExt`),
//! which production code never names (source check `testkit_is_named_only_by_tests`).

pub mod accounts;
pub mod book;
pub mod btc;
pub mod core;
pub mod evm;
pub mod explorer;
pub mod hidden;
pub mod hypercore;
pub mod keys;
pub mod links;
pub mod llm;
pub mod mnemonics;
pub mod received;
pub mod removed;
pub mod reset;
pub mod rpc_import;
pub mod sidecar;
pub mod sites;
pub mod sol;
pub mod walletconnect;
pub mod yubikey;
pub mod zec;

use yw_core::lang::Lang;

use crate::screen::facts::{PipeStatus, PlatformFlags, ScreenFacts};
use crate::wallet::Wallet;

/// A read-only view of the wallet with the shell's facts, which the screen builders are methods
/// of (spec/15 §11.3). It derefs to the [`Wallet`], so a builder reads the wallet's fields and
/// calls its `&self` fns as it did on yw-app's `App`.
#[derive(Clone, Copy)]
pub struct Screen<'a> {
    wallet: &'a Wallet,
    facts: Facts<'a>,
}

impl<'a> Screen<'a> {
    /// The view of `wallet` with `facts` (made by [`Wallet::screen`] and `crate::testkit`).
    #[must_use]
    pub(crate) const fn new(wallet: &'a Wallet, facts: &'a dyn ScreenFacts) -> Self {
        Self {
            wallet,
            facts: Facts(facts),
        }
    }

    /// The shell facts a builder asks (spec/15 §11.3), at the point it asks them.
    #[must_use]
    pub const fn facts(&self) -> Facts<'a> {
        self.facts
    }
}

impl ::core::ops::Deref for Screen<'_> {
    type Target = Wallet;

    fn deref(&self) -> &Wallet {
        self.wallet
    }
}

impl ::core::fmt::Debug for Screen<'_> {
    /// Only the type's name: a screen is drawn, never printed.
    fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        formatter.write_str("Screen")
    }
}

/// The shell's facts as a builder holds them: a copy of the reference, answering by delegation
/// (so `&self.facts()` is a `&dyn ScreenFacts` as the yw-app builders passed it).
#[derive(Clone, Copy)]
pub struct Facts<'a>(&'a dyn ScreenFacts);

impl ::core::fmt::Debug for Facts<'_> {
    /// No fact: only the type's name (a fact is asked, never printed).
    fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        formatter.write_str("Facts")
    }
}

impl ScreenFacts for Facts<'_> {
    fn local_wall_ms(&self, unix_ms: u64) -> Option<u64> {
        self.0.local_wall_ms(unix_ms)
    }

    fn data_dir(&self) -> String {
        self.0.data_dir()
    }

    fn rpc_json_present(&self) -> bool {
        self.0.rpc_json_present()
    }

    fn extension_dir(&self) -> Option<String> {
        self.0.extension_dir()
    }

    fn expected_extension_dir(&self) -> Option<String> {
        self.0.expected_extension_dir()
    }

    fn pipe(&self) -> PipeStatus {
        self.0.pipe()
    }

    fn version_text(&self, lang: Lang) -> String {
        self.0.version_text(lang)
    }

    fn flags(&self) -> PlatformFlags {
        self.0.flags()
    }
}
