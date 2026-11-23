//! The Windows answers to what a screen asks the shell while it is built (spec/15 §11.3,
//! `yw_engine::screen::facts::ScreenFacts`).
//!
//! 2026-11-24 (spec/15 §11.4 S5-3): the render builders (`ui/screens*.rs`, `ui/removed.rs`) ask
//! [`App::facts`] instead of reading `yw_win`, the data folder, the `rpc.json` file, the
//! extension folder, the pipe host or the version line themselves (source check
//! `render_asks_the_shell_only_through_facts`). Each answer is computed when asked, by the same
//! call the builder made before, so the number and timing of the file probes per render are those
//! of before (`rpc_json_present` only while the network section or S08 is drawn,
//! `extension_dir` once per S23). The test seams of those calls (`app_rpc_import::TEST_RPC_JSON`,
//! `app_extension::TOUR_EXTENSION_DIR`) stay inside them. No answer carries a secret or an RPC
//! URL: the folders are the display strings the screens showed before.

use yw_core::lang::Lang;
use yw_engine::screen::facts::{PipeStatus, PlatformFlags, ScreenFacts};

use crate::app::App;

/// The Windows [`ScreenFacts`]: read-only, over the whole `App` (the shell's fields and, for the
/// version line's install record, the wallet's).
#[derive(Clone, Copy)]
pub struct WinFacts<'a> {
    app: &'a App,
}

impl core::fmt::Debug for WinFacts<'_> {
    /// No fact: only the type's name (a fact is asked, never printed).
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("WinFacts")
    }
}

#[cfg(test)]
thread_local! {
    /// Tests: the facts asked on this thread, in order (the probe count per render).
    pub static ASKED: core::cell::RefCell<Vec<&'static str>> =
        const { core::cell::RefCell::new(Vec::new()) };
}

/// Notes a fact asked (tests).
#[cfg(test)]
fn asked(fact: &'static str) {
    ASKED.with(|asked| asked.borrow_mut().push(fact));
}

/// Outside tests nothing is noted.
#[cfg(not(test))]
const fn asked(_fact: &'static str) {}

impl App {
    /// The shell facts the render builders ask (spec/15 §11.3; 2026-11-24 S5-3).
    #[must_use]
    pub const fn facts(&self) -> WinFacts<'_> {
        WinFacts { app: self }
    }
}

impl ScreenFacts for WinFacts<'_> {
    fn local_wall_ms(&self, unix_ms: u64) -> Option<u64> {
        yw_win::time::local_wall_ms(unix_ms)
    }

    fn data_dir(&self) -> String {
        self.app.paths.data.display().to_string()
    }

    fn rpc_json_present(&self) -> bool {
        asked("rpc_json_present");
        crate::app_rpc_import::rpc_json_path().is_some_and(|path| path.is_file())
    }

    fn extension_dir(&self) -> Option<String> {
        asked("extension_dir");
        crate::app_extension::extension_dir().map(|dir| dir.display().to_string())
    }

    fn expected_extension_dir(&self) -> Option<String> {
        asked("expected_extension_dir");
        crate::app_extension::expected_dir().map(|dir| dir.display().to_string())
    }

    fn pipe(&self) -> PipeStatus {
        self.app
            .pipe
            .as_ref()
            .map_or_else(PipeStatus::default, |pipe| PipeStatus {
                server: pipe.server.is_some(),
                error: pipe.error,
            })
    }

    fn version_text(&self, lang: Lang) -> String {
        crate::build_info::version_text(lang, self.app.wallet.install_commit.as_deref())
    }

    fn flags(&self) -> PlatformFlags {
        PlatformFlags::WINDOWS
    }
}
