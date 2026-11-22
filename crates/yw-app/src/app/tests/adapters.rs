//! The tests' id adapters of the families whose files move to the engine at S4d E1 (2026-11-22,
//! S4d E0c: moved here from `app_btc_commands`, `app_explorer`, `app_sol_commands`, `app_keys`,
//! `app_llm`, `app_hidden` and `app_browser`, where they were `#[cfg(test)]` fns of `impl App`
//! blocks). They press a control id through `ui::cmd_table` (S3 C1–C9, plan §3.2) or compare the
//! dispatcher's view (S3 A3), so they are shell test code; the method names and bodies are
//! unchanged, and every test that calls them is unchanged.

use crate::app::App;

impl App {
    /// Test adapter (S3 C9, plan §3.2): presses Bitcoin control `id` directly, as the tests did
    /// before; `false` when `id` is not one.
    /// Was in `app_btc_commands` until 2026-11-22 (S4d E0c).
    pub(crate) fn on_btc_command(&mut self, id: u16) -> bool {
        self.press_family(
            id,
            |press| match press {
                yw_engine::cmd::Press::Btc(press) => Some(press),
                _ => None,
            },
            |app, press| {
                app.on_btc(press);
                true
            },
        )
    }

    /// Test adapter (S3 C3, plan §3.2): presses explorer control `id` directly, as the tests
    /// did before; `false` when `id` is not one.
    /// Was in `app_explorer` until 2026-11-22 (S4d E0c).
    pub(crate) fn on_explorer_command(&mut self, id: u16) -> bool {
        self.press_family(
            id,
            |press| match press {
                yw_engine::cmd::Press::Explorer(press) => Some(press),
                _ => None,
            },
            |app, press| {
                app.on_explorer(press);
                true
            },
        )
    }

    /// Test adapter (S3 C8, plan §3.2): presses Solana control `id` directly, as the tests did
    /// before; `false` when `id` is not one.
    /// Was in `app_sol_commands` until 2026-11-22 (S4d E0c).
    pub(crate) fn on_sol_command(&mut self, id: u16) -> bool {
        self.press_family(
            id,
            |press| match press {
                yw_engine::cmd::Press::Sol(press) => Some(press),
                _ => None,
            },
            |app, press| {
                app.on_sol(press);
                true
            },
        )
    }

    /// Test adapter (S3 C5, plan §3.2): presses imported-key control `id` directly, as the tests
    /// did before; `false` when `id` is not one.
    /// Was in `app_keys` until 2026-11-22 (S4d E0c).
    pub(crate) fn on_keys_command(&mut self, id: u16) -> bool {
        self.press_family(
            id,
            |press| match press {
                yw_engine::cmd::Press::Keys(press) => Some(press),
                _ => None,
            },
            |app, press| {
                app.on_keys(press);
                true
            },
        )
    }

    /// Test adapter (S3 C3, plan §3.2): presses AI-section control `id` directly, as the tests
    /// and the screenshot tour did before; `false` when `id` is not one.
    /// Was in `app_llm` until 2026-11-22 (S4d E0c).
    pub(crate) fn on_llm_command(&mut self, id: u16) -> bool {
        self.press_family(
            id,
            |press| match press {
                yw_engine::cmd::Press::Llm(press) => Some(press),
                _ => None,
            },
            |app, press| {
                app.on_llm(press);
                true
            },
        )
    }

    /// Test adapter (S3 C1, plan §3.2): presses hidden-account control `id` directly, as the
    /// tests did before; `false` when `id` is not one.
    /// Was in `app_hidden` until 2026-11-22 (S4d E0c).
    pub(crate) fn on_hidden_command(&mut self, id: u16) -> bool {
        self.press_family(
            id,
            |press| match press {
                yw_engine::cmd::Press::Hidden(press) => Some(press),
                _ => None,
            },
            |app, press| {
                app.on_hidden(press);
                true
            },
        )
    }

    /// Tests (2026-11-18, S3 A3): whether the dispatcher holds the view the UI state gives now
    /// (`sync_browser` ran after the last change; spec/05 §4.5).
    /// Was in `app_browser` until 2026-11-22 (S4d E0c).
    pub(crate) fn browser_view_current(&self) -> bool {
        self.browser.as_ref().is_some_and(|browser| {
            format!("{:?}", browser.core.wallet()) == format!("{:?}", self.wallet_view())
        })
    }
}
