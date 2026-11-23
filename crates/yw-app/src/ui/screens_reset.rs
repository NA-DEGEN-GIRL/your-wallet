//! S22 `지갑 초기화` (spec/04 §2.20), S23 `Chrome 확장 설치` (§2.21), their entry links, and
//! T-WAIT-STALLED (a wait past `app_reset::WAIT_TIMEOUT_MS`).
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): the builders, their helpers and texts moved to yw-engine
//! `screen::build::reset` (bodies unchanged); this file keeps the control ids of its controls
//! (`ids`) and the tests that need an `App`, which only the Windows shell has.

/// Command ids (block 13,400–13,449, `ui::command_ids`).
pub mod ids {
    /// `지갑 초기화…` (S07, S09, S04, S01 with T-LEFTOVER, settings → 보안, T-WAIT-STALLED).
    pub const RESET_OPEN: u16 = 13_400;
    /// S22 confirmation field.
    pub const RESET_PHRASE: u16 = 13_401;
    /// S22 `설정과 API 키도 함께 옮기기`.
    pub const RESET_SETTINGS_CHECK: u16 = 13_402;
    /// S22 hold area (2 s).
    pub const RESET_HOLD: u16 = 13_403;
    /// S22 `취소`.
    pub const RESET_CANCEL: u16 = 13_404;
    /// T-WAIT-STALLED `다시 불러오기`.
    pub const WAIT_RETRY: u16 = 13_410;
    /// `Chrome 확장 설치` (settings, S08, S13).
    pub const EXT_OPEN: u16 = 13_420;
    /// S23 `← 돌아가기`.
    pub const EXT_BACK: u16 = 13_421;
    /// S23 `탐색기에서 폴더 열기`.
    pub const EXT_OPEN_FOLDER: u16 = 13_422;
    /// S23 `확장 폴더 경로 복사`.
    pub const EXT_COPY_PATH: u16 = 13_423;
    /// S23 `chrome://extensions 주소 복사`.
    pub const EXT_COPY_URL: u16 = 13_424;

    /// Every fixed id of this module.
    pub const FIXED: &[u16] = &[
        RESET_OPEN,
        RESET_PHRASE,
        RESET_SETTINGS_CHECK,
        RESET_HOLD,
        RESET_CANCEL,
        WAIT_RETRY,
        EXT_OPEN,
        EXT_BACK,
        EXT_OPEN_FOLDER,
        EXT_COPY_PATH,
        EXT_COPY_URL,
    ];

    /// The S22 / T-WAIT-STALLED press control `id` stands for (2026-11-18, S3 C5:
    /// `ui::cmd_table`); `설정과 API 키도 함께 옮기기` carries its box's state now. `None` when
    /// `id` is not one of them: the confirmation edit is a field, and the 2 s hold area
    /// ([`RESET_HOLD`]) is a mouse hold, never a press.
    #[must_use]
    pub fn reset_press_of(
        id: u16,
        controls: &crate::ui::main_window::ControlSet,
    ) -> Option<yw_engine::cmd::ResetPress> {
        use yw_engine::cmd::ResetPress;
        Some(match id {
            RESET_OPEN => ResetPress::Open,
            RESET_SETTINGS_CHECK => ResetPress::SettingsCheck(controls.checked(id)),
            RESET_CANCEL => ResetPress::Cancel,
            WAIT_RETRY => ResetPress::WaitRetry,
            _ => return None,
        })
    }

    /// The control id of `press` (the inverse of [`reset_press_of`]).
    #[must_use]
    pub const fn reset_id_of(press: yw_engine::cmd::ResetPress) -> u16 {
        use yw_engine::cmd::ResetPress;
        match press {
            ResetPress::Open => RESET_OPEN,
            ResetPress::SettingsCheck(_) => RESET_SETTINGS_CHECK,
            ResetPress::Cancel => RESET_CANCEL,
            ResetPress::WaitRetry => WAIT_RETRY,
        }
    }

    /// The S23 press control `id` stands for (2026-11-18, S3 C5: `ui::cmd_table`); `None` when
    /// `id` is not one of them.
    #[must_use]
    pub const fn ext_press_of(id: u16) -> Option<yw_engine::cmd::ExtPress> {
        use yw_engine::cmd::ExtPress;
        Some(match id {
            EXT_OPEN => ExtPress::Open,
            EXT_BACK => ExtPress::Back,
            EXT_OPEN_FOLDER => ExtPress::OpenFolder,
            EXT_COPY_PATH => ExtPress::CopyPath,
            EXT_COPY_URL => ExtPress::CopyUrl,
            _ => return None,
        })
    }

    /// The control id of `press` (the inverse of [`ext_press_of`]).
    #[must_use]
    pub const fn ext_id_of(press: yw_engine::cmd::ExtPress) -> u16 {
        use yw_engine::cmd::ExtPress;
        match press {
            ExtPress::Open => EXT_OPEN,
            ExtPress::Back => EXT_BACK,
            ExtPress::OpenFolder => EXT_OPEN_FOLDER,
            ExtPress::CopyPath => EXT_COPY_PATH,
            ExtPress::CopyUrl => EXT_COPY_URL,
        }
    }
}

#[cfg(test)]
mod tests {
    use yw_core::lang::{Lang, has_hangul};

    use crate::app::{App, Paths};
    use crate::ui::main_window::Item;
    use yw_engine::apikeys::ApiKeys;
    use yw_engine::settings::Settings;

    use yw_engine::testkit::ScreenTestExt;
    /// Every fixed text of `items` (titles, lines, field labels, control labels); field values
    /// are data (paths, file names) and left out.
    fn fixed_texts(items: &[Item]) -> Vec<String> {
        let mut out = Vec::new();
        for item in items {
            match item {
                Item::Title(text)
                | Item::Text(text)
                | Item::Muted(text)
                | Item::Help(text)
                | Item::Banner(text, _)
                | Item::CardStart(Some(text)) => out.push(text.clone()),
                Item::Field(label, _) | Item::Hold { label, .. } => out.push(label.clone()),
                Item::LabeledRow(label, ctls) => {
                    out.push(label.clone());
                    out.extend(ctls.iter().map(|ctl| ctl.text.clone()));
                }
                Item::Row(ctls) => out.extend(ctls.iter().map(|ctl| ctl.text.clone())),
                _ => {}
            }
        }
        out
    }

    fn app(lang: Lang) -> (App, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "yw-reset-screen-{}-{}",
            std::process::id(),
            yw_win::time::monotonic_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let settings = Settings {
            language: lang,
            ..Settings::default()
        };
        let app = App::new(
            Paths {
                data: dir.clone(),
                logs: dir.join("logs"),
            },
            true,
            settings,
            ApiKeys::default(),
        );
        (app, dir)
    }

    /// S22, S23 and T-WAIT-STALLED in English have no Hangul (spec/14); the confirmation phrase
    /// is the language's own.
    #[test]
    fn english_reset_and_extension_screens() {
        let (mut app, dir) = app(Lang::En);
        let mut items = Vec::new();
        app.reset_screen(&app.facts(), &mut items);
        app.reset.phrase_ok = true;
        app.reset_screen(&app.facts(), &mut items);
        app.extension_screen(&app.facts(), &mut items);
        app.extension_link(&app.facts(), &mut items);
        app.wait_stalled(&app.facts(), &mut items);
        yw_engine::testkit::screen::reset_link(Lang::En, &mut items, "help");
        let items = crate::ui::lower::lowered(items);
        let texts = fixed_texts(&items);
        assert!(texts.iter().any(|text| text == "Reset wallet"), "{texts:?}");
        for text in &texts {
            assert!(!has_hangul(text), "{text}");
        }
        assert!(yw_engine::wallet::app_reset::phrase_matches(
            Lang::En,
            " reset "
        ));
        assert!(!yw_engine::wallet::app_reset::phrase_matches(
            Lang::En,
            "초기화"
        ));
        assert!(yw_engine::wallet::app_reset::phrase_matches(
            Lang::Ko,
            "초기화"
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
