//! The Windows lowering of the neutral screen model (spec/15 §11.2 "화면 모델 → Win32 컨트롤·GDI",
//! §11.3): `yw_engine::screen::model::Item` into this shell's own [`Item`] list, one for one, which
//! `main_window::layout`, `paint` and `ControlSet::sync` consume unchanged. A control gets its id
//! from its press or field ([`cmd_table::id_of`], [`cmd_table::edit_id_of`],
//! [`cmd_table::cred_id_of`]), a button its `theme::BUTTON_*` style, S22's hold area its one id
//! ([`screens_reset::ids::RESET_HOLD`]); the backdrop stays `None` (the layout sets it). So the
//! lowered list equals the list the screens build today, value for value (the census hashes its
//! `Debug`).
//!
//! 2026-11-24 (spec/15 §11.4 S5-2): created, with its debug count [`Lowered::press_mismatch`]: a
//! drawn press whose control id maps back to another press (a row past its id span, S3 C10–C12)
//! is counted, never panicked on; the census and the windowed form test assert 0 once the screens
//! build the model (S5-4). Until then nothing in production lowers. (2026-11-24 S5-2 review:) a
//! credential edit's text never reaches the Windows list either: the model's builders drop it,
//! and one set on the model `Ctl` afterwards is wiped, lowered empty and counted in
//! [`Lowered::cred_text`], which S5-4 asserts 0 with `press_mismatch`.
//!
//! 2026-11-24 (spec/15 §11.4 S5-4): the screens build the model (`App::screen_model`) and
//! [`App::items`] lowers it here — the Windows list the census hashes, `layout`, `paint` and
//! `ControlSet::sync` consume, value for value the list the screens built before. The screens
//! name their controls by id at first (the transitional `Act::Legacy`, drawn as that id) and by
//! press or field family by family after. Both counts go to `App::press_mismatch` (debug builds),
//! which the census asserts 0 at every observation.

use yw_engine::screen::model::{self, Act, CtlKind, Style};
use yw_win::ui::controls::{ButtonStyle, ControlKind};

use crate::app::App;
use crate::ui::cmd_table;
use crate::ui::main_window::{ControlSet, Ctl, Face, Item};
use crate::ui::screens::RECEIVE_IDS;
use crate::ui::screens_reset;
use crate::ui::theme;

/// A lowered item list and its debug count.
#[derive(Debug, Default)]
pub struct Lowered {
    /// The Windows item list.
    pub items: Vec<Item>,
    /// Drawn presses whose control id does not map back to the same control's press
    /// ([`yw_engine::cmd::Press::same_control`]: a check box's state ignored).
    pub press_mismatch: u32,
    /// Credential edits that came with text (only by setting `text` after a builder, which
    /// drops it); lowered with empty text, the text wiped.
    pub cred_text: u32,
}

/// Lowers `items` into the Windows item list.
#[must_use]
pub fn lower(items: Vec<model::Item>) -> Lowered {
    let mut lowering = Lowering {
        // No window: a check box's press maps back with the state `None`, as drawn.
        controls: ControlSet::default(),
        press_mismatch: 0,
        cred_text: 0,
    };
    let items = items.into_iter().map(|item| lowering.item(item)).collect();
    Lowered {
        items,
        press_mismatch: lowering.press_mismatch,
        cred_text: lowering.cred_text,
    }
}

impl App {
    /// The current screen as the Windows item list: the neutral screen model
    /// ([`App::screen_model`], built by the screens) lowered here (2026-11-24, spec/15 §11.4
    /// S5-4; before, the screens built this list themselves, `ui::screens`). A drawn press that
    /// maps back to another control and a credential edit that came with text are counted in
    /// `App::press_mismatch` (debug builds; the census asserts 0). Then, as before, an
    /// unverified passphrase's `받기` and `주소 복사` controls are turned off and the copy just
    /// made says so at its own control.
    #[must_use]
    pub fn items(&self) -> Vec<Item> {
        let lowered = lower(self.screen_model());
        #[cfg(debug_assertions)]
        self.press_mismatch.set(
            self.press_mismatch
                .get()
                .saturating_add(lowered.press_mismatch)
                .saturating_add(lowered.cred_text),
        );
        let mut items = lowered.items;
        if self.passphrase_unverified() {
            disable_receive(&mut items);
        }
        // The copy just made says so at its own control (2026-11-12, `Wallet::copy_text`).
        // 2026-11-20 (S4 P6): the mark holds the press; its control id is the table's.
        if let Some(copied) = self.copied {
            crate::ui::main_window::mark_copied(
                self.settings.language,
                &mut items,
                cmd_table::id_of(copied.anchor),
                copied.address,
            );
        }
        items
    }
}

/// Turns off every `받기` and `주소 복사` control in `items` (unverified-passphrase sessions;
/// 2026-11-24 S5-4: from `ui::screens`, unchanged).
fn disable_receive(items: &mut [Item]) {
    for item in items {
        match item {
            Item::Row(ctls) | Item::LabeledRow(_, ctls) | Item::Toolbar(_, ctls) => {
                for ctl in ctls.iter_mut().filter(|ctl| RECEIVE_IDS.contains(&ctl.id)) {
                    ctl.enabled = false;
                }
            }
            Item::CopyLine { value, .. } if RECEIVE_IDS.contains(&value.id) => {
                value.enabled = false;
            }
            _ => {}
        }
    }
}

/// Tests: the Windows item list of `items` (tests that call a screen builder directly; 2026-11-24,
/// S5-4).
#[cfg(test)]
#[must_use]
pub fn lowered(items: Vec<model::Item>) -> Vec<Item> {
    lower(items).items
}

/// The button style of `style`.
#[must_use]
pub const fn button_style(style: Style) -> ButtonStyle {
    match style {
        Style::Primary => theme::BUTTON_PRIMARY,
        Style::Secondary => theme::BUTTON_SECONDARY,
        Style::Danger => theme::BUTTON_DANGER,
        Style::Link => theme::BUTTON_LINK,
        Style::TabOn => theme::BUTTON_TAB_ON,
        Style::TabOff => theme::BUTTON_TAB_OFF,
        Style::Entry => theme::BUTTON_ENTRY,
        Style::EntryOn => theme::BUTTON_ENTRY_ON,
    }
}

struct Lowering {
    controls: ControlSet,
    press_mismatch: u32,
    cred_text: u32,
}

impl Lowering {
    fn id(&mut self, act: Act) -> u16 {
        match act {
            Act::Press(press) => {
                let id = cmd_table::id_of(press);
                let back = cmd_table::press_of(id, &self.controls);
                if !back.is_some_and(|back| back.same_control(press)) {
                    self.press_mismatch = self.press_mismatch.saturating_add(1);
                }
                id
            }
            Act::Field(field) => cmd_table::edit_id_of(field),
            Act::Cred(field) => cmd_table::cred_id_of(field),
            // Transitional (S5-4 only): the id the screen named, drawn as it was.
            Act::Legacy(id) => id,
        }
    }

    fn ctl(&mut self, ctl: model::Ctl) -> Ctl {
        let model::Ctl {
            act,
            kind,
            text,
            width,
            enabled,
            checked,
            limit,
            badge,
            compact,
            face,
            tip,
            fit,
        } = ctl;
        let text = if matches!(act, Act::Cred(_)) {
            if !text.is_empty() {
                self.cred_text = self.cred_text.saturating_add(1);
            }
            drop(yw_core::secret::Zeroizing::new(text));
            String::new()
        } else {
            text
        };
        Ctl {
            id: self.id(act),
            kind: match kind {
                CtlKind::Button(style) => ControlKind::Button(button_style(style)),
                CtlKind::Check => ControlKind::CheckBox,
                CtlKind::Radio { first } => ControlKind::Radio {
                    first_in_group: first,
                },
                CtlKind::Edit { password, readonly } => ControlKind::Edit { password, readonly },
            },
            text,
            width,
            enabled,
            checked,
            limit,
            backdrop: None,
            badge,
            compact,
            face: face.map(|face| match face {
                model::Face::Glyph(glyph) => Face::Glyph(glyph),
                model::Face::Value(lines) => Face::Value(lines),
                model::Face::Entry(symbol) => Face::Entry(symbol),
                model::Face::Copied(lines, caption) => Face::Copied(lines, caption),
            }),
            tip,
            fit,
        }
    }

    fn ctls(&mut self, ctls: Vec<model::Ctl>) -> Vec<Ctl> {
        ctls.into_iter().map(|ctl| self.ctl(ctl)).collect()
    }

    fn item(&mut self, item: model::Item) -> Item {
        match item {
            model::Item::Title(text) => Item::Title(text),
            model::Item::Text(text) => Item::Text(text),
            model::Item::Muted(text) => Item::Muted(text),
            model::Item::Help(text) => Item::Help(text),
            model::Item::Subtitle(text) => Item::Subtitle(text),
            model::Item::Display(text) => Item::Display(text),
            model::Item::DisplayMuted(text) => Item::DisplayMuted(text),
            model::Item::Mono(text) => Item::Mono(text),
            model::Item::CopyLine { value, actions } => Item::CopyLine {
                value: self.ctl(value),
                actions: self.ctls(actions),
            },
            model::Item::ListRow {
                title,
                note,
                value,
                dim,
            } => Item::ListRow {
                title,
                note,
                value,
                dim,
            },
            model::Item::Pill(text, tone) => Item::Pill(text, tone),
            model::Item::Menu(ctls) => Item::Menu(self.ctls(ctls)),
            model::Item::Field(label, value) => Item::Field(label, value),
            model::Item::Banner(text, tone) => Item::Banner(text, tone),
            model::Item::Gap(dip) => Item::Gap(dip),
            model::Item::Row(ctls) => Item::Row(self.ctls(ctls)),
            model::Item::LabeledRow(label, ctls) => Item::LabeledRow(label, self.ctls(ctls)),
            model::Item::Rule => Item::Rule,
            model::Item::Qr(payload) => Item::Qr(payload),
            model::Item::CardStart(heading) => Item::CardStart(heading),
            model::Item::CardEnd => Item::CardEnd,
            model::Item::Steps(labels, current) => Item::Steps(labels, current),
            model::Item::Toolbar(title, ctls) => Item::Toolbar(title, self.ctls(ctls)),
            model::Item::Badged(badge, inner) => Item::Badged(badge, Box::new(self.item(*inner))),
            model::Item::Hold {
                label,
                progress,
                enabled,
            } => Item::Hold {
                id: screens_reset::ids::RESET_HOLD,
                label,
                progress,
                enabled,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::lower;
    use crate::ui::cmd_table;
    use crate::ui::main_window::{self as win, GLYPH_COPY};
    use crate::ui::screens_reset;
    use yw_engine::badge::Badge;
    use yw_engine::cmd::{BookPress, CorePress, EvmPress, Press, ReceivedPress, Row};
    use yw_engine::form::{CredField, EditField};
    use yw_engine::received::RecvChain;
    use yw_engine::screen::Tone;
    use yw_engine::screen::model::{Ctl, Item};

    /// Every control builder lowers to the Windows builder with the press's or field's id, and
    /// every item kind to the same kind: the list equals the one built today, `Debug` included.
    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one list of every item kind and control builder, side by side with its Windows twin"
    )]
    fn the_lowered_list_equals_the_windows_list() {
        let lock = Press::Core(CorePress::Lock);
        let exit = Press::Core(CorePress::Exit);
        let ack = Press::Evm(EvmPress::SendAck(None));
        let toggle = Press::Received(ReceivedPress::Toggle {
            chain: RecvChain::Btc,
            checked: None,
        });
        let id = cmd_table::id_of;
        let rename = cmd_table::edit_id_of(EditField::CoreRename);
        let key = cmd_table::cred_id_of(CredField::LlmKey);
        let spans = vec![("0x".to_owned(), false), ("F990".to_owned(), true)];
        let badge = Badge::hyperliquid();
        let model = vec![
            Item::Title("t".to_owned()),
            Item::Text("x".to_owned()),
            Item::Muted("m".to_owned()),
            Item::Help("h".to_owned()),
            Item::Subtitle("s".to_owned()),
            Item::Display("d".to_owned()),
            Item::DisplayMuted("dm".to_owned()),
            Item::Mono("mono".to_owned()),
            Item::CopyLine {
                value: Ctl::value(lock, "주소 복사", spans.clone()),
                actions: vec![Ctl::icon(exit, GLYPH_COPY, "복사")],
            },
            Item::ListRow {
                title: "ETH".to_owned(),
                note: "Ether".to_owned(),
                value: "1".to_owned(),
                dim: true,
            },
            Item::Pill("p".to_owned(), Tone::Testnet),
            Item::Menu(vec![
                Ctl::entry(lock, "a", true),
                Ctl::entry(exit, "b", false),
            ]),
            Item::Field("l".to_owned(), "v".to_owned()),
            Item::Banner("b".to_owned(), Tone::Warn),
            Item::Gap(8),
            Item::Row(vec![
                Ctl::primary(lock, "p").width(120),
                Ctl::button(exit, "b").enabled(false).tip("tip"),
                Ctl::danger(lock, "d").compact(),
                Ctl::link(exit, "l").badge(badge),
                Ctl::tab(lock, "on", true),
                Ctl::tab(exit, "off", false),
                Ctl::picker(lock, "pick", false).fit(["a", "bb"]),
                Ctl::check(ack, "c", true),
                Ctl::check(toggle, "r", false),
            ]),
            Item::LabeledRow(
                "label".to_owned(),
                vec![
                    Ctl::edit(EditField::CoreRename, "name", 200, false, 32),
                    Ctl::edit(CredField::LlmKey, "", 200, true, 256).readonly(),
                    Ctl::radio(lock, "r1", true, true),
                    Ctl::radio(exit, "r2", false, false),
                ],
            ),
            Item::Rule,
            Item::Qr("payload".to_owned()),
            Item::CardStart(Some("card".to_owned())),
            Item::CardEnd,
            Item::Steps(vec!["1".to_owned(), "2".to_owned()], 1),
            Item::Toolbar("app".to_owned(), vec![Ctl::link(lock, "잠금")]),
            Item::Badged(badge, Box::new(Item::Subtitle("sub".to_owned()))),
            Item::Hold {
                label: "hold".to_owned(),
                progress: 500,
                enabled: true,
            },
        ];
        let windows = vec![
            win::Item::Title("t".to_owned()),
            win::Item::Text("x".to_owned()),
            win::Item::Muted("m".to_owned()),
            win::Item::Help("h".to_owned()),
            win::Item::Subtitle("s".to_owned()),
            win::Item::Display("d".to_owned()),
            win::Item::DisplayMuted("dm".to_owned()),
            win::Item::Mono("mono".to_owned()),
            win::Item::CopyLine {
                value: win::Ctl::value(id(lock), "주소 복사", spans),
                actions: vec![win::Ctl::icon(id(exit), GLYPH_COPY, "복사")],
            },
            win::Item::ListRow {
                title: "ETH".to_owned(),
                note: "Ether".to_owned(),
                value: "1".to_owned(),
                dim: true,
            },
            win::Item::Pill("p".to_owned(), Tone::Testnet),
            win::Item::Menu(vec![
                win::Ctl::entry(id(lock), "a", true),
                win::Ctl::entry(id(exit), "b", false),
            ]),
            win::Item::Field("l".to_owned(), "v".to_owned()),
            win::Item::Banner("b".to_owned(), Tone::Warn),
            win::Item::Gap(8),
            win::Item::Row(vec![
                win::Ctl::primary(id(lock), "p").width(120),
                win::Ctl::button(id(exit), "b").enabled(false).tip("tip"),
                win::Ctl::danger(id(lock), "d").compact(),
                win::Ctl::link(id(exit), "l").badge(badge),
                win::Ctl::tab(id(lock), "on", true),
                win::Ctl::tab(id(exit), "off", false),
                win::Ctl::picker(id(lock), "pick", false).fit(["a", "bb"]),
                win::Ctl::check(id(ack), "c", true),
                win::Ctl::check(id(toggle), "r", false),
            ]),
            win::Item::LabeledRow(
                "label".to_owned(),
                vec![
                    win::Ctl::edit(rename, "name", 200, false, 32),
                    win::Ctl::edit(key, "", 200, true, 256).readonly(),
                    win::Ctl::radio(id(lock), "r1", true, true),
                    win::Ctl::radio(id(exit), "r2", false, false),
                ],
            ),
            win::Item::Rule,
            win::Item::Qr("payload".to_owned()),
            win::Item::CardStart(Some("card".to_owned())),
            win::Item::CardEnd,
            win::Item::Steps(vec!["1".to_owned(), "2".to_owned()], 1),
            win::Item::Toolbar("app".to_owned(), vec![win::Ctl::link(id(lock), "잠금")]),
            win::Item::Badged(badge, Box::new(win::Item::Subtitle("sub".to_owned()))),
            win::Item::Hold {
                id: screens_reset::ids::RESET_HOLD,
                label: "hold".to_owned(),
                progress: 500,
                enabled: true,
            },
        ];
        let lowered = lower(model);
        assert_eq!((lowered.press_mismatch, lowered.cred_text), (0, 0));
        assert_eq!(lowered.items, windows);
        assert_eq!(format!("{:?}", lowered.items), format!("{windows:?}"));
    }

    /// A drawn press whose id maps back to another control's press is counted, not drawn as
    /// something else silently; a check box's state does not count.
    #[test]
    fn a_press_whose_id_maps_back_elsewhere_is_counted() {
        let checked = Press::Book(BookPress::Verified(Some(true)));
        let lowered = lower(vec![Item::Row(vec![Ctl::check(checked, "v", true)])]);
        assert_eq!(lowered.press_mismatch, 0, "the state is ignored");
        // A row past its span (S3 C10–C12): its id is another control's, or no press.
        let past = Press::Evm(EvmPress::SendAsset(Row(
            crate::ui::screens_evm::ids::SEND_ASSET_SPAN,
        )));
        assert!(
            cmd_table::press_of(cmd_table::id_of(past), &win::ControlSet::default())
                .is_none_or(|back| !back.same_control(past))
        );
        let lowered = lower(vec![
            Item::Row(vec![Ctl::button(past, "x")]),
            Item::Menu(vec![Ctl::button(Press::Core(CorePress::Lock), "ok")]),
        ]);
        assert_eq!(lowered.press_mismatch, 1);
    }
    /// A credential edit whose text was set on the model after its builder is lowered with
    /// empty text and counted (2026-11-24 S5-2 review): no credential text reaches the Windows
    /// list or its `Debug` (which the census hashes).
    #[test]
    fn a_credential_text_never_reaches_the_windows_list() {
        let given = "not-a-real-key-7f3a";
        let mut cred = Ctl::edit(CredField::LlmKey, given, 200, true, 256);
        assert!(cred.text.is_empty(), "the builder drops it");
        cred.text = given.to_owned();
        let lowered = lower(vec![Item::LabeledRow(
            "key".to_owned(),
            vec![
                cred,
                Ctl::edit(EditField::CoreRename, "name", 200, false, 32),
            ],
        )]);
        assert_eq!(lowered.cred_text, 1);
        assert!(!format!("{:?}", lowered.items).contains(given));
        let key = cmd_table::cred_id_of(CredField::LlmKey);
        let rename = cmd_table::edit_id_of(EditField::CoreRename);
        assert_eq!(
            lowered.items,
            vec![win::Item::LabeledRow(
                "key".to_owned(),
                vec![
                    win::Ctl::edit(key, "", 200, true, 256),
                    win::Ctl::edit(rename, "name", 200, false, 32),
                ],
            )]
        );
    }
}
