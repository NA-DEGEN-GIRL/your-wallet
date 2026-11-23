//! The neutral screen model (spec/15 §11.3): what a main-window screen shows, as a vertical list of
//! [`Item`]s, in kinds every platform can draw — text (title, paragraph, address), values (copy
//! lines, list rows, label and value), status bands, rows of controls, a hold area, structure
//! (gaps, cards, steps, badges) and a QR payload. A control names what it does ([`Act`]: a
//! [`Press`] or a field), never a platform control id, window handle, pixel or secret text; a
//! credential edit is an [`Act::Cred`] with empty text: every builder drops the text it is given
//! for one (2026-11-24 S5-2 review: before, only the callers kept it empty), and the Windows
//! lowering blanks and counts one whose `text` was set afterwards (yw-app `ui::lower`).
//!
//! 2026-11-24 (spec/15 §11.3, §11.4 S5-2): created, one kind per kind of the Windows
//! `ui::main_window::Item` with the same payloads and the same control builder API, so the Windows
//! shell lowers it one for one into its own item list (yw-app `ui::lower`: the control id from the
//! press or field tables, the button style from [`Style`]) and lays it out and paints it as before.
//! What stays Windows-only: the layout metrics, the colors and fonts, the button backdrop (set by
//! the layout), the QR pixel layout, the control ids. The screens start building this model in
//! S5-4; until then only the lowering and its tests use it.
//!
//! 2026-11-24 (spec/15 §11.4 S5-4): the screens build it, naming each control's press or field
//! (a family press is an [`Act`] through `From`); [`mark_copied`] and [`disable_receive`] find
//! their controls by press; the row bound of each list is `screen::rows`. No control id is named
//! here or in the screens (yw-app source check `the_screen_model_names_no_control_id`).

use yw_core::lang::Lang;

use crate::badge::Badge;
use crate::cmd::{
    BookPress, BtcPress, CorePress, EvmPress, ExplorerPress, ExtPress, HcPress, HiddenPress,
    KeysPress, LinksPress, LlmPress, MnPress, Press, ReceivedPress, ResetPress, RpcImportPress,
    SidecarPress, SitesPress, SolPress, WcPress, YkConnectPress, YkManagePress, YkPress, ZecPress,
};
use crate::form::{CredField, EditField};
use crate::screen::Tone;

/// The fixed texts of the copy mark ([`mark_copied`], spec/14). 2026-11-24 (spec/15 §11.4 S5-4):
/// moved from yw-app `ui::main_window::text` with the mark (wording unchanged; the fourth entry,
/// `QR_TOO_NARROW`, stays with the Windows layout).
pub mod text {
    yw_core::texts! {
        /// What a control says for about 1.5 s after its copy (2026-11-12,
        /// [`super::mark_copied`]).
        T_COPIED = "복사됨" / "Copied";
        /// The same after an address copy: with the paste check, in short (address poisoning).
        T_COPIED_ADDRESS = "복사됨 · 붙여넣은 뒤 전체 확인" / "Copied · check it whole after pasting";
        /// The paste check alone: after the row of a text button that says `복사됨` for an
        /// address.
        T_PASTE_CHECK = "붙여넣은 뒤 전체 확인" / "Check it whole after pasting";
    }
}

pub use text::{T_COPIED, T_COPIED_ADDRESS, T_PASTE_CHECK};

/// What a control does: the press it sends, or the field it edits (spec/15 §11.3: 버튼은 `Cmd`,
/// 입력 칸은 필드 id).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Act {
    /// A button, link, check box or radio: its press (a check box's or radio's state is read
    /// when it is clicked, so a model press carries `None` for it).
    Press(Press),
    /// A plain edit.
    Field(EditField),
    /// A masked credential edit (its text is never in the model).
    Cred(CredField),
    // 2026-11-24 (spec/15 §11.4 S5-4): between the flip commit and the last S5-4 commit a
    // fourth, transitional act held a Windows control id (drawn as that id, `From<u16>`), while
    // the screens moved from ids to presses; it is gone (as S3 D3 removed `Press::Legacy`), and
    // yw-app source check `the_screen_model_names_no_control_id` keeps it out.
}

impl From<Press> for Act {
    fn from(press: Press) -> Self {
        Self::Press(press)
    }
}

impl From<EditField> for Act {
    fn from(field: EditField) -> Self {
        Self::Field(field)
    }
}

impl From<CredField> for Act {
    fn from(field: CredField) -> Self {
        Self::Cred(field)
    }
}

/// A family's press is an [`Act::Press`] (2026-11-24, S5-4): the screens write
/// `Ctl::button(CorePress::Lock, …)`.
macro_rules! family_acts {
    ($($family:ident),* $(,)?) => {
        $(
            impl From<$family> for Act {
                fn from(press: $family) -> Self {
                    Self::Press(press.into())
                }
            }
        )*
    };
}

family_acts! {
    CorePress, ReceivedPress, SitesPress, LlmPress, WcPress, HiddenPress, SidecarPress,
    ExplorerPress, LinksPress, BookPress, ResetPress, ExtPress, KeysPress, RpcImportPress,
    MnPress, HcPress, ZecPress, SolPress, BtcPress, EvmPress, YkPress, YkManagePress,
    YkConnectPress,
}

/// A button's look (Windows: `ui::theme::BUTTON_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    /// The screen's main action.
    Primary,
    /// Every other action.
    Secondary,
    /// A destructive action.
    Danger,
    /// A text-only navigation or show/hide button.
    Link,
    /// The selected segment of a tab or chip row.
    TabOn,
    /// Another segment.
    TabOff,
    /// One entry of an open drop-down.
    Entry,
    /// The selected entry.
    EntryOn,
}

/// A control's kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtlKind {
    /// A push button.
    Button(Style),
    /// A check box.
    Check,
    /// A radio button; `first` starts its group.
    Radio {
        /// First of its group.
        first: bool,
    },
    /// A single-line edit.
    Edit {
        /// Masked (a credential).
        password: bool,
        /// Read-only.
        readonly: bool,
    },
}

/// Symbol of a copy action (Segoe UI Symbol U+29C9 TWO JOINED SQUARES).
pub const GLYPH_COPY: &str = "\u{29C9}";
/// Symbol of "open in the browser" (U+2197 NORTH EAST ARROW).
pub const GLYPH_OPEN: &str = "\u{2197}";
/// Symbol of "copy the explorer link" (U+1F517 LINK SYMBOL, monochrome in Segoe UI Symbol).
pub const GLYPH_LINK: &str = "\u{1F517}";
/// Symbol of "save to the address book" (U+2606 WHITE STAR).
pub const GLYPH_SAVE: &str = "\u{2606}";
/// A closed drop-down (U+25BE BLACK DOWN-POINTING SMALL TRIANGLE).
pub const GLYPH_DOWN: &str = "\u{25BE}";
/// An open drop-down (U+25B4 BLACK UP-POINTING SMALL TRIANGLE).
pub const GLYPH_UP: &str = "\u{25B4}";
/// The selected entry of a drop-down, and a copy just made (U+2713 CHECK MARK).
pub const GLYPH_CHECK: &str = "\u{2713}";

/// What a button draws instead of its label ([`Ctl::face`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Face {
    /// A symbol, centered: an icon button.
    Glyph(&'static str),
    /// A copyable value (an address or a hash): mono `(text, emphasized)` spans by line — the
    /// screen gives one line, the layout breaks it to the button's width — with [`GLYPH_COPY`] at
    /// the right end.
    Value(Vec<Vec<(String, bool)>>),
    /// A drop-down's selector or one of its entries: the label after the badge, and the symbol
    /// ([`GLYPH_DOWN`], [`GLYPH_UP`], [`GLYPH_CHECK`]) at the right end.
    Entry(Option<&'static str>),
    /// A [`Face::Value`] right after its copy: the same lines with [`GLYPH_CHECK`] where the copy
    /// symbol is, and the caption (`복사됨`) after the line's actions.
    Copied(Vec<Vec<(String, bool)>>, &'static str),
}

/// A control in a row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ctl {
    /// What it does.
    pub act: Act,
    /// Kind.
    pub kind: CtlKind,
    /// Label / initial text (empty for a credential edit: the builders drop it).
    pub text: String,
    /// Width in DIP (0 = from the label).
    pub width: i32,
    /// Enabled.
    pub enabled: bool,
    /// Check state for check boxes and radios (and the selected tab).
    pub checked: Option<bool>,
    /// Edit length limit.
    pub limit: Option<u32>,
    /// A chain badge drawn before a button's label.
    pub badge: Option<Badge>,
    /// A small button: the actions inside a list row.
    pub compact: bool,
    /// What a button draws instead of its label (the label stays its accessible name).
    pub face: Option<Face>,
    /// The tooltip shown while the pointer rests on the control.
    pub tip: Option<String>,
    /// Other labels the control is sized for ([`Ctl::fit`]).
    pub fit: Vec<String>,
}

impl Ctl {
    /// Every builder ends here. A credential edit's text never enters the model (spec/15 §11.3;
    /// 2026-11-24 S5-2 review: before, `Ctl::edit(CredField::…, "x", …)` kept `x`, and `Debug`
    /// printed it).
    fn new(act: Act, kind: CtlKind, text: &str) -> Self {
        let text = if matches!(act, Act::Cred(_)) {
            String::new()
        } else {
            text.to_owned()
        };
        Self {
            act,
            kind,
            text,
            width: 0,
            enabled: true,
            checked: None,
            limit: None,
            badge: None,
            compact: false,
            face: None,
            tip: None,
            fit: Vec::new(),
        }
    }

    fn styled(act: impl Into<Act>, text: &str, style: Style) -> Self {
        Self::new(act.into(), CtlKind::Button(style), text)
    }

    /// A secondary push button (every action that is not the screen's main one).
    #[must_use]
    pub fn button(act: impl Into<Act>, text: &str) -> Self {
        Self::styled(act, text, Style::Secondary)
    }

    /// The primary push button (the screen's main action).
    #[must_use]
    pub fn primary(act: impl Into<Act>, text: &str) -> Self {
        Self::styled(act, text, Style::Primary)
    }

    /// A destructive action (삭제, 연결 해제 …).
    #[must_use]
    pub fn danger(act: impl Into<Act>, text: &str) -> Self {
        Self::styled(act, text, Style::Danger)
    }

    /// A text-only navigation or show/hide button (← 메인으로, 고급 ▸).
    #[must_use]
    pub fn link(act: impl Into<Act>, text: &str) -> Self {
        Self::styled(act, text, Style::Link)
    }

    /// One segment of a tab or chip row; `checked == Some(selected)`.
    #[must_use]
    pub fn tab(act: impl Into<Act>, text: &str, selected: bool) -> Self {
        let mut ctl = Self::styled(
            act,
            text,
            if selected {
                Style::TabOn
            } else {
                Style::TabOff
            },
        );
        ctl.checked = Some(selected);
        ctl
    }

    /// The selector of a drop-down: the selected entry's label with ▾ (▴ while `open`) at the
    /// right end. The list is the [`Item::Menu`] after its row.
    #[must_use]
    pub fn picker(act: impl Into<Act>, text: &str, open: bool) -> Self {
        let mut ctl = Self::button(act, text);
        ctl.face = Some(Face::Entry(Some(if open { GLYPH_UP } else { GLYPH_DOWN })));
        ctl
    }

    /// One entry of an open drop-down; `checked == Some(selected)` (the selected one is tinted
    /// and carries a ✓).
    #[must_use]
    pub fn entry(act: impl Into<Act>, text: &str, selected: bool) -> Self {
        let mut ctl = Self::styled(
            act,
            text,
            if selected {
                Style::EntryOn
            } else {
                Style::Entry
            },
        );
        ctl.checked = Some(selected);
        ctl.compact = true;
        ctl.face = Some(Face::Entry(selected.then_some(GLYPH_CHECK)));
        ctl
    }

    /// Sizes the control for the widest of `labels` too.
    #[must_use]
    pub fn fit<'a>(mut self, labels: impl IntoIterator<Item = &'a str>) -> Self {
        self.fit = labels.into_iter().map(str::to_owned).collect();
        self
    }

    /// A check box.
    #[must_use]
    pub fn check(act: impl Into<Act>, text: &str, checked: bool) -> Self {
        let mut ctl = Self::new(act.into(), CtlKind::Check, text);
        ctl.checked = Some(checked);
        ctl
    }

    /// A radio button.
    #[must_use]
    pub fn radio(act: impl Into<Act>, text: &str, checked: bool, first: bool) -> Self {
        let mut ctl = Self::new(act.into(), CtlKind::Radio { first }, text);
        ctl.checked = Some(checked);
        ctl
    }

    /// A single-line edit.
    #[must_use]
    pub fn edit(act: impl Into<Act>, text: &str, width: i32, password: bool, limit: u32) -> Self {
        let mut ctl = Self::new(
            act.into(),
            CtlKind::Edit {
                password,
                readonly: false,
            },
            text,
        );
        ctl.width = width;
        ctl.limit = Some(limit);
        ctl
    }

    /// A small icon button: `glyph` drawn in the link color, `label` its accessible name and
    /// tooltip.
    #[must_use]
    pub fn icon(act: impl Into<Act>, glyph: &'static str, label: &str) -> Self {
        let mut ctl = Self::link(act, label).compact();
        ctl.face = Some(Face::Glyph(glyph));
        ctl.tip = Some(label.to_owned());
        ctl
    }

    /// A copyable value: the whole address or hash as mono `spans` on a flat button whose click
    /// runs its press — a copy; `label` is its accessible name and tooltip. Used as the value of
    /// an [`Item::CopyLine`].
    #[must_use]
    pub fn value(act: impl Into<Act>, label: &str, spans: Vec<(String, bool)>) -> Self {
        let mut ctl = Self::link(act, label);
        ctl.face = Some(Face::Value(vec![spans]));
        ctl.tip = Some(label.to_owned());
        ctl
    }

    /// The plain text of a [`Face::Value`] (`None` for other controls).
    #[must_use]
    pub fn value_text(&self) -> Option<String> {
        match &self.face {
            Some(Face::Value(lines) | Face::Copied(lines, _)) => Some(
                lines
                    .iter()
                    .flatten()
                    .map(|(piece, _)| piece.as_str())
                    .collect(),
            ),
            _ => None,
        }
    }

    /// Draws a chain badge before a button's label (other kinds ignore it).
    #[must_use]
    pub const fn badge(mut self, badge: Badge) -> Self {
        self.badge = Some(badge);
        self
    }

    /// A tooltip (a shortcut such as `잠금 (Ctrl+L)`). An enabled control shows it on hover.
    #[must_use]
    pub fn tip(mut self, text: &str) -> Self {
        self.tip = Some(text.to_owned());
        self
    }

    /// Makes a button small (list-row actions).
    #[must_use]
    pub const fn compact(mut self) -> Self {
        self.compact = true;
        self
    }

    /// Sets enabled.
    #[must_use]
    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Sets a fixed width (DIP).
    #[must_use]
    pub const fn width(mut self, width: i32) -> Self {
        self.width = width;
        self
    }

    /// Makes an edit read-only.
    #[must_use]
    pub const fn readonly(mut self) -> Self {
        if let CtlKind::Edit { password, .. } = self.kind {
            self.kind = CtlKind::Edit {
                password,
                readonly: true,
            };
        }
        self
    }

    /// Whether this is a push button (any style).
    #[must_use]
    pub const fn is_button(&self) -> bool {
        matches!(self.kind, CtlKind::Button(_))
    }

    /// Whether this control sends `press` (a check box's state ignored,
    /// [`Press::same_control`]).
    #[must_use]
    pub fn sends(&self, press: Press) -> bool {
        matches!(self.act, Act::Press(own) if own.same_control(press))
    }
}

/// The copy just made says so at its own control (2026-11-12): a copyable value's copy symbol
/// becomes ✓ and its line says `복사됨` (with the paste check for an address); an icon button's
/// symbol becomes ✓; a text button says `복사됨` (sized for its label too) and, for an address in
/// a row, a paste-check tag follows the row. The first control that sends `anchor` is marked.
///
/// 2026-11-24 (spec/15 §11.4 S5-4): moved from yw-app `ui::main_window`, where it found the
/// control by its id (`cmd_table::id_of(anchor)`); here by its press ([`Ctl::sends`]: the same
/// control exactly when the ids are equal, yw-app table test
/// `same_control_is_same_id_on_every_press`).
pub fn mark_copied(lang: Lang, items: &mut Vec<Item>, anchor: Press, address: bool) {
    let mut tag_after = None;
    for (index, item) in items.iter_mut().enumerate() {
        let (ctls, row) = match item {
            Item::CopyLine { value, actions } => {
                if value.sends(anchor) {
                    if let Some(Face::Value(lines)) = &mut value.face {
                        let note = if address { T_COPIED_ADDRESS } else { T_COPIED }.get(lang);
                        value.face = Some(Face::Copied(core::mem::take(lines), note));
                    }
                    return;
                }
                (actions, false)
            }
            Item::Row(ctls) | Item::LabeledRow(_, ctls) => (ctls, true),
            _ => continue,
        };
        let Some(ctl) = ctls
            .iter_mut()
            .find(|ctl| ctl.sends(anchor) && ctl.is_button())
        else {
            continue;
        };
        match ctl.face {
            Some(Face::Glyph(_)) => ctl.face = Some(Face::Glyph(GLYPH_CHECK)),
            None => {
                let label = core::mem::replace(&mut ctl.text, T_COPIED.get(lang).to_owned());
                ctl.fit.push(label);
                if address && row {
                    tag_after = Some(index);
                }
            }
            Some(_) => {}
        }
        break;
    }
    if let Some(index) = tag_after {
        let tag = Item::Pill(T_PASTE_CHECK.get(lang).to_owned(), Tone::Success);
        items.insert(index.saturating_add(1), tag);
    }
}

/// Turns off every `받기` and `주소 복사` control in `items` (unverified-passphrase sessions,
/// spec/02 §7.5): the presses [`Press::is_receive_gated`] names, which the wallet also refuses.
/// 2026-11-24 (spec/15 §11.4 S5-4): moved from yw-app, where it matched the eight control ids of
/// `ui::screens::RECEIVE_IDS` (the same controls, yw-app table test
/// `family_presses_keep_the_gate_and_the_observer`).
pub fn disable_receive(items: &mut [Item]) {
    let gated = |ctl: &Ctl| matches!(ctl.act, Act::Press(press) if press.is_receive_gated());
    for item in items {
        match item {
            Item::Row(ctls) | Item::LabeledRow(_, ctls) | Item::Toolbar(_, ctls) => {
                for ctl in ctls.iter_mut().filter(|ctl| gated(ctl)) {
                    ctl.enabled = false;
                }
            }
            Item::CopyLine { value, .. } if gated(value) => {
                value.enabled = false;
            }
            _ => {}
        }
    }
}

/// One element of a screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    /// Screen title.
    Title(String),
    /// Body paragraph.
    Text(String),
    /// Secondary paragraph.
    Muted(String),
    /// A plain-language help line under a field.
    Help(String),
    /// A card heading.
    Subtitle(String),
    /// Large text: a balance or the welcome headline.
    Display(String),
    /// A balance kept from an earlier read that the last read could not refresh (muted).
    DisplayMuted(String),
    /// Monospace line (addresses, hashes).
    Mono(String),
    /// A copyable value line: `value` ([`Ctl::value`]) with `actions` after it on the same line,
    /// or on the next when the value does not fit beside them.
    CopyLine {
        /// The copyable value.
        value: Ctl,
        /// Actions right after the value.
        actions: Vec<Ctl>,
    },
    /// One list entry: a bold title, the bold value after it and a small muted note; `dim` draws
    /// everything muted.
    ListRow {
        /// Bold title (a token symbol).
        title: String,
        /// Small muted note after the value (the token name).
        note: String,
        /// The value after the title.
        value: String,
        /// Muted (a hidden row).
        dim: bool,
    },
    /// A small rounded status tag in its tone.
    Pill(String, Tone),
    /// A vertical list of controls under the value column of a [`Item::LabeledRow`] (an open
    /// drop-down).
    Menu(Vec<Ctl>),
    /// A label and its read-only value on one line.
    Field(String, String),
    /// A status band with its tag.
    Banner(String, Tone),
    /// Vertical space (DIP).
    Gap(i32),
    /// A horizontal row of controls.
    Row(Vec<Ctl>),
    /// A label on the left and controls on the right in one row.
    LabeledRow(String, Vec<Ctl>),
    /// A thin separator line.
    Rule,
    /// A receive QR of this payload ([`crate::screen::qr`]).
    Qr(String),
    /// Starts a card (section); the optional heading is drawn at its top.
    CardStart(Option<String>),
    /// Ends the current card.
    CardEnd,
    /// The step indicator of a multi-step flow: labels and the current step (1-based, 0 = none
    /// started yet).
    Steps(Vec<String>, usize),
    /// The top bar of the unlocked screens: the app name and controls.
    Toolbar(String, Vec<Ctl>),
    /// A chain badge before a text item or a `Field`'s value.
    Badged(Badge, Box<Item>),
    /// S22's press-and-hold area (spec/04 §2.20; no control and no press: the shell hit-tests the
    /// one area a screen has and sends `Cmd::HoldBegin`/`HoldEnd`).
    Hold {
        /// Label.
        label: String,
        /// Progress 0–1000.
        progress: u16,
        /// Pressable.
        enabled: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::{Act, Ctl, CtlKind, Face, GLYPH_CHECK, GLYPH_COPY, GLYPH_DOWN, GLYPH_UP, Style};
    use crate::cmd::{CorePress, Press};
    use crate::form::{CredField, EditField};

    #[test]
    fn builders_set_kind_style_and_face() {
        let press = Press::Core(CorePress::Lock);
        let button = Ctl::button(press, "잠금").tip("잠금 (Ctrl+L)");
        assert_eq!(button.act, Act::Press(press));
        assert_eq!(button.kind, CtlKind::Button(Style::Secondary));
        assert_eq!(button.tip.as_deref(), Some("잠금 (Ctrl+L)"));
        assert!(button.is_button() && button.enabled && button.face.is_none());
        assert_eq!(
            Ctl::tab(press, "t", true).kind,
            CtlKind::Button(Style::TabOn)
        );
        assert_eq!(Ctl::tab(press, "t", false).checked, Some(false));
        assert_eq!(
            Ctl::picker(press, "p", true).face,
            Some(Face::Entry(Some(GLYPH_UP)))
        );
        assert_eq!(
            Ctl::picker(press, "p", false).face,
            Some(Face::Entry(Some(GLYPH_DOWN)))
        );
        let entry = Ctl::entry(press, "e", true);
        assert_eq!(
            (entry.kind, entry.compact, entry.face),
            (
                CtlKind::Button(Style::EntryOn),
                true,
                Some(Face::Entry(Some(GLYPH_CHECK)))
            )
        );
        let value = Ctl::value(press, "주소 복사", vec![("0x".to_owned(), false)]);
        assert_eq!(value.value_text().as_deref(), Some("0x"));
        assert_eq!(value.kind, CtlKind::Button(Style::Link));
        let icon = Ctl::icon(press, GLYPH_COPY, "복사");
        assert!(icon.compact && icon.tip.as_deref() == Some("복사"));
        let edit = Ctl::edit(EditField::CoreRename, "a", 200, false, 32).readonly();
        assert_eq!(edit.act, Act::Field(EditField::CoreRename));
        assert_eq!(
            (edit.kind, edit.width, edit.limit),
            (
                CtlKind::Edit {
                    password: false,
                    readonly: true
                },
                200,
                Some(32)
            )
        );
        let cred = Ctl::edit(CredField::LlmKey, "", 200, true, 256);
        assert_eq!(cred.act, Act::Cred(CredField::LlmKey));
        assert!(cred.text.is_empty());
        assert_eq!(
            Ctl::radio(press, "r", true, true).kind,
            CtlKind::Radio { first: true }
        );
        assert_eq!(Ctl::check(press, "c", false).checked, Some(false));
        // `readonly` touches only edits.
        assert_eq!(
            Ctl::button(press, "b").readonly().kind,
            CtlKind::Button(Style::Secondary)
        );
    }

    /// A credential's text never enters the model, whatever a builder is given (2026-11-24 S5-2
    /// review), so the model's `Debug` cannot print it; other edits keep theirs.
    #[test]
    fn a_credential_edit_never_holds_text() {
        let given = "not-a-real-key-7f3a";
        for cred in [
            Ctl::edit(CredField::LlmKey, given, 200, true, 256),
            Ctl::edit(CredField::LlmKey, given, 200, false, 256).readonly(),
            Ctl::button(CredField::LlmKey, given),
            Ctl::check(CredField::LlmKey, given, true),
            Ctl::radio(CredField::LlmKey, given, true, true),
            Ctl::tab(CredField::LlmKey, given, true),
        ] {
            assert!(cred.text.is_empty());
            assert!(!format!("{cred:?}").contains(given));
        }
        assert_eq!(
            Ctl::edit(EditField::CoreRename, given, 200, false, 32).text,
            given
        );
    }

    /// 2026-11-24 (S5-4): the copy mark finds its control by press, a check box's state set
    /// aside; the receive gate turns off exactly the presses `Press::is_receive_gated` names.
    #[test]
    fn the_copy_mark_and_the_receive_gate_go_by_press() {
        use super::{
            Item, T_COPIED, T_COPIED_ADDRESS, T_PASTE_CHECK, disable_receive, mark_copied,
        };
        use crate::cmd::{BookPress, EvmPress, SolPress};
        use crate::screen::Tone;
        use yw_core::lang::Lang;
        let spans = vec![("0x".to_owned(), false)];
        let items = vec![
            Item::CopyLine {
                value: Ctl::value(EvmPress::CopyAddress, "주소 복사", spans.clone()),
                actions: vec![Ctl::icon(EvmPress::BookOpen, GLYPH_COPY, "복사")],
            },
            Item::Row(vec![
                Ctl::check(BookPress::Verified(None), "확인", false),
                Ctl::button(SolPress::CopyAddress, "주소 복사"),
                Ctl::button(SolPress::ReceiveOpen, "받기"),
            ]),
        ];
        let mut marked = items.clone();
        mark_copied(
            Lang::Ko,
            &mut marked,
            Press::Evm(EvmPress::CopyAddress),
            true,
        );
        let line = |item: &Item| match item {
            Item::CopyLine { value, actions } => Some((value.clone(), actions.clone())),
            _ => None,
        };
        let row_of = |item: &Item| match item {
            Item::Row(row) => Some(row.clone()),
            _ => None,
        };
        let (value, _) = line(&marked[0]).unwrap();
        assert_eq!(
            value.face,
            Some(Face::Copied(vec![spans], T_COPIED_ADDRESS.ko))
        );
        let mut marked = items.clone();
        mark_copied(
            Lang::Ko,
            &mut marked,
            Press::Sol(SolPress::CopyAddress),
            true,
        );
        let row = row_of(&marked[1]).unwrap();
        assert_eq!(row[1].text, T_COPIED.ko);
        assert_eq!(
            marked[2],
            Item::Pill(T_PASTE_CHECK.ko.to_owned(), Tone::Success)
        );
        // A check box's press with its state still finds the box (not a button: unmarked).
        let mut marked = items.clone();
        mark_copied(
            Lang::Ko,
            &mut marked,
            Press::Book(BookPress::Verified(Some(true))),
            false,
        );
        assert_eq!(marked, items);
        let mut gated = items.clone();
        disable_receive(&mut gated);
        let (value, actions) = line(&gated[0]).unwrap();
        assert!(!value.enabled && actions[0].enabled);
        let row = row_of(&gated[1]).unwrap();
        assert_eq!(
            row.iter().map(|ctl| ctl.enabled).collect::<Vec<_>>(),
            [true, false, false]
        );
    }
}
