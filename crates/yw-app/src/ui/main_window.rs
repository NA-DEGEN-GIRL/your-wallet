//! Main window rendering (spec/04 §2): screens are described as a vertical list of [`Item`]s
//! (painted text, cards, banners, rows of standard controls for non-secret values); [`layout`]
//! places them for the current width, DPI and scroll offset, [`paint`] draws the text and shapes,
//! and [`ControlSet::sync`] creates or moves the child controls.
//!
//! The design system (spec/04 §1.6, `ui::theme`): a light-gray window with white cards
//! ([`Item::CardStart`] … [`Item::CardEnd`]), one type scale, a 4-DIP spacing grid, owner-drawn
//! primary / secondary / danger / link / tab buttons, and banners that always name their status
//! (정보·완료·주의·고위험·차단·오류·테스트넷) in a colored tag.

use yw_win::ui::controls::{
    ButtonFace, ButtonIcon, ButtonStyle, Control, ControlKind, FaceRun, create_control,
};
use yw_win::ui::{Color, DrawFlags, PaintDc, Rect, Window, scale};

use crate::ui::badge::{BADGE_DIP, BADGE_GAP_DIP, Badge, TITLE_BADGE_DIP};
use crate::ui::theme::{self, FontRole, Fonts, wide};

/// Banner tone. Each tone has one meaning everywhere (spec/04 §1.6 status colors).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// 오류: an error with a code (the action did not happen or cannot start).
    Danger,
    /// 주의: check something before continuing.
    Warn,
    /// 정보: neutral information.
    Info,
    /// 테스트넷: `TESTNET_BG`.
    Testnet,
    /// `BTC_MAINNET_BG` / `BTC_MAINNET_TEXT` (spec/08 §2 `BITCOIN MAINNET`).
    BtcMainnet,
    /// `BTC_TESTNET4_BG` / `TEXT` (spec/08 §2 `BITCOIN TESTNET4 — 가치 없음`).
    BtcTestnet4,
    /// 고위험: a likely loss of funds (address poisoning, program-owned recipient …).
    HighRisk,
    /// 차단: the function is stopped until the cause is fixed.
    Blocked,
    /// 완료: an action succeeded.
    Success,
}

impl Tone {
    /// The status word drawn in the banner's tag (`None` for the Bitcoin network banners, whose
    /// text is the whole message).
    #[must_use]
    pub const fn label(self) -> Option<&'static str> {
        match self {
            Self::Danger => Some("오류"),
            Self::Warn => Some("주의"),
            Self::Info => Some("정보"),
            Self::Testnet => Some("테스트넷"),
            Self::HighRisk => Some("고위험"),
            Self::Blocked => Some("차단"),
            Self::Success => Some("완료"),
            Self::BtcMainnet | Self::BtcTestnet4 => None,
        }
    }

    /// `(background, text, tag)` colors.
    #[must_use]
    pub const fn colors(self) -> (Color, Color, Color) {
        match self {
            Self::Danger | Self::HighRisk => {
                (theme::DANGER_BG, theme::DANGER_TEXT, theme::DANGER_ACCENT)
            }
            Self::Warn => (theme::WARN_BG, theme::WARN_TEXT, theme::WARN_ACCENT),
            Self::Info => (theme::INFO_BG, theme::INFO_TEXT, theme::INFO_ACCENT),
            Self::Testnet => (theme::TESTNET_BG, theme::TEXT, theme::TESTNET_ACCENT),
            Self::BtcMainnet => (
                theme::BTC_MAINNET_BG,
                theme::BTC_MAINNET_TEXT,
                theme::BTC_MAINNET_BG,
            ),
            Self::BtcTestnet4 => (theme::BTC_TESTNET4_BG, theme::TEXT, theme::BTC_TESTNET4_BG),
            Self::Blocked => (theme::BLOCKED_BG, theme::BLOCKED_TEXT, theme::CARD),
            Self::Success => (
                theme::SUCCESS_BG,
                theme::SUCCESS_TEXT,
                theme::SUCCESS_ACCENT,
            ),
        }
    }
}

/// A control in a row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ctl {
    /// Command id.
    pub id: u16,
    /// Kind.
    pub kind: ControlKind,
    /// Label / initial text.
    pub text: String,
    /// Width in DIP (0 = from the label).
    pub width: i32,
    /// Enabled.
    pub enabled: bool,
    /// Check state for check boxes and radios (and the selected tab).
    pub checked: Option<bool>,
    /// Edit length limit.
    pub limit: Option<u32>,
    /// The color under the control (set by [`layout`]).
    pub backdrop: Option<Color>,
    /// A chain badge drawn before a button's label (`crate::ui::badge`).
    pub badge: Option<Badge>,
    /// A small button (26 DIP tall, tighter padding): the actions inside a list row
    /// (2026-11-11, token rows and the address line's actions).
    pub compact: bool,
    /// What a button draws instead of its label (2026-11-11: icon buttons and copyable values;
    /// the label stays the control's text, i.e. its accessible name).
    pub face: Option<Face>,
    /// The tooltip shown while the pointer rests on the control.
    pub tip: Option<String>,
    /// Other labels the control is sized for ([`Ctl::fit`]).
    pub fit: Vec<String>,
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

/// What a control says for about 1.5 s after its copy (2026-11-12, [`mark_copied`]).
pub const T_COPIED: &str = "복사됨";
/// The same after an address copy: with the paste check, in short (address poisoning).
pub const T_COPIED_ADDRESS: &str = "복사됨 · 붙여넣은 뒤 전체 확인";
/// The paste check alone: after the row of a text button that says `복사됨` for an address.
pub const T_PASTE_CHECK: &str = "붙여넣은 뒤 전체 확인";

/// What a button draws instead of its label ([`Ctl::face`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Face {
    /// A symbol in Segoe UI Symbol (`theme::Fonts::symbol`), centered: an icon button.
    Glyph(&'static str),
    /// A copyable value (an address or a hash): mono `(text, emphasized)` spans by line — the
    /// screen gives one line, [`layout`] breaks it to the button's width — left-aligned, with
    /// [`GLYPH_COPY`] at the right end of the button.
    Value(Vec<Vec<(String, bool)>>),
    /// A drop-down's selector or one of its entries (2026-11-12): the label left-aligned after
    /// the badge, and the symbol ([`GLYPH_DOWN`], [`GLYPH_UP`], [`GLYPH_CHECK`]) at the right
    /// end.
    Entry(Option<&'static str>),
    /// A [`Face::Value`] right after its copy (2026-11-12, [`mark_copied`]): the same lines with
    /// [`GLYPH_CHECK`] in the success color where the copy symbol is; [`layout`] writes the
    /// caption (`복사됨`) after the line's actions.
    Copied(Vec<Vec<(String, bool)>>, &'static str),
}

impl Ctl {
    fn styled(id: u16, text: &str, style: ButtonStyle) -> Self {
        Self {
            id,
            kind: ControlKind::Button(style),
            text: text.to_owned(),
            width: 0,
            enabled: true,
            checked: None,
            limit: None,
            backdrop: None,
            badge: None,
            compact: false,
            face: None,
            tip: None,
            fit: Vec::new(),
        }
    }

    /// A secondary push button (every action that is not the screen's main one).
    #[must_use]
    pub fn button(id: u16, text: &str) -> Self {
        Self::styled(id, text, theme::BUTTON_SECONDARY)
    }

    /// The primary push button (the screen's main action).
    #[must_use]
    pub fn primary(id: u16, text: &str) -> Self {
        Self::styled(id, text, theme::BUTTON_PRIMARY)
    }

    /// A destructive action (삭제, 연결 해제 …).
    #[must_use]
    pub fn danger(id: u16, text: &str) -> Self {
        Self::styled(id, text, theme::BUTTON_DANGER)
    }

    /// A text-only navigation or show/hide button (← 메인으로, 고급 ▸).
    #[must_use]
    pub fn link(id: u16, text: &str) -> Self {
        Self::styled(id, text, theme::BUTTON_LINK)
    }

    /// One segment of a tab or chip row; `checked == Some(selected)`.
    #[must_use]
    pub fn tab(id: u16, text: &str, selected: bool) -> Self {
        let mut ctl = Self::styled(
            id,
            text,
            if selected {
                theme::BUTTON_TAB_ON
            } else {
                theme::BUTTON_TAB_OFF
            },
        );
        ctl.checked = Some(selected);
        ctl
    }

    /// The selector of a drop-down (2026-11-12): the selected entry's label with ▾ (▴ while
    /// `open`) at the right end. The list is the [`Item::Menu`] after its row.
    #[must_use]
    pub fn picker(id: u16, text: &str, open: bool) -> Self {
        let mut ctl = Self::button(id, text);
        ctl.face = Some(Face::Entry(Some(if open { GLYPH_UP } else { GLYPH_DOWN })));
        ctl
    }

    /// One entry of an open drop-down; `checked == Some(selected)` (the selected one is tinted
    /// and carries a ✓).
    #[must_use]
    pub fn entry(id: u16, text: &str, selected: bool) -> Self {
        let mut ctl = Self::styled(
            id,
            text,
            if selected {
                theme::BUTTON_ENTRY_ON
            } else {
                theme::BUTTON_ENTRY
            },
        );
        ctl.checked = Some(selected);
        ctl.compact = true;
        ctl.face = Some(Face::Entry(selected.then_some(GLYPH_CHECK)));
        ctl
    }

    /// Sizes the control for the widest of `labels` too (a drop-down's selector keeps one width
    /// whichever entry is selected, and its list is as wide).
    #[must_use]
    pub fn fit<'a>(mut self, labels: impl IntoIterator<Item = &'a str>) -> Self {
        self.fit = labels.into_iter().map(str::to_owned).collect();
        self
    }

    /// A check box.
    #[must_use]
    pub fn check(id: u16, text: &str, checked: bool) -> Self {
        Self {
            id,
            kind: ControlKind::CheckBox,
            text: text.to_owned(),
            width: 0,
            enabled: true,
            checked: Some(checked),
            limit: None,
            backdrop: None,
            badge: None,
            compact: false,
            face: None,
            tip: None,
            fit: Vec::new(),
        }
    }

    /// A radio button.
    #[must_use]
    pub fn radio(id: u16, text: &str, checked: bool, first: bool) -> Self {
        Self {
            id,
            kind: ControlKind::Radio {
                first_in_group: first,
            },
            text: text.to_owned(),
            width: 0,
            enabled: true,
            checked: Some(checked),
            limit: None,
            backdrop: None,
            badge: None,
            compact: false,
            face: None,
            tip: None,
            fit: Vec::new(),
        }
    }

    /// A single-line edit.
    #[must_use]
    pub fn edit(id: u16, text: &str, width: i32, password: bool, limit: u32) -> Self {
        Self {
            id,
            kind: ControlKind::Edit {
                password,
                readonly: false,
            },
            text: text.to_owned(),
            width,
            enabled: true,
            checked: None,
            limit: Some(limit),
            backdrop: None,
            badge: None,
            compact: false,
            face: None,
            tip: None,
            fit: Vec::new(),
        }
    }

    /// A small icon button (2026-11-11): `glyph` drawn in the link color, `label` its accessible
    /// name and tooltip (`탐색기에서 열기`, `탐색기 링크 복사`, `이 주소 저장` …).
    #[must_use]
    pub fn icon(id: u16, glyph: &'static str, label: &str) -> Self {
        let mut ctl = Self::link(id, label).compact();
        ctl.face = Some(Face::Glyph(glyph));
        ctl.tip = Some(label.to_owned());
        ctl
    }

    /// A copyable value (2026-11-11): the whole address or hash as mono `spans` on a flat button
    /// whose click (or Enter) runs `id` — a copy; `label` (`주소 복사`, `해시 복사`) is its
    /// accessible name and tooltip. Used as the value of an [`Item::CopyLine`].
    #[must_use]
    pub fn value(id: u16, label: &str, spans: Vec<(String, bool)>) -> Self {
        let mut ctl = Self::link(id, label);
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

    /// A tooltip (2026-11-12: a shortcut — `잠금 (Ctrl+L)`, `새로고침 (F5)` — instead of spelling
    /// it in the label). An enabled control shows it on hover.
    #[must_use]
    pub fn tip(mut self, text: &str) -> Self {
        self.tip = Some(text.to_owned());
        self
    }

    /// Makes a button small (list-row actions, 2026-11-11).
    #[must_use]
    pub const fn compact(mut self) -> Self {
        self.compact = true;
        self
    }

    /// Sets enabled.
    #[must_use]
    pub fn enabled(mut self, enabled: bool) -> Self {
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
        if let ControlKind::Edit { password, .. } = self.kind {
            self.kind = ControlKind::Edit {
                password,
                readonly: true,
            };
        }
        self
    }

    /// Whether this is a push button (any style).
    #[must_use]
    pub const fn is_button(&self) -> bool {
        matches!(self.kind, ControlKind::Button(_))
    }
}

/// One element of a screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    /// Screen title (bold 14 pt).
    Title(String),
    /// Body paragraph.
    Text(String),
    /// Secondary paragraph.
    Muted(String),
    /// A plain-language help line under a field (caption size, muted).
    Help(String),
    /// A card heading (bold 11 pt).
    Subtitle(String),
    /// Large text: a balance or the welcome headline (bold 20 pt).
    Display(String),
    /// A balance kept from an earlier read that the last read could not refresh (bold 20 pt,
    /// muted; 2026-11-10).
    DisplayMuted(String),
    /// Monospace line (addresses, hashes). Grouped Solana/Bitcoin addresses get their bold groups.
    Mono(String),
    /// A copyable value line (2026-11-11, spec/04 §2.6): `value` ([`Ctl::value`]: the whole
    /// address or hash in mono with its emphasis, a click copies it, [`GLYPH_COPY`] at its right
    /// end) stretched up to `actions` (icon buttons [`Ctl::icon`] or small links), which sit
    /// right-aligned on the same line. When the value does not fit beside them it takes the
    /// line's whole width (breaking into several lines when longer) and the actions go
    /// right-aligned on the next line. The account cards' own address, the token contracts, the
    /// activity recipients (the wallet's own signed journal) and the transaction hashes.
    CopyLine {
        /// The copyable value.
        value: Ctl,
        /// Actions right after the value.
        actions: Vec<Ctl>,
    },
    /// One list entry (the token card): a bold title, the bold value right after it (2026-11-12:
    /// beside the symbol it belongs to, not at the far edge of the card) and a small muted note
    /// after the value. `dim` draws everything muted (hidden rows).
    ListRow {
        /// Bold title (a token symbol).
        title: String,
        /// Small muted note after the value (the token name).
        note: String,
        /// The value after the title (a balance: the amount alone, the title names the symbol).
        value: String,
        /// Muted (a hidden row).
        dim: bool,
    },
    /// A small rounded status tag in its tone's colors (2026-11-11: the S10 network cards'
    /// `메인넷 — 실제 자산`·testnet tags instead of a full-width band). Drawn at the end of the
    /// row just above it when it fits there, else on its own line.
    Pill(String, Tone),
    /// A vertical list of controls under the value column of a [`Item::LabeledRow`] (the open
    /// network drop-down of S10, 2026-11-11).
    Menu(Vec<Ctl>),
    /// A label and its read-only value on one line (the value wraps).
    Field(String, String),
    /// Colored banner with its status tag.
    Banner(String, Tone),
    /// Vertical space (DIP).
    Gap(i32),
    /// A horizontal row of controls.
    Row(Vec<Ctl>),
    /// A label on the left and controls on the right in one row.
    LabeledRow(String, Vec<Ctl>),
    /// A thin separator line.
    Rule,
    /// A receive QR of this payload (spec/04 §2.8).
    Qr(String),
    /// Starts a white card (section); the optional heading is drawn at its top.
    CardStart(Option<String>),
    /// Ends the current card.
    CardEnd,
    /// The step indicator of a multi-step flow: labels and the current step (1-based, 0 = none
    /// started yet).
    Steps(Vec<String>, usize),
    /// The top bar of the unlocked screens: the app name on the left, controls on the right.
    Toolbar(String, Vec<Ctl>),
    /// A chain badge before a text item (`Title`, `Subtitle`, `Text`, `Muted`, `Help`, `Mono`)
    /// or before a `Field`'s value; other items are laid out without it.
    Badged(Badge, Box<Item>),
    /// A press-and-hold area (painted, no child control; the app hit-tests
    /// [`Placed::holds`] and runs `id` after a 2 s continuous hold, spec/04 §2.20).
    Hold {
        /// Action id.
        id: u16,
        /// Label.
        label: String,
        /// Progress 0–1000 (the strip at the bottom).
        progress: u16,
        /// Pressable.
        enabled: bool,
    },
}

/// How a placed text is drawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextAlign {
    /// Word-wrapped, left aligned.
    Wrap,
    /// One line, left aligned, vertically centered.
    Line,
    /// One line, centered both ways.
    Center,
    /// One line, right aligned, vertically centered.
    Right,
}

/// A text to paint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaintText {
    /// Rectangle.
    pub rect: Rect,
    /// Text.
    pub text: String,
    /// Font.
    pub font: FontRole,
    /// Color.
    pub color: theme_color::Value,
    /// Background fill (plain rectangle; rounded backgrounds are [`Shape`]s).
    pub fill: Option<theme_color::Value>,
    /// Wrap or single line.
    pub wrap: bool,
    /// Alignment (overrides `wrap` when not [`TextAlign::Wrap`]).
    pub align: TextAlign,
    /// `(text, emphasized)` mono spans drawn on one line instead of `text` when they fit; empty
    /// for every text placed today (the copyable values are [`Face::Value`] buttons).
    pub spans: Vec<(String, bool)>,
}

/// A filled rounded shape (cards, banner backgrounds, tags, step dots).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    /// Rectangle (scrolled).
    pub rect: Rect,
    /// Corner radius in pixels.
    pub radius: i32,
    /// Fill.
    pub fill: theme_color::Value,
    /// Outline.
    pub border: theme_color::Value,
}

/// Color values as plain `u32` to keep [`PaintText`] comparable.
pub mod theme_color {
    /// `0xRRGGBB`.
    pub type Value = u32;
}

/// Layout result.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Placed {
    /// Texts and banners.
    pub texts: Vec<PaintText>,
    /// Rounded shapes, painted before the texts in order.
    pub shapes: Vec<Shape>,
    /// Separator lines.
    pub rules: Vec<Rect>,
    /// Controls with their pixel rectangles.
    pub controls: Vec<(Ctl, Rect)>,
    /// QR codes: origin, module pixels, payload (re-encoded at paint; never cached).
    pub qrs: Vec<(i32, i32, i32, String)>,
    /// Hold areas: action id, pixel rectangle (scrolled), enabled.
    pub holds: Vec<(u16, Rect, bool)>,
    /// Chain badges: square pixel rectangle (scrolled), painted after the shapes.
    pub badges: Vec<(Badge, Rect)>,
    /// Total content height (px, unscrolled).
    pub content_height: i32,
}

impl Placed {
    /// Moves everything by `dy` pixels: `layout(.., scroll - dy, ..)` without laying out again
    /// (every placed `y` is `content_y - scroll`).
    pub fn shift(&mut self, dy: i32) {
        let move_rect = |rect: &mut Rect| rect.y = rect.y.saturating_add(dy);
        self.texts
            .iter_mut()
            .for_each(|text| move_rect(&mut text.rect));
        self.shapes
            .iter_mut()
            .for_each(|shape| move_rect(&mut shape.rect));
        self.rules.iter_mut().for_each(move_rect);
        self.controls
            .iter_mut()
            .for_each(|(_, rect)| move_rect(rect));
        self.holds
            .iter_mut()
            .for_each(|(_, rect, _)| move_rect(rect));
        self.badges.iter_mut().for_each(|(_, rect)| move_rect(rect));
        for (_, y, _, _) in &mut self.qrs {
            *y = y.saturating_add(dy);
        }
    }
}

/// Measures `(text, font, width)` → height in pixels.
pub type Measure<'a> = &'a dyn Fn(&str, FontRole, i32) -> i32;
/// Measures a one-line label width in pixels.
pub type MeasureWidth<'a> = &'a dyn Fn(&str) -> i32;

const fn control_height(ctl: &Ctl) -> i32 {
    match ctl.kind {
        ControlKind::Edit { .. } => 30,
        ControlKind::Button(_) if ctl.compact => 26,
        ControlKind::Button(_) => 34,
        ControlKind::CheckBox | ControlKind::Radio { .. } => 24,
        ControlKind::Label => 22,
    }
}

/// Width of an icon button ([`Ctl::icon`], 26 DIP tall).
const ICON_DIP: i32 = 30;
/// Inner left and right padding of a value button ([`Ctl::value`]).
pub const VALUE_PAD_DIP: i32 = 6;
/// Room for [`GLYPH_COPY`] at the value button's right end.
const VALUE_GLYPH_DIP: i32 = 16;
/// Least gap between the value text and its copy symbol.
const VALUE_GAP_DIP: i32 = 12;
/// A value button's width beyond its text.
const VALUE_CHROME_DIP: i32 = 2 * VALUE_PAD_DIP + VALUE_GLYPH_DIP + VALUE_GAP_DIP;
/// Inner left and right padding of a drop-down's selector and entries ([`Face::Entry`]).
const ENTRY_PAD_DIP: i32 = 12;
/// Room for the symbol at the right end of a [`Face::Entry`] (with the gap before it).
const ENTRY_MARK_DIP: i32 = 28;
/// Height of one entry of an open drop-down.
const ENTRY_DIP: i32 = 30;
/// Padding of the list panel around its entries.
const MENU_PAD_DIP: i32 = 4;

/// How many mono characters `advance` pixels wide fit in `room` pixels (at least 8).
fn columns(room: i32, advance: i32) -> usize {
    usize::try_from(room / advance.max(1)).unwrap_or(0).max(8)
}

/// `spans` cut into lines of at most `columns` characters (the emphasis kept on each piece).
fn break_spans(spans: &[(String, bool)], columns: usize) -> Vec<Vec<(String, bool)>> {
    let mut lines: Vec<Vec<(String, bool)>> = vec![Vec::new()];
    let mut used = 0_usize;
    for (piece, emphasized) in spans {
        let mut rest: Vec<char> = piece.chars().collect();
        while !rest.is_empty() {
            if used == columns {
                lines.push(Vec::new());
                used = 0;
            }
            let take = columns.saturating_sub(used).min(rest.len());
            let head: String = rest.drain(..take).collect();
            used = used.saturating_add(take);
            if let Some(line) = lines.last_mut() {
                line.push((head, *emphasized));
            }
        }
    }
    lines
}

/// A bold label's width from the regular-weight measure (bold Malgun Gothic is a little wider).
fn bold_width(regular: i32) -> i32 {
    regular.saturating_mul(110) / 100
}

/// The content box items are placed in: the window margin, or a card's padded inside.
#[derive(Clone, Copy)]
struct Frame {
    x: i32,
    w: i32,
    backdrop: Color,
}

struct Layouter<'m> {
    px: Box<dyn Fn(i32) -> i32>,
    measure: Measure<'m>,
    label_width: MeasureWidth<'m>,
    scroll: i32,
    client_w: i32,
    margin: i32,
    width: i32,
    y: i32,
    frame: Frame,
    card: Option<i32>,
    last_gap: i32,
    /// The last row just placed: `(x after its last control, content y of its last line, line
    /// height)`; an [`Item::Pill`] right after it goes on that line.
    row_end: Option<(i32, i32, i32)>,
    /// The first control of the last labeled row: `(x, width)`; an [`Item::Menu`] hangs under
    /// it.
    anchor: Option<(i32, i32)>,
    placed: Placed,
}

impl Layouter<'_> {
    fn px(&self, dip: i32) -> i32 {
        (self.px)(dip)
    }

    fn outer(&self) -> Frame {
        Frame {
            x: self.margin,
            w: self.width,
            backdrop: theme::BG,
        }
    }

    fn advance(&mut self, height: i32, gap: i32) {
        self.y = self.y.saturating_add(height).saturating_add(gap);
        self.last_gap = gap;
    }

    fn text(&mut self, text: &str, font: FontRole, color: Color, indent: i32, gap: i32) {
        let width = self.frame.w.saturating_sub(indent).max(self.px(40));
        let height = (self.measure)(text, font, width).max(self.px(16));
        self.placed.texts.push(PaintText {
            rect: Rect::new(
                self.frame.x.saturating_add(indent),
                self.y.saturating_sub(self.scroll),
                width,
                height,
            ),
            text: text.to_owned(),
            font,
            color: color.0,
            fill: None,
            wrap: true,
            align: TextAlign::Wrap,
            spans: Vec::new(),
        });
        self.advance(height, gap);
    }

    fn shape(&mut self, rect: Rect, radius: i32, fill: Color, border: Color) {
        self.placed.shapes.push(Shape {
            rect,
            radius,
            fill: fill.0,
            border: border.0,
        });
    }

    fn open_card(&mut self, title: Option<&str>) {
        self.close_card();
        let pad = self.px(theme::SPACE_L);
        self.card = Some(self.y);
        let outer = self.outer();
        self.frame = Frame {
            x: outer.x.saturating_add(pad),
            w: outer.w.saturating_sub(pad.saturating_mul(2)),
            backdrop: theme::CARD,
        };
        self.y = self.y.saturating_add(pad);
        // The card shape goes in now so it paints under its contents; its height is fixed at
        // close time.
        self.shape(
            Rect::new(outer.x, self.y.saturating_sub(self.scroll), outer.w, 0),
            self.px(theme::RADIUS_CARD),
            theme::CARD,
            theme::CARD_BORDER,
        );
        if let Some(title) = title {
            self.text(
                title,
                FontRole::Subtitle,
                theme::TEXT,
                0,
                self.px(theme::SPACE_S),
            );
        }
    }

    fn close_card(&mut self) {
        let Some(top) = self.card.take() else {
            return;
        };
        let pad = self.px(theme::SPACE_L);
        self.y = self
            .y
            .saturating_sub(self.last_gap)
            .saturating_add(pad)
            .max(top.saturating_add(pad.saturating_mul(2)));
        let outer = self.outer();
        let rect = Rect::new(
            outer.x,
            top.saturating_sub(self.scroll),
            outer.w,
            self.y.saturating_sub(top),
        );
        // The most recent card shape without a height is this card's.
        if let Some(shape) = self
            .placed
            .shapes
            .iter_mut()
            .rev()
            .find(|shape| shape.rect.h == 0 && shape.fill == theme::CARD.0)
        {
            shape.rect = rect;
        }
        self.frame = outer;
        self.advance(0, self.px(theme::SPACE_M));
    }

    fn banner(&mut self, text: &str, tone: Tone) {
        let (fill, color, accent) = tone.colors();
        let pad = self.px(10);
        let tag = tone.label();
        let tag_w = tag.map_or(0, |label| {
            (self.label_width)(label)
                .saturating_add(self.px(18))
                .max(self.px(44))
        });
        let tag_h = self.px(22);
        let text_x = if tag_w > 0 {
            tag_w.saturating_add(self.px(10))
        } else {
            0
        };
        let inner = self
            .frame
            .w
            .saturating_sub(pad.saturating_mul(2))
            .saturating_sub(text_x)
            .max(self.px(40));
        let bold = matches!(tone, Tone::BtcMainnet | Tone::BtcTestnet4 | Tone::Blocked);
        let font = if bold {
            FontRole::BodyBold
        } else {
            FontRole::Body
        };
        let text_h = (self.measure)(text, font, inner).max(self.px(16));
        let height = text_h.max(tag_h).saturating_add(pad.saturating_mul(2));
        let top = self.y.saturating_sub(self.scroll);
        let rect = Rect::new(self.frame.x, top, self.frame.w, height);
        self.shape(rect, self.px(theme::RADIUS_CONTROL), fill, fill);
        if let Some(label) = tag {
            let tag_rect = Rect::new(
                self.frame.x.saturating_add(pad),
                top.saturating_add(pad),
                tag_w,
                tag_h,
            );
            let (tag_fill, tag_text) = if tone == Tone::Blocked {
                (theme::CARD, theme::BLOCKED_BG)
            } else {
                (accent, theme::CARD)
            };
            self.shape(tag_rect, tag_h / 2, tag_fill, tag_fill);
            self.placed.texts.push(PaintText {
                rect: tag_rect,
                text: label.to_owned(),
                font: FontRole::BodyBold,
                color: tag_text.0,
                fill: None,
                wrap: false,
                align: TextAlign::Center,
                spans: Vec::new(),
            });
        }
        self.placed.texts.push(PaintText {
            rect: Rect::new(
                self.frame.x.saturating_add(pad).saturating_add(text_x),
                top.saturating_add(pad)
                    .saturating_add((tag_h - text_h).max(0) / 2),
                inner,
                text_h,
            ),
            text: text.to_owned(),
            font,
            color: color.0,
            fill: None,
            wrap: true,
            align: TextAlign::Wrap,
            spans: Vec::new(),
        });
        self.advance(height, self.px(theme::SPACE_S));
    }

    fn ctl_width(&self, ctl: &Ctl) -> i32 {
        if ctl.width > 0 {
            self.px(ctl.width)
        } else if let Some(Face::Glyph(_)) = ctl.face {
            self.px(ICON_DIP)
        } else if let Some(text) = ctl.value_text() {
            self.mono_width(&text)
                .saturating_add(self.px(VALUE_CHROME_DIP))
        } else if let Some(Face::Entry(_)) = ctl.face {
            let label = ctl
                .fit
                .iter()
                .map(|other| (self.label_width)(other))
                .fold((self.label_width)(&ctl.text), i32::max);
            let badge = if ctl.badge.is_some() {
                BADGE_DIP + BADGE_GAP_DIP
            } else {
                0
            };
            label
                .saturating_add(self.px(2 * ENTRY_PAD_DIP + ENTRY_MARK_DIP + badge))
                .max(self.px(160))
        } else {
            let pad = match (ctl.is_button(), ctl.compact) {
                (true, true) => 20,
                (true, false) => 36,
                (false, _) => 28,
            };
            let badge = if ctl.is_button() && ctl.badge.is_some() {
                BADGE_DIP + BADGE_GAP_DIP
            } else {
                0
            };
            let least = match (ctl.is_button(), ctl.compact) {
                (true, true) => 44,
                (true, false) => 88,
                (false, _) => 60,
            };
            // Its `fit` labels too: a copy button keeps its width while it says `복사됨`.
            ctl.fit
                .iter()
                .map(|other| (self.label_width)(other))
                .fold((self.label_width)(&ctl.text), i32::max)
                .saturating_add(self.px(pad + badge))
                .max(self.px(least))
        }
    }

    fn row(&mut self, label: Option<&str>, ctls: &[Ctl]) {
        let frame = self.frame;
        let mut x = frame.x;
        let right = frame.x.saturating_add(frame.w);
        let mut row_h = ctls
            .iter()
            .map(|ctl| self.px(control_height(ctl)))
            .max()
            .unwrap_or(self.px(24))
            .max(self.px(24));
        if let Some(label) = label {
            let label_w = self.label_column();
            let label_h = (self.measure)(label, FontRole::Body, label_w).max(row_h);
            let single = row_h;
            row_h = label_h;
            self.placed.texts.push(PaintText {
                rect: Rect::new(frame.x, self.y.saturating_sub(self.scroll), label_w, row_h),
                text: label.to_owned(),
                font: FontRole::Body,
                color: theme::TEXT.0,
                fill: None,
                wrap: label_h > single,
                align: if label_h > single {
                    TextAlign::Wrap
                } else {
                    TextAlign::Line
                },
                spans: Vec::new(),
            });
            x = frame.x.saturating_add(label_w).saturating_add(self.px(8));
        }
        let line_start = x;
        self.anchor = None;
        for (index, ctl) in ctls.iter().enumerate() {
            let w = self
                .ctl_width(ctl)
                .min(right.saturating_sub(line_start).max(self.px(40)));
            if index == 0 && label.is_some() {
                self.anchor = Some((line_start, w));
            }
            if x.saturating_add(w) > right && x > line_start {
                x = line_start;
                self.y = self.y.saturating_add(row_h).saturating_add(self.px(6));
            }
            let h = self.px(control_height(ctl));
            let rect = Rect::new(
                x,
                self.y
                    .saturating_add((row_h - h) / 2)
                    .saturating_sub(self.scroll),
                w,
                h,
            );
            self.push_control(ctl, rect);
            x = x.saturating_add(w).saturating_add(self.px(8));
        }
        let end = (x, self.y, row_h);
        self.advance(row_h, self.px(10));
        self.row_end = Some(end);
    }

    /// Places one control at `rect` on the current frame (a link button takes the card color).
    fn push_control(&mut self, ctl: &Ctl, rect: Rect) {
        let backdrop = self.frame.backdrop;
        let mut placed = ctl.clone();
        placed.backdrop = Some(backdrop);
        if let ControlKind::Button(style) = placed.kind
            && style.fill == theme::BG
            && backdrop != theme::BG
        {
            // A link button on a card takes the card color.
            placed.kind = ControlKind::Button(theme::link_on(backdrop));
        }
        self.placed.controls.push((placed, rect));
    }

    /// The width of the label column of a [`Item::LabeledRow`] (and of the [`Item::Menu`] under
    /// it).
    fn label_column(&self) -> i32 {
        self.px(170).min(self.frame.w / 3)
    }

    /// The drawn width of `text` in the mono font: Consolas 10 pt (`theme::Fonts::create`) has
    /// one advance for every character and weight — GDI's cell height at this DPI
    /// (`(10 × dpi + 36) / 72`) × 1126/2048.
    fn mono_width(&self, text: &str) -> i32 {
        let cell = self.px(960).saturating_add(36) / 72;
        let advance = cell.saturating_mul(1_126).saturating_add(1_024) / 2_048;
        i32::try_from(text.chars().count())
            .unwrap_or(i32::MAX)
            .saturating_mul(advance.max(1))
    }

    /// The width of `actions` placed side by side (icons 2 DIP apart, other controls 4).
    fn actions_width(&self, actions: &[Ctl]) -> i32 {
        actions.iter().enumerate().fold(0_i32, |sum, (index, ctl)| {
            let gap = if index == 0 { 0 } else { self.action_gap(ctl) };
            sum.saturating_add(gap).saturating_add(self.ctl_width(ctl))
        })
    }

    fn action_gap(&self, ctl: &Ctl) -> i32 {
        self.px(if matches!(ctl.face, Some(Face::Glyph(_))) {
            2
        } else {
            4
        })
    }

    /// Places `actions` side by side from `x` on the line at content `y` that is `line_h` tall.
    fn place_actions(&mut self, actions: &[Ctl], mut x: i32, y: i32, line_h: i32) {
        for (index, ctl) in actions.iter().enumerate() {
            if index > 0 {
                x = x.saturating_add(self.action_gap(ctl));
            }
            let w = self.ctl_width(ctl);
            let h = self.px(control_height(ctl));
            let rect = Rect::new(
                x,
                y.saturating_add((line_h - h) / 2)
                    .saturating_sub(self.scroll),
                w,
                h,
            );
            self.push_control(ctl, rect);
            x = x.saturating_add(w);
        }
    }

    /// [`Item::CopyLine`]: the value button from the frame's left edge (its padding hangs into
    /// the card's, so the text lines up with the lines above), as wide as its text, and the
    /// actions right after it (2026-11-12: an icon belongs next to the value it acts on, not at
    /// the far edge of the card); or, when the value does not fit beside them, the value over
    /// the whole width (in lines of whole characters) and the actions under its left edge.
    /// Right after a copy ([`mark_copied`]) its caption follows the last control of the line.
    fn copy_line(&mut self, value: &Ctl, actions: &[Ctl]) {
        let pad = self.px(VALUE_PAD_DIP);
        let chrome = self.px(VALUE_CHROME_DIP);
        let mono_h = (self.measure)("0", FontRole::Mono, self.frame.w.max(1)).max(self.px(16));
        let spans: Vec<(String, bool)> = match &value.face {
            Some(Face::Value(lines) | Face::Copied(lines, _)) => {
                lines.iter().flatten().cloned().collect()
            }
            _ => vec![(value.text.clone(), false)],
        };
        // The caption of a copy just made: the value's own, or the plain one for an icon.
        let copied = match &value.face {
            Some(Face::Copied(_, note)) => Some(*note),
            _ => None,
        };
        let note = copied.or_else(|| {
            actions
                .iter()
                .any(|ctl| ctl.face == Some(Face::Glyph(GLYPH_CHECK)))
                .then_some(T_COPIED)
        });
        let text: String = spans.iter().map(|(piece, _)| piece.as_str()).collect();
        let text_w = self.mono_width(&text);
        let actions_w = self.actions_width(actions);
        let left = self.frame.x.saturating_sub(pad);
        let full = self.frame.w.saturating_add(pad.saturating_mul(2));
        let gap = if actions.is_empty() { 0 } else { self.px(4) };
        let beside = full
            .saturating_sub(pad)
            .saturating_sub(actions_w)
            .saturating_sub(gap);
        let fitted = text_w.saturating_add(chrome);
        let one_line = fitted <= beside;
        let width = if one_line { fitted } else { full };
        let room = width.saturating_sub(chrome).max(self.px(40));
        let lines = break_spans(&spans, columns(room, self.mono_width("0")));
        let count = i32::try_from(lines.len()).unwrap_or(1).max(1);
        let height = mono_h
            .saturating_mul(count)
            .saturating_add(self.px(8))
            .max(self.px(26));
        let mut placed = value.clone();
        placed.face = Some(match copied {
            Some(note) => Face::Copied(lines, note),
            None => Face::Value(lines),
        });
        self.push_control(
            &placed,
            Rect::new(left, self.y.saturating_sub(self.scroll), width, height),
        );
        if one_line {
            let x = left.saturating_add(width).saturating_add(gap);
            self.place_actions(actions, x, self.y, height);
            if let Some(note) = note {
                self.copied_note(note, x.saturating_add(actions_w), self.y, height);
            }
            self.advance(height, self.px(theme::SPACE_XS));
            return;
        }
        self.advance(height, self.px(2));
        if !actions.is_empty() {
            let line_h = self.px(26);
            self.place_actions(actions, self.frame.x, self.y, line_h);
            if let Some(note) = note {
                let x = self.frame.x.saturating_add(actions_w);
                self.copied_note(note, x, self.y, line_h);
            }
            self.advance(line_h, self.px(theme::SPACE_XS));
        }
    }

    /// The caption of a copy just made (2026-11-12), after the line's last control, which ends
    /// at `x`: the first of `note` and the short [`T_COPIED`] that fits in the rest of the line.
    /// It takes no room of its own (none is written when neither fits), so nothing moves when
    /// it comes and goes.
    fn copied_note(&mut self, note: &'static str, x: i32, y: i32, line_h: i32) {
        let x = x.saturating_add(self.px(6));
        let room = self.frame.x.saturating_add(self.frame.w).saturating_sub(x);
        let fitting = [note, T_COPIED]
            .into_iter()
            .map(|text| (text, (self.label_width)(text)))
            .find(|(_, w)| *w <= room);
        let Some((text, w)) = fitting else {
            return;
        };
        self.placed.texts.push(PaintText {
            rect: Rect::new(x, y.saturating_sub(self.scroll), w, line_h),
            text: text.to_owned(),
            font: FontRole::Caption,
            color: theme::SUCCESS_TEXT.0,
            fill: None,
            wrap: false,
            align: TextAlign::Line,
            spans: Vec::new(),
        });
    }

    /// [`Item::ListRow`]: the title in a column of at least 72 DIP (so the values of short
    /// symbols line up down the list), the value right after it, the note after the value — or
    /// under the line when it has no room there.
    fn list_row(&mut self, title: &str, note: &str, value: &str, dim: bool) {
        let gap = self.px(12);
        let color = if dim { theme::MUTED } else { theme::TEXT };
        let line_h = (self.measure)("가", FontRole::BodyBold, self.frame.w.max(1));
        let top = self.y.saturating_sub(self.scroll);
        let title_w = bold_width((self.label_width)(title))
            .saturating_add(self.px(2))
            .min(self.frame.w / 2);
        let title_h = (self.measure)(title, FontRole::BodyBold, title_w).max(line_h);
        self.placed.texts.push(PaintText {
            rect: Rect::new(self.frame.x, top, title_w, title_h),
            text: title.to_owned(),
            font: FontRole::BodyBold,
            color: color.0,
            fill: None,
            wrap: true,
            align: TextAlign::Wrap,
            spans: Vec::new(),
        });
        let value_x = self
            .frame
            .x
            .saturating_add(title_w.max(self.px(72)))
            .saturating_add(gap);
        let right = self.frame.x.saturating_add(self.frame.w);
        let value_room = right.saturating_sub(value_x).max(self.px(60));
        let wanted_value = bold_width((self.label_width)(value)).saturating_add(self.px(4));
        let value_w = wanted_value.min(value_room);
        let value_wraps = wanted_value > value_room;
        let value_h = if value_wraps {
            (self.measure)(value, FontRole::BodyBold, value_w).max(line_h)
        } else {
            line_h
        };
        self.placed.texts.push(PaintText {
            rect: Rect::new(value_x, top, value_w, value_h),
            text: value.to_owned(),
            font: FontRole::BodyBold,
            color: color.0,
            fill: None,
            wrap: value_wraps,
            align: if value_wraps {
                TextAlign::Wrap
            } else {
                TextAlign::Line
            },
            spans: Vec::new(),
        });
        let mut height = title_h.max(value_h);
        if !note.is_empty() {
            let note_x = value_x.saturating_add(value_w).saturating_add(gap);
            let beside = right.saturating_sub(note_x);
            let wanted_note = (self.label_width)(note);
            let (x, y, w) = if height <= line_h && wanted_note <= beside {
                // After the value, its line on the value's baseline (9 pt beside 10 pt).
                (note_x, top.saturating_add(self.px(2)), beside)
            } else {
                (self.frame.x, top.saturating_add(height), self.frame.w)
            };
            let note_h = (self.measure)(note, FontRole::Caption, w).max(self.px(14));
            self.placed.texts.push(PaintText {
                rect: Rect::new(x, y, w, note_h),
                text: note.to_owned(),
                font: FontRole::Caption,
                color: theme::MUTED.0,
                fill: None,
                wrap: true,
                align: TextAlign::Wrap,
                spans: Vec::new(),
            });
            height = height.max(y.saturating_sub(top).saturating_add(note_h));
        }
        self.advance(height, self.px(theme::SPACE_XS));
    }

    /// [`Item::Pill`]: at the end of the row just placed when it fits there, else on its own
    /// line.
    fn pill(&mut self, text: &str, tone: Tone, row_end: Option<(i32, i32, i32)>) {
        let (fill, color, border) = tone.colors();
        let w = bold_width((self.label_width)(text)).saturating_add(self.px(20));
        let h = self.px(22);
        let right = self.frame.x.saturating_add(self.frame.w);
        let inline = row_end.filter(|(x, _, _)| x.saturating_add(w) <= right);
        let (x, y) = match inline {
            Some((x, line_y, line_h)) => (x, line_y.saturating_add((line_h - h) / 2)),
            None => (self.frame.x, self.y),
        };
        let rect = Rect::new(x, y.saturating_sub(self.scroll), w, h);
        self.shape(rect, h / 2, fill, border);
        self.placed.texts.push(PaintText {
            rect,
            text: text.to_owned(),
            font: FontRole::BodyBold,
            color: color.0,
            fill: None,
            wrap: false,
            align: TextAlign::Center,
            spans: Vec::new(),
        });
        if inline.is_none() {
            self.advance(h, self.px(theme::SPACE_S));
        }
    }

    /// [`Item::Menu`]: a drop-down's list (2026-11-12) — a bordered panel right under the
    /// selector of the row above, from its left edge and at least as wide, one entry per line.
    fn menu(&mut self, ctls: &[Ctl]) {
        let pad = self.px(MENU_PAD_DIP);
        let (x, selector_w) = self.anchor.unwrap_or((
            self.frame
                .x
                .saturating_add(self.label_column())
                .saturating_add(self.px(8)),
            0,
        ));
        let available = self
            .frame
            .x
            .saturating_add(self.frame.w)
            .saturating_sub(x)
            .max(self.px(80));
        let width = ctls
            .iter()
            .map(|ctl| self.ctl_width(ctl))
            .max()
            .unwrap_or(0)
            .saturating_add(pad.saturating_mul(2))
            .max(selector_w)
            .max(self.px(160))
            .min(available);
        // The list hangs under the row above (its 10 DIP gap shrinks to 2).
        self.y = self
            .y
            .saturating_sub(self.last_gap)
            .saturating_add(self.px(2));
        let entry_h = self.px(ENTRY_DIP);
        let count = i32::try_from(ctls.len()).unwrap_or(0);
        let height = entry_h
            .saturating_mul(count)
            .saturating_add(pad.saturating_mul(2));
        self.shape(
            Rect::new(x, self.y.saturating_sub(self.scroll), width, height),
            self.px(theme::RADIUS_CONTROL),
            theme::CARD,
            theme::BUTTON_SECONDARY.border,
        );
        let mut y = self.y.saturating_add(pad);
        for ctl in ctls {
            // On the panel, whatever is under it.
            let mut placed = ctl.clone();
            placed.backdrop = Some(theme::CARD);
            self.placed.controls.push((
                placed,
                Rect::new(
                    x.saturating_add(pad),
                    y.saturating_sub(self.scroll),
                    width.saturating_sub(pad.saturating_mul(2)),
                    entry_h,
                ),
            ));
            y = y.saturating_add(entry_h);
        }
        self.advance(height, self.px(10));
    }

    fn hold(&mut self, id: u16, label: &str, progress: u16, enabled: bool) {
        let w = self.px(320).min(self.frame.w);
        let h = self.px(44);
        let top = self.y.saturating_sub(self.scroll);
        let rect = Rect::new(self.frame.x, top, w, h);
        let radius = self.px(theme::RADIUS_CONTROL);
        let (fill, border, text) = if enabled {
            (theme::DANGER_BG, theme::DANGER_ACCENT, theme::DANGER_TEXT)
        } else {
            (theme::DISABLED_BG, theme::BORDER, theme::DISABLED_TEXT)
        };
        self.shape(rect, radius, fill, border);
        if enabled && progress > 0 {
            let strip = self.px(6);
            let filled = i32::from(progress.min(1_000))
                .saturating_mul(w.saturating_sub(radius.saturating_mul(2)))
                / 1_000;
            self.shape(
                Rect::new(
                    rect.x.saturating_add(radius),
                    rect.y
                        .saturating_add(h)
                        .saturating_sub(strip.saturating_mul(2)),
                    filled.max(strip),
                    strip,
                ),
                strip / 2,
                theme::DANGER_ACCENT,
                theme::DANGER_ACCENT,
            );
        }
        self.placed.texts.push(PaintText {
            rect,
            text: label.to_owned(),
            font: FontRole::BodyBold,
            color: text.0,
            fill: None,
            wrap: false,
            align: TextAlign::Center,
            spans: Vec::new(),
        });
        self.placed.holds.push((id, rect, enabled));
        self.advance(h, self.px(10));
    }

    fn toolbar(&mut self, title: &str, ctls: &[Ctl]) {
        let bar_h = self.px(56);
        let full_w = self.client_w;
        // The bar spans the window top (it is the first item of a screen).
        let top = self
            .y
            .saturating_sub(self.px(theme::SPACE_XL))
            .saturating_sub(self.scroll);
        self.shape(
            Rect::new(0, top, full_w, bar_h),
            0,
            theme::CARD,
            theme::CARD,
        );
        self.placed
            .rules
            .push(Rect::new(0, top.saturating_add(bar_h), full_w, 1));
        self.placed.texts.push(PaintText {
            rect: Rect::new(self.margin, top, self.width / 2, bar_h),
            text: title.to_owned(),
            font: FontRole::Subtitle,
            color: theme::TEXT.0,
            fill: None,
            wrap: false,
            align: TextAlign::Line,
            spans: Vec::new(),
        });
        let mut x = self.margin.saturating_add(self.width);
        for ctl in ctls.iter().rev() {
            let w = self.ctl_width(ctl);
            let h = self.px(control_height(ctl));
            x = x.saturating_sub(w);
            let mut placed = ctl.clone();
            placed.backdrop = Some(theme::CARD);
            if let ControlKind::Button(style) = placed.kind
                && style.fill == theme::BG
            {
                placed.kind = ControlKind::Button(theme::link_on(theme::CARD));
            }
            self.placed.controls.push((
                placed,
                Rect::new(x, top.saturating_add((bar_h - h) / 2), w, h),
            ));
            x = x.saturating_sub(self.px(8));
        }
        // Controls were pushed right to left; keep the tab order left to right.
        let count = ctls.len();
        let start = self.placed.controls.len().saturating_sub(count);
        if let Some(slice) = self.placed.controls.get_mut(start..) {
            slice.reverse();
        }
        self.y = self
            .y
            .saturating_sub(self.px(theme::SPACE_XL))
            .saturating_add(bar_h)
            .saturating_add(self.px(theme::SPACE_L));
        self.last_gap = 0;
    }

    fn steps(&mut self, labels: &[String], current: usize) {
        let count = i32::try_from(labels.len().max(1)).unwrap_or(1);
        let dot = self.px(26);
        let column = self.frame.w / count;
        let top = self.y.saturating_sub(self.scroll);
        let label_h = self.px(20);
        for (index, label) in labels.iter().enumerate() {
            let step = index.saturating_add(1);
            let offset = i32::try_from(index).unwrap_or(0);
            let center = self
                .frame
                .x
                .saturating_add(column.saturating_mul(offset))
                .saturating_add(column / 2);
            if index > 0 {
                let previous = center.saturating_sub(column);
                self.placed.rules.push(Rect::new(
                    previous.saturating_add(dot / 2).saturating_add(self.px(6)),
                    top.saturating_add(dot / 2),
                    column.saturating_sub(dot).saturating_sub(self.px(12)),
                    self.px(2).max(1),
                ));
            }
            let done = step < current;
            let active = step == current;
            let (fill, border, number_color) = if done || active {
                (theme::PRIMARY_BG, theme::PRIMARY_BG, theme::PRIMARY_TEXT)
            } else {
                (theme::CARD, theme::BORDER, theme::MUTED)
            };
            let rect = Rect::new(center.saturating_sub(dot / 2), top, dot, dot);
            self.shape(rect, dot / 2, fill, border);
            self.placed.texts.push(PaintText {
                rect,
                text: if done {
                    "✓".to_owned()
                } else {
                    step.to_string()
                },
                font: FontRole::BodyBold,
                color: number_color.0,
                fill: None,
                wrap: false,
                align: TextAlign::Center,
                spans: Vec::new(),
            });
            self.placed.texts.push(PaintText {
                rect: Rect::new(
                    center.saturating_sub(column / 2),
                    top.saturating_add(dot).saturating_add(self.px(6)),
                    column,
                    label_h,
                ),
                text: label.clone(),
                font: if active {
                    FontRole::BodyBold
                } else {
                    FontRole::Body
                },
                color: if active || done {
                    theme::TEXT.0
                } else {
                    theme::MUTED.0
                },
                fill: None,
                wrap: false,
                align: TextAlign::Center,
                spans: Vec::new(),
            });
        }
        self.advance(
            dot.saturating_add(self.px(6)).saturating_add(label_h),
            self.px(theme::SPACE_L),
        );
    }

    fn field(&mut self, label: &str, value: &str) {
        self.field_with(label, value, None);
    }

    /// A field, with a badge before the value when given.
    fn field_with(&mut self, label: &str, value: &str, badge: Option<Badge>) {
        let label_w = self.px(150).min(self.frame.w / 3);
        let mut value_x = label_w.saturating_add(self.px(12));
        if let Some(badge) = badge {
            let x = self.frame.x.saturating_add(value_x);
            value_x = value_x.saturating_add(self.badge_at(badge, x, self.px(20), BADGE_DIP));
        }
        let value_w = self.frame.w.saturating_sub(value_x).max(self.px(40));
        let mono = value.starts_with("0x")
            || crate::ui::theme::address_segments(value).is_some()
            || value.starts_with("m/");
        let font = if mono { FontRole::Mono } else { FontRole::Body };
        let value_h = (self.measure)(value, font, value_w).max(self.px(18));
        let top = self.y.saturating_sub(self.scroll);
        self.placed.texts.push(PaintText {
            rect: Rect::new(self.frame.x, top, label_w, self.px(20)),
            text: label.to_owned(),
            font: FontRole::Body,
            color: theme::MUTED.0,
            fill: None,
            wrap: false,
            align: TextAlign::Line,
            spans: Vec::new(),
        });
        self.placed.texts.push(PaintText {
            rect: Rect::new(self.frame.x.saturating_add(value_x), top, value_w, value_h),
            text: value.to_owned(),
            font,
            color: theme::TEXT.0,
            fill: None,
            wrap: true,
            align: TextAlign::Wrap,
            spans: Vec::new(),
        });
        self.advance(value_h.max(self.px(20)), self.px(theme::SPACE_S));
    }

    fn qr(&mut self, payload: &str, dpi: u32) {
        let available = self.frame.w.min(self.px(420));
        let geometry = crate::ui::qr::encode(payload)
            .and_then(|code| crate::ui::qr::layout(code.size(), dpi, available));
        match geometry {
            Some(geometry) => {
                self.placed.qrs.push((
                    self.frame.x,
                    self.y.saturating_sub(self.scroll),
                    geometry.module_pixels,
                    payload.to_owned(),
                ));
                self.advance(geometry.canvas_pixels(), self.px(theme::SPACE_M));
            }
            None => self.text(
                "창을 넓히면 QR이 표시됩니다",
                FontRole::Body,
                theme::MUTED,
                0,
                self.px(8),
            ),
        }
    }
}

/// Marks the control `id` of `items` as just copied (2026-11-12, `App::copy_text`): the answer
/// is at the control that was pressed and nothing else changes. A copy line's value draws
/// [`GLYPH_CHECK`] for its copy symbol and gets a caption after its icons (`address`: with the
/// paste check); an icon becomes the check mark with the same caption; a text button says
/// `복사됨` at the width of its label, and after an address its row ends with the paste check
/// as a tag ([`Item::Pill`]: on the row's own line whenever it fits there). No control is
/// added, removed or moved, so [`ControlSet::sync`] creates none again and the focus stays.
pub fn mark_copied(items: &mut Vec<Item>, id: u16, address: bool) {
    let mut tag_after = None;
    for (index, item) in items.iter_mut().enumerate() {
        let (ctls, row) = match item {
            Item::CopyLine { value, actions } => {
                if value.id == id {
                    if let Some(Face::Value(lines)) = &mut value.face {
                        let note = if address { T_COPIED_ADDRESS } else { T_COPIED };
                        value.face = Some(Face::Copied(core::mem::take(lines), note));
                    }
                    return;
                }
                (actions, false)
            }
            Item::Row(ctls) | Item::LabeledRow(_, ctls) => (ctls, true),
            _ => continue,
        };
        let Some(ctl) = ctls.iter_mut().find(|ctl| ctl.id == id && ctl.is_button()) else {
            continue;
        };
        match ctl.face {
            Some(Face::Glyph(_)) => ctl.face = Some(Face::Glyph(GLYPH_CHECK)),
            None => {
                let label = core::mem::replace(&mut ctl.text, T_COPIED.to_owned());
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
        let tag = Item::Pill(T_PASTE_CHECK.to_owned(), Tone::Success);
        items.insert(index.saturating_add(1), tag);
    }
}

/// Places `items` in a client area `client_w` pixels wide at `dpi`, scrolled by `scroll` px.
#[must_use]
pub fn layout(
    items: &[Item],
    client_w: i32,
    dpi: u32,
    scroll: i32,
    measure: Measure<'_>,
    label_width: MeasureWidth<'_>,
) -> Placed {
    let px = move |dip: i32| scale(dip, dpi);
    let margin = px(theme::SPACE_XL);
    // Content stays readable on wide windows: at most 880 DIP, centered.
    let max_w = px(880);
    let available = client_w
        .saturating_sub(margin.saturating_mul(2))
        .max(px(200));
    let width = available.min(max_w);
    let left = margin.saturating_add(available.saturating_sub(width) / 2);
    let mut layouter = Layouter {
        px: Box::new(px),
        measure,
        label_width,
        scroll,
        client_w,
        margin: left,
        width,
        y: margin,
        frame: Frame {
            x: left,
            w: width,
            backdrop: theme::BG,
        },
        card: None,
        last_gap: 0,
        row_end: None,
        anchor: None,
        placed: Placed::default(),
    };
    for item in items {
        layouter.place(item, dpi);
    }
    layouter.close_card();
    let mut placed = layouter.placed;
    placed.content_height = layouter.y.saturating_add(margin);
    placed
}

/// The font, color and gap (DIP) of a text item.
fn text_style(item: &Item) -> Option<(&str, FontRole, Color, i32)> {
    Some(match item {
        Item::Title(text) => (text.as_str(), FontRole::Title, theme::TEXT, theme::SPACE_M),
        Item::Display(text) => (
            text.as_str(),
            FontRole::Display,
            theme::TEXT,
            theme::SPACE_XS,
        ),
        Item::DisplayMuted(text) => (
            text.as_str(),
            FontRole::Display,
            theme::MUTED,
            theme::SPACE_XS,
        ),
        Item::Subtitle(text) => (
            text.as_str(),
            FontRole::Subtitle,
            theme::TEXT,
            theme::SPACE_S,
        ),
        Item::Text(text) => (text.as_str(), FontRole::Body, theme::TEXT, theme::SPACE_S),
        Item::Muted(text) => (text.as_str(), FontRole::Body, theme::MUTED, theme::SPACE_S),
        Item::Help(text) => (
            text.as_str(),
            FontRole::Caption,
            theme::MUTED,
            theme::SPACE_S,
        ),
        Item::Mono(text) => (text.as_str(), FontRole::Mono, theme::TEXT, theme::SPACE_S),
        _ => return None,
    })
}

impl Layouter<'_> {
    /// A badge square of `dip` at `x`, centered on a first line `line_h` tall at the current y.
    fn badge_at(&mut self, badge: Badge, x: i32, line_h: i32, dip: i32) -> i32 {
        let size = self.px(dip);
        let top = self
            .y
            .saturating_add((line_h.saturating_sub(size) / 2).max(0))
            .saturating_sub(self.scroll);
        self.placed
            .badges
            .push((badge, Rect::new(x, top, size, size)));
        size.saturating_add(self.px(BADGE_GAP_DIP))
    }

    fn badged(&mut self, badge: Badge, item: &Item, dpi: u32) {
        if let Some((text, font, color, gap)) = text_style(item) {
            let dip = if font == FontRole::Title {
                TITLE_BADGE_DIP
            } else {
                BADGE_DIP
            };
            let line_h = (self.measure)("가", font, self.frame.w.max(1));
            let indent = self.badge_at(badge, self.frame.x, line_h, dip);
            self.text(text, font, color, indent, self.px(gap));
        } else if let Item::Field(label, value) = item {
            self.field_with(label, value, Some(badge));
        } else {
            self.place(item, dpi);
        }
    }

    fn place(&mut self, item: &Item, dpi: u32) {
        let px = |dip: i32| scale(dip, dpi);
        // Only a pill right after a row uses the row's last line.
        let row_end = self.row_end.take();
        if let Some((text, font, color, gap)) = text_style(item) {
            self.text(text, font, color, 0, px(gap));
            return;
        }
        let layouter = self;
        match item {
            // Handled by `text_style` above.
            Item::Title(_)
            | Item::Display(_)
            | Item::DisplayMuted(_)
            | Item::Subtitle(_)
            | Item::Text(_)
            | Item::Muted(_)
            | Item::Help(_)
            | Item::Mono(_) => {}
            Item::Badged(badge, inner) => layouter.badged(*badge, inner, dpi),
            Item::Field(label, value) => layouter.field(label, value),
            Item::Banner(text, tone) => layouter.banner(text, *tone),
            Item::Gap(dip) => layouter.advance(0, px(*dip)),
            Item::Qr(payload) => layouter.qr(payload, dpi),
            Item::Rule => {
                let frame = layouter.frame;
                layouter.placed.rules.push(Rect::new(
                    frame.x,
                    layouter
                        .y
                        .saturating_add(px(4))
                        .saturating_sub(layouter.scroll),
                    frame.w,
                    1,
                ));
                layouter.advance(px(12), 0);
            }
            Item::Row(ctls) => layouter.row(None, ctls),
            Item::LabeledRow(label, ctls) => layouter.row(Some(label), ctls),
            Item::CopyLine { value, actions } => layouter.copy_line(value, actions),
            Item::ListRow {
                title,
                note,
                value,
                dim,
            } => layouter.list_row(title, note, value, *dim),
            Item::Pill(text, tone) => layouter.pill(text, *tone, row_end),
            Item::Menu(ctls) => layouter.menu(ctls),
            Item::CardStart(title) => layouter.open_card(title.as_deref()),
            Item::CardEnd => layouter.close_card(),
            Item::Steps(labels, current) => layouter.steps(labels, *current),
            Item::Toolbar(title, ctls) => layouter.toolbar(title, ctls),
            Item::Hold {
                id,
                label,
                progress,
                enabled,
            } => layouter.hold(*id, label, *progress, *enabled),
        }
    }
}

/// Paints the placed texts and shapes that meet the paint session's update rectangle (after a
/// scroll only the uncovered strip).
pub fn paint(dc: &mut PaintDc<'_>, client: Rect, placed: &Placed, fonts: &Fonts) {
    let area = dc.update_rect();
    let (top, bottom) = if area.h > 0 {
        (area.y, area.bottom())
    } else {
        (0, client.h)
    };
    let outside = |rect: &Rect| rect.bottom() <= top || rect.y >= bottom;
    dc.fill_rect(client, theme::BG);
    for shape in &placed.shapes {
        if outside(&shape.rect) {
            continue;
        }
        dc.round_rect(
            shape.rect,
            shape.radius,
            Color(shape.fill),
            Color(shape.border),
        );
    }
    for rule in placed.rules.iter().filter(|rule| !outside(rule)) {
        dc.fill_rect(*rule, theme::CARD_BORDER);
    }
    for (badge, rect) in placed.badges.iter().filter(|(_, rect)| !outside(rect)) {
        dc.draw_argb(rect.x, rect.y, rect.w, rect.h, &badge.render(rect.w));
    }
    for (x, y, module, payload) in &placed.qrs {
        if *y >= bottom {
            continue;
        }
        if let Some(code) = crate::ui::qr::encode(payload) {
            let geometry = crate::ui::qr::QrLayout {
                symbol_modules: code.size(),
                total_modules: code
                    .size()
                    .saturating_add(crate::ui::qr::QUIET_ZONE_MODULES.saturating_mul(2)),
                module_pixels: *module,
            };
            crate::ui::qr::paint(dc, *x, *y, &code, &geometry);
        }
    }
    for text in &placed.texts {
        if outside(&text.rect) {
            continue;
        }
        if let Some(fill) = text.fill {
            dc.fill_rect(text.rect, Color(fill));
        }
        // Own-address spans: one line, vertically centered beside their buttons; a line too
        // wide for them wraps as plain mono below.
        if !text.spans.is_empty()
            && crate::ui::theme::paint_spans(
                dc,
                fonts,
                &text.spans,
                text.rect,
                Color(text.color),
                theme::FOCUS,
            )
        {
            continue;
        }
        dc.set_text_color(Color(text.color));
        if text.font == FontRole::Mono
            && let Some(segments) = crate::ui::theme::address_segments(&text.text)
            && crate::ui::theme::paint_sol_address(dc, fonts, &segments, text.rect)
        {
            continue;
        }
        dc.select_font(fonts.get(text.font));
        let flags = match text.align {
            TextAlign::Center => DrawFlags::CENTER,
            TextAlign::Right => DrawFlags::RIGHT,
            TextAlign::Wrap if text.wrap => DrawFlags::WRAP,
            TextAlign::Line | TextAlign::Wrap => DrawFlags::LINE,
        };
        dc.draw_text(&wide(&text.text), text.rect, flags);
    }
}

/// Whether Tab stops at this control (`WS_TABSTOP` of yw-win's controls: buttons, check boxes,
/// edits and the first radio of a group) while it is enabled.
#[must_use]
pub const fn is_tab_stop(ctl: &Ctl) -> bool {
    ctl.enabled
        && match ctl.kind {
            ControlKind::Button(_) | ControlKind::CheckBox | ControlKind::Edit { .. } => true,
            ControlKind::Radio { first_in_group } => first_in_group,
            ControlKind::Label => false,
        }
}

/// A radio button's `(first of its group, checked and enabled)`; `None` for other controls
/// (Tab's entry into a radio group, `app_scroll::radio_entry`).
#[must_use]
pub fn radio_state(ctl: &Ctl) -> Option<(bool, bool)> {
    match ctl.kind {
        ControlKind::Radio { first_in_group } => {
            Some((first_in_group, ctl.enabled && ctl.checked == Some(true)))
        }
        _ => None,
    }
}

/// The kind of a control without its button colors (a style change keeps the control).
fn kind_class(kind: ControlKind) -> ControlKind {
    match kind {
        ControlKind::Button(_) => ControlKind::Button(theme::BUTTON_SECONDARY),
        other => other,
    }
}

/// The yw-win face of `ctl`'s `face` in `style` at `dpi`: a glyph in the style's text color, a
/// value's lines (emphasized spans in bold mono and `theme::FOCUS`, the rest in mono and
/// `theme::TEXT`) with the copy symbol in the link color at the right end, or a drop-down
/// entry's label from the left with its symbol at the right end. Right after a copy
/// ([`mark_copied`]) the value's symbol, or the icon, is the check mark in the success color.
fn button_face(ctl: &Ctl, face: &Face, fonts: &Fonts, style: ButtonStyle, dpi: u32) -> ButtonFace {
    match face {
        Face::Entry(mark) => ButtonFace {
            lines: vec![vec![FaceRun::new(&ctl.text, &fonts.body, style.text)]],
            left: Some(scale(ENTRY_PAD_DIP, dpi)),
            trailing: mark.map(|mark| {
                let color = if mark == GLYPH_CHECK {
                    theme::FOCUS
                } else {
                    theme::MUTED
                };
                FaceRun::new(mark, &fonts.symbol, color)
            }),
        },
        Face::Glyph(glyph) => {
            let color = if *glyph == GLYPH_CHECK {
                theme::SUCCESS_TEXT
            } else {
                style.text
            };
            ButtonFace {
                lines: vec![vec![FaceRun::new(glyph, &fonts.symbol, color)]],
                left: None,
                trailing: None,
            }
        }
        Face::Value(lines) | Face::Copied(lines, _) => ButtonFace {
            lines: lines
                .iter()
                .map(|line| {
                    line.iter()
                        .map(|(piece, emphasized)| {
                            if *emphasized {
                                FaceRun::new(piece, &fonts.mono_bold, theme::FOCUS)
                            } else {
                                FaceRun::new(piece, &fonts.mono, theme::TEXT)
                            }
                        })
                        .collect()
                })
                .collect(),
            left: Some(scale(VALUE_PAD_DIP, dpi)),
            trailing: Some(if matches!(face, Face::Copied(..)) {
                FaceRun::new(GLYPH_CHECK, &fonts.symbol, theme::SUCCESS_TEXT)
            } else {
                FaceRun::new(GLYPH_COPY, &fonts.symbol, theme::FOCUS)
            }),
        },
    }
}

/// What a headless test typed into edit `id` ([`ControlSet::type_text`]).
#[cfg(test)]
fn typed(set: &ControlSet, id: u16) -> Option<String> {
    set.typed
        .borrow()
        .iter()
        .find(|(known, _)| *known == id)
        .map(|(_, text)| text.clone())
}

/// Outside tests nothing is typed without a window.
#[cfg(not(test))]
const fn typed(_: &ControlSet, _: u16) -> Option<String> {
    None
}

/// How many leading and how many trailing entries `old` and `new` have in common, as
/// `(prefix, suffix)`. The two never overlap (`prefix + suffix <= min(old.len(), new.len())`);
/// what lies between them is the middle that a change replaces ([`ControlSet::sync`]). An entry
/// of the prefix has the same entries before it and one of the suffix the same after it, so a
/// control that moved past another one (an edit opened under another row) is always in the
/// middle.
fn common_ends<T: PartialEq>(old: &[T], new: &[T]) -> (usize, usize) {
    let prefix = old
        .iter()
        .zip(new)
        .take_while(|(was, is)| was == is)
        .count();
    let room = old.len().min(new.len()).saturating_sub(prefix);
    let suffix = old
        .iter()
        .rev()
        .zip(new.iter().rev())
        .take(room)
        .take_while(|(was, is)| was == is)
        .count();
    (prefix, suffix)
}

/// Whether a changed control list keeps the live edit of `old` where `wanted` goes, instead of
/// re-creating it from the model as it does with every other edit. Only the edit being typed in
/// stays: it has the keyboard focus (so the change did not come from a click on another control)
/// and the model did not give it another text — the wanted text is the one it wanted before, or
/// the one the edit shows (`shows`, asked last). A masked edit never stays and is never asked for
/// its text: what was typed into it is gone with any change of the list, as before.
fn keeps_edit(old: &Ctl, wanted: &Ctl, focused: bool, shows: impl FnOnce(&str) -> bool) -> bool {
    matches!(
        old.kind,
        ControlKind::Edit {
            password: false,
            ..
        }
    ) && focused
        && old.limit == wanted.limit
        && (wanted.text == old.text || shows(&wanted.text))
}

/// Whether the live edit shows exactly `text`; its text is compared in a wiping buffer.
fn shows_text(control: &Control, text: &str) -> bool {
    let units = text.encode_utf16().count().saturating_add(1);
    control
        .text_wiping(units)
        .as_slice()
        .iter()
        .copied()
        .eq(text.encode_utf16())
}

/// Whether the control that took the place of the focused one in a rebuild gets the focus back
/// ([`ControlSet::sync`]): an enabled button, check box or edit, and a radio button only when it
/// is the checked one (focusing an unchecked radio button clicks it).
const fn takes_focus_back(ctl: &Ctl) -> bool {
    ctl.enabled
        && match ctl.kind {
            ControlKind::Button(_) | ControlKind::CheckBox | ControlKind::Edit { .. } => true,
            ControlKind::Radio { .. } => matches!(ctl.checked, Some(true)),
            ControlKind::Label => false,
        }
}

/// The main window's child controls, moved and updated by every refresh. A changed control list
/// replaces only the controls between its common ends ([`common_ends`]); the ones before and
/// after stay, and the keyboard focus stays on the control with the same id (2026-11-12 —
/// before, any change re-created every control and left the focus on the window: a balance that
/// arrived took it from the field being typed in).
#[derive(Debug, Default)]
pub struct ControlSet {
    controls: Vec<(Ctl, Control)>,
    /// The DPI the button badges were rendered at.
    icon_dpi: u32,
    /// Headless tests only: what a test typed into an edit that has no window
    /// ([`ControlSet::type_text`]); the readers and `clear_text` use it then.
    #[cfg(test)]
    typed: core::cell::RefCell<Vec<(u16, String)>>,
}

impl ControlSet {
    fn signature(controls: &[(Ctl, Rect)]) -> Vec<(u16, ControlKind)> {
        controls
            .iter()
            .map(|(ctl, _)| (ctl.id, kind_class(ctl.kind)))
            .collect()
    }

    /// Destroys every control.
    pub fn clear(&mut self) {
        self.controls.clear();
    }

    /// Reads a control's current text (non-secret).
    #[must_use]
    pub fn text(&self, id: u16, max_units: usize) -> Option<String> {
        self.controls
            .iter()
            .find(|(ctl, _)| ctl.id == id)
            .map(|(_, control)| control.text(max_units))
            .or_else(|| typed(self, id))
    }

    /// Reads an edit's text into a wiping buffer (RPC tokens and URLs).
    #[must_use]
    pub fn text_wiping(&self, id: u16, max_units: usize) -> Option<yw_win::mem::WipeBuf<u16>> {
        self.controls
            .iter()
            .find(|(ctl, _)| ctl.id == id)
            .map(|(_, control)| control.text_wiping(max_units))
            .or_else(|| {
                let text = typed(self, id)?;
                let units: Vec<u16> = text.encode_utf16().take(max_units).collect();
                let mut buffer = yw_win::mem::WipeBuf::with_capacity(units.len().max(1));
                buffer.extend_from_slice(&units).ok()?;
                Some(buffer)
            })
    }

    /// Headless tests: types `text` into edit `id` (no window exists).
    #[cfg(test)]
    pub fn type_text(&self, id: u16, text: &str) {
        let mut typed = self.typed.borrow_mut();
        typed.retain(|(known, _)| *known != id);
        typed.push((id, text.to_owned()));
    }

    /// Replaces a control's text (non-secret values only).
    pub fn set_text(&self, id: u16, text: &str) {
        if let Some((_, control)) = self.controls.iter().find(|(ctl, _)| ctl.id == id) {
            control.set_text(text);
        }
    }

    /// Clears an edit.
    pub fn clear_text(&self, id: u16) {
        if let Some((_, control)) = self.controls.iter().find(|(ctl, _)| ctl.id == id) {
            control.set_text("");
        }
        #[cfg(test)]
        self.typed.borrow_mut().retain(|(known, _)| *known != id);
    }

    /// The index (placed order) of the control that has the keyboard focus.
    #[must_use]
    pub fn focused(&self) -> Option<usize> {
        self.controls
            .iter()
            .position(|(_, control)| control.has_focus())
    }

    /// Whether the control at `index` is an edit.
    #[must_use]
    pub fn is_edit(&self, index: usize) -> bool {
        self.controls
            .get(index)
            .is_some_and(|(ctl, _)| matches!(ctl.kind, ControlKind::Edit { .. }))
    }

    /// Focuses the control at `index` as Tab does (an edit's text selected).
    pub fn focus_at(&self, index: usize) {
        if let Some((ctl, control)) = self.controls.get(index) {
            if matches!(ctl.kind, ControlKind::Edit { .. }) {
                control.select_all();
            }
            control.focus();
        }
    }

    /// Whether a check box or radio is checked.
    #[must_use]
    pub fn checked(&self, id: u16) -> Option<bool> {
        self.controls
            .iter()
            .find(|(ctl, _)| ctl.id == id)
            .map(|(_, control)| control.is_checked())
    }

    /// After a pure scroll ([`Placed::shift`] + [`Window::scroll_content`], which already moved
    /// every child): shows the controls that came into `client` and hides those that left it.
    /// A control is placed at its rectangle before it is shown (whether or not the system moved
    /// it while hidden).
    pub fn scrolled(&self, placed: &Placed, client: Rect) {
        for ((_, control), (_, rect)) in self.controls.iter().zip(&placed.controls) {
            let visible = rect.bottom() > 0 && rect.y < client.h;
            if visible == control.is_shown() {
                continue;
            }
            if visible {
                control.set_rect(*rect);
            }
            control.show(visible);
        }
    }

    /// The focused control's id and, for an edit, its selection (positions, not text).
    fn focus_mark(&self) -> Option<(u16, Option<(u32, u32)>)> {
        let (ctl, control) = self.controls.get(self.focused()?)?;
        let selection = matches!(ctl.kind, ControlKind::Edit { .. }).then(|| control.selection());
        Some((ctl.id, selection))
    }

    /// After a rebuild destroyed the focused control: focuses the control that has its id now
    /// ([`takes_focus_back`]); a re-created edit gets its caret or selection back, so typing goes
    /// on where it was. An id that is gone leaves the focus on the window, as before.
    fn refocus(&self, id: u16, selection: Option<(u32, u32)>) {
        if self.focused().is_some() {
            return;
        }
        let Some((ctl, control)) = self.controls.iter().find(|(ctl, _)| ctl.id == id) else {
            return;
        };
        if !takes_focus_back(ctl) {
            return;
        }
        control.focus();
        if let (ControlKind::Edit { .. }, Some((start, end))) = (ctl.kind, selection) {
            control.set_selection(start, end);
        }
    }

    /// Makes the set match a changed control list whose `prefix` first and `suffix` last
    /// controls are the old ones ([`common_ends`]): destroys the old middle, then creates the
    /// new one. Buttons, check boxes, radios and labels at the two ends stay; an edit there
    /// stays only by [`keeps_edit`] and is otherwise re-created from the model in place.
    /// Returns, for each control of the set, whether it was created here.
    fn rebuild(
        &mut self,
        window: &Window,
        placed: &Placed,
        fonts: &Fonts,
        (prefix, suffix): (usize, usize),
    ) -> Vec<bool> {
        let tail_at = self.controls.len().saturating_sub(suffix);
        let tail = self.controls.split_off(tail_at);
        // Every old control that goes is destroyed before a new one is created.
        self.controls.truncate(prefix);
        let head = core::mem::take(&mut self.controls);
        let middle = placed
            .controls
            .len()
            .saturating_sub(prefix.saturating_add(suffix));
        let mut old: Vec<Option<(Ctl, Control)>> = head
            .into_iter()
            .map(Some)
            .chain(core::iter::repeat_with(|| None).take(middle))
            .chain(tail.into_iter().map(Some))
            .collect();
        for (slot, (wanted, _)) in old.iter_mut().zip(&placed.controls) {
            if let Some((ctl, control)) = slot.as_ref()
                && matches!(ctl.kind, ControlKind::Edit { .. })
                && !keeps_edit(ctl, wanted, control.has_focus(), |text| {
                    shows_text(control, text)
                })
            {
                *slot = None;
            }
        }
        // Sibling z-order is the Tab, arrow-key and radio-group order, and a new child starts at
        // its bottom: beside controls that stayed, each new one is put behind its predecessor
        // (in ascending order, so the whole set ends up in placed order).
        let reused = old.iter().any(Option::is_some);
        let mut created = Vec::with_capacity(old.len());
        for (slot, (ctl, rect)) in old.into_iter().zip(&placed.controls) {
            if let Some(kept) = slot {
                self.controls.push(kept);
                created.push(false);
            } else if let Ok(control) = create_control(window, ctl.kind, ctl.id, &ctl.text, *rect) {
                control.set_font(&fonts.body);
                if let Some(limit) = ctl.limit {
                    control.set_limit(limit);
                }
                if reused {
                    control.place_after(self.controls.last().map(|(_, previous)| previous));
                }
                self.controls.push((ctl.clone(), control));
                created.push(true);
            }
        }
        created
    }

    /// Creates, moves and updates controls to match `placed`. A changed list of `(id, kind)`
    /// goes through [`Self::rebuild`]; the focus it took from a destroyed control goes back to
    /// the control with that id.
    pub fn sync(&mut self, window: &Window, placed: &Placed, fonts: &Fonts, client: Rect) {
        let wanted = Self::signature(&placed.controls);
        let current: Vec<(u16, ControlKind)> = self
            .controls
            .iter()
            .map(|(ctl, _)| (ctl.id, kind_class(ctl.kind)))
            .collect();
        let dpi = window.dpi();
        let rescaled = self.icon_dpi != dpi;
        self.icon_dpi = dpi;
        let mut created = Vec::new();
        let mut focus = None;
        if wanted != current {
            focus = self.focus_mark();
            created = self.rebuild(window, placed, fonts, common_ends(&current, &wanted));
        }
        // One repaint for the whole batch: moving each control with its own repaint leaves
        // stale button images behind while scrolling.
        window.begin_batch();
        for (index, ((ctl, control), (wanted_ctl, rect))) in
            self.controls.iter_mut().zip(&placed.controls).enumerate()
        {
            // A new control has no badge, face or tooltip yet; a new DPI redoes them all.
            let fresh = rescaled || created.get(index).copied().unwrap_or(false);
            control.set_rect(*rect);
            control.set_font(&fonts.body);
            if let Some(backdrop) = wanted_ctl.backdrop {
                control.set_backdrop(backdrop);
            }
            if let ControlKind::Button(style) = wanted_ctl.kind {
                control.set_button_style(style);
                if fresh || ctl.badge != wanted_ctl.badge {
                    let size = scale(BADGE_DIP, dpi);
                    control.set_icon(wanted_ctl.badge.map(|badge| ButtonIcon {
                        size,
                        pixels: badge.render(size),
                    }));
                }
                // An entry's face draws the label and takes its color from the style.
                let relabeled = matches!(wanted_ctl.face, Some(Face::Entry(_)))
                    && (ctl.text != wanted_ctl.text || ctl.kind != wanted_ctl.kind);
                if fresh || relabeled || ctl.face != wanted_ctl.face {
                    control.set_face(
                        wanted_ctl
                            .face
                            .as_ref()
                            .map(|face| button_face(wanted_ctl, face, fonts, style, dpi)),
                    );
                }
            }
            if fresh || ctl.tip != wanted_ctl.tip {
                control.set_tooltip(wanted_ctl.tip.as_deref());
            }
            let visible = rect.bottom() > 0 && rect.y < client.h;
            control.show(visible);
            if control.is_enabled() != wanted_ctl.enabled {
                control.enable(wanted_ctl.enabled);
            }
            if !wanted_ctl.is_button()
                && let Some(checked) = wanted_ctl.checked
                && control.is_checked() != checked
            {
                control.set_checked(checked);
            }
            let label_like = !matches!(wanted_ctl.kind, ControlKind::Edit { .. });
            if label_like && ctl.text != wanted_ctl.text {
                control.set_text(&wanted_ctl.text);
            }
            *ctl = wanted_ctl.clone();
        }
        window.end_batch();
        if let Some((id, selection)) = focus {
            self.refocus(id, selection);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The old and the new middle of a changed control list, as index ranges.
    fn middles(old: &[Ctl], new: &[Ctl]) -> (core::ops::Range<usize>, core::ops::Range<usize>) {
        let signature = |ctls: &[Ctl]| -> Vec<(u16, ControlKind)> {
            ctls.iter()
                .map(|ctl| (ctl.id, kind_class(ctl.kind)))
                .collect()
        };
        let (prefix, suffix) = common_ends(&signature(old), &signature(new));
        (prefix..old.len() - suffix, prefix..new.len() - suffix)
    }

    #[test]
    fn common_ends_never_overlap() {
        assert_eq!(common_ends(&[1, 2, 3], &[1, 2, 3]), (3, 0));
        assert_eq!(common_ends(&[1, 2, 3], &[4, 5]), (0, 0));
        assert_eq!(common_ends::<u8>(&[], &[1]), (0, 0));
        // Rows added in the middle, and a style-only difference (same class) changes nothing.
        assert_eq!(common_ends(&[1, 2, 5, 6], &[1, 2, 3, 4, 5, 6]), (2, 2));
        let was = [Ctl::button(1, "가"), Ctl::button(2, "나")];
        let is = [Ctl::primary(1, "가"), Ctl::button(2, "다")];
        assert_eq!(middles(&was, &is), (2..2, 2..2));
        // Repeated ids: the suffix takes only what the prefix left.
        assert_eq!(common_ends(&[7, 7, 7], &[7, 7]), (2, 0));
        assert_eq!(common_ends(&[7, 8, 7], &[7]), (1, 0));
        assert_eq!(common_ends(&[7, 8, 7], &[7, 7]), (1, 1));
    }

    /// An edit that opens under another row is in the middle (destroyed and re-created), with
    /// whatever was typed into it: the masked RPC address field (설정 → 네트워크(RPC) `교체`) and
    /// the rename field of the recovery phrases.
    #[test]
    fn an_edit_that_changes_rows_is_rebuilt() {
        const EDIT: u16 = 90;
        let row = |base: u16| {
            vec![
                Ctl::button(base, "교체"),
                Ctl::button(base + 1, "테스트"),
                Ctl::danger(base + 2, "삭제"),
            ]
        };
        let field = |password: bool| {
            vec![
                Ctl::edit(EDIT, "", 420, password, 2_048),
                Ctl::primary(91, "저장"),
                Ctl::button(92, "취소"),
            ]
        };
        let at = |ctls: &[Ctl]| ctls.iter().position(|ctl| ctl.id == EDIT).unwrap();
        // RPC rows: three buttons each, the field under the row being replaced.
        let under_first = [row(10), field(true), row(13), row(16)].concat();
        let under_second = [row(10), row(13), field(true), row(16)].concat();
        let (old, new) = middles(&under_first, &under_second);
        assert!(old.contains(&at(&under_first)) && new.contains(&at(&under_second)));
        let (old, new) = middles(&under_second, &under_first);
        assert!(old.contains(&at(&under_second)) && new.contains(&at(&under_first)));
        // Recovery phrases: the field takes the place of the row's own buttons.
        let actions = |base: u16| {
            vec![
                Ctl::button(base, "이름 바꾸기"),
                Ctl::button(base + 1, "단어 보기"),
            ]
        };
        let first = [field(false), actions(22), actions(24)].concat();
        let second = [actions(20), field(false), actions(24)].concat();
        let third = [actions(20), actions(22), field(false)].concat();
        for (was, is) in [(&first, &second), (&second, &third), (&third, &first)] {
            let (old, new) = middles(was, is);
            assert!(
                old.contains(&at(was)) && new.contains(&at(is)),
                "{old:?} {new:?}"
            );
        }
    }

    /// The send form while the address-book rows under the address change: the address edit
    /// stays in the prefix and the amount edit in the suffix (kept or not by [`keeps_edit`]).
    #[test]
    fn picker_rows_change_between_the_send_edits() {
        let form = |rows: &[u16]| {
            let mut ctls = vec![
                Ctl::edit(1, "0x12", 430, false, 64),
                Ctl::button(2, "주소록에서 선택"),
            ];
            ctls.extend(rows.iter().map(|id| Ctl::tab(*id, "항목", false)));
            ctls.extend([
                Ctl::edit(3, "", 260, false, 128),
                Ctl::button(4, "최대"),
                Ctl::primary(5, "검토"),
            ]);
            ctls
        };
        assert_eq!(
            middles(&form(&[30, 31]), &form(&[30, 31, 32, 33])),
            (4..4, 4..6)
        );
        assert_eq!(middles(&form(&[30, 31, 32]), &form(&[35])), (2..5, 2..3));
        assert_eq!(middles(&form(&[]), &form(&[30])), (2..2, 2..3));
    }

    /// Only the plain edit being typed in survives a rebuild, and only while the model did not
    /// give it another text; a masked edit never does, and its text is not even looked at.
    #[test]
    fn only_the_focused_plain_edit_is_kept() {
        let plain = Ctl::edit(1, "abc", 200, false, 64);
        let asked = core::cell::Cell::new(false);
        let shows = |answer: bool| {
            let asked = &asked;
            move |_: &str| {
                asked.set(true);
                answer
            }
        };
        // The model did not change: kept without reading the edit (what was typed stays).
        assert!(keeps_edit(&plain, &plain, true, shows(false)));
        assert!(!asked.get());
        // The model follows the typing: kept when the edit shows the wanted text.
        let typed = Ctl::edit(1, "abcd", 200, false, 64);
        assert!(keeps_edit(&plain, &typed, true, shows(true)));
        // The model re-seeded it, it is not focused, or its limit changed: re-created.
        assert!(!keeps_edit(&plain, &typed, true, shows(false)));
        assert!(!keeps_edit(&plain, &plain, false, shows(true)));
        let longer = Ctl::edit(1, "abc", 200, false, 128);
        assert!(!keeps_edit(&plain, &longer, true, shows(true)));
        // Masked: never, whatever the answers would be — and nobody asks.
        asked.set(false);
        let masked = Ctl::edit(1, "", 200, true, 64);
        assert!(!keeps_edit(&masked, &masked, true, shows(true)));
        assert!(!asked.get());
        // Not an edit at all.
        let button = Ctl::button(1, "abc");
        assert!(!keeps_edit(&button, &button, true, shows(true)));
    }

    /// The focus goes back to an enabled control, and to a radio button only when it is the
    /// checked one (a focused unchecked radio button would be clicked).
    #[test]
    fn focus_returns_only_where_it_cannot_click() {
        assert!(takes_focus_back(&Ctl::button(1, "가")));
        assert!(takes_focus_back(&Ctl::edit(1, "", 100, true, 8)));
        assert!(!takes_focus_back(&Ctl::button(1, "가").enabled(false)));
        assert!(takes_focus_back(&Ctl::radio(1, "가", true, true)));
        assert!(!takes_focus_back(&Ctl::radio(1, "가", false, true)));
        let label = Ctl {
            kind: ControlKind::Label,
            ..Ctl::button(1, "가")
        };
        assert!(!takes_focus_back(&label));
    }

    #[test]
    fn shift_equals_layout_at_the_new_offset() {
        let items = vec![
            Item::Title("제목".to_owned()),
            Item::Banner("주의 문구".to_owned(), Tone::Warn),
            Item::CardStart(Some("카드".to_owned())),
            Item::Field("주소".to_owned(), "0x1234".to_owned()),
            Item::Row(vec![Ctl::button(1, "보내기"), Ctl::primary(2, "받기")]),
            Item::Pill("메인넷 — 실제 자산".to_owned(), Tone::BtcMainnet),
            Item::Menu(vec![
                Ctl::tab(4, "Base", false),
                Ctl::tab(5, "Sepolia", true),
            ]),
            Item::CopyLine {
                value: Ctl::value(
                    6,
                    "주소 복사",
                    crate::ui::theme::own_address_spans(
                        "0xF9900bb6FF2D2C67858c3468d21c5f103C4Ff646",
                        crate::ui::theme::AddressKind::Evm,
                        false,
                    ),
                ),
                actions: vec![Ctl::icon(7, GLYPH_OPEN, "탐색기에서 주소 보기")],
            },
            Item::ListRow {
                title: "USDG".to_owned(),
                note: "Global Dollar, Paxos".to_owned(),
                value: "0 USDG".to_owned(),
                dim: false,
            },
            Item::Rule,
            Item::Qr("0x1234".to_owned()),
            Item::CardEnd,
            Item::Hold {
                id: 3,
                label: "길게 누르기".to_owned(),
                progress: 0,
                enabled: true,
            },
            Item::Text("본문".to_owned()),
        ];
        let measure = |_: &str, _: FontRole, _: i32| 20;
        let width = |text: &str| i32::try_from(text.len()).unwrap_or(0).saturating_mul(7);
        let at = |scroll: i32| layout(&items, 900, 96, scroll, &measure, &width);
        let mut shifted = at(120);
        shifted.shift(120 - 45);
        assert_eq!(shifted, at(45));
        shifted.shift(45 - 300);
        assert_eq!(shifted, at(300));
    }

    /// A pill sits at the end of the row above it when it fits (no line of its own).
    #[test]
    fn pill_joins_the_row() {
        let measure = |_: &str, _: FontRole, _: i32| 20;
        let width = |text: &str| i32::try_from(text.len()).unwrap_or(0).saturating_mul(7);
        let row = Item::LabeledRow("네트워크".to_owned(), vec![Ctl::button(1, "Sepolia ▾")]);
        let pill = Item::Pill("테스트넷".to_owned(), Tone::Testnet);
        let alone = layout(std::slice::from_ref(&row), 900, 96, 0, &measure, &width);
        let tagged = layout(&[row, pill], 900, 96, 0, &measure, &width);
        assert_eq!(tagged.content_height, alone.content_height);
        let (_, button) = &tagged.controls[0];
        let tag = tagged
            .texts
            .iter()
            .find(|text| text.text == "테스트넷")
            .unwrap();
        assert!(tag.rect.x > button.x + button.w, "after the button");
        assert!(tag.rect.y >= button.y && tag.rect.bottom() <= button.bottom());
    }

    /// A copy line (2026-11-11): the value button from the text's left edge up to the icons,
    /// which sit right-aligned on the same line; in a narrow window the value takes the whole
    /// width in lines of whole characters (its spans kept) and the icons go on the next line.
    #[test]
    fn copy_line_keeps_the_value_whole_and_the_icons_beside_it() {
        let measure = |_: &str, _: FontRole, _: i32| 20;
        let width = |text: &str| i32::try_from(text.len()).unwrap_or(0).saturating_mul(7);
        let address = "0xF9900bb6FF2D2C67858c3468d21c5f103C4Ff646";
        let spans =
            crate::ui::theme::own_address_spans(address, crate::ui::theme::AddressKind::Evm, false);
        let line = Item::CopyLine {
            value: Ctl::value(7, "주소 복사", spans.clone()),
            actions: vec![
                Ctl::icon(8, GLYPH_OPEN, "탐색기에서 열기"),
                Ctl::icon(9, GLYPH_LINK, "탐색기 링크 복사"),
            ],
        };
        let placed = layout(std::slice::from_ref(&line), 900, 96, 0, &measure, &width);
        let (value, value_rect) = &placed.controls[0];
        assert_eq!(value.text, "주소 복사");
        assert_eq!(value.tip.as_deref(), Some("주소 복사"));
        assert_eq!(value.face, Some(Face::Value(vec![spans.clone()])));
        assert_eq!(value.value_text().as_deref(), Some(address));
        let (open, open_rect) = &placed.controls[1];
        let (chain_link, link_rect) = &placed.controls[2];
        assert_eq!(open.face, Some(Face::Glyph(GLYPH_OPEN)));
        assert_eq!(chain_link.tip.as_deref(), Some("탐색기 링크 복사"));
        // The text lines up with the card's left edge (the padding hangs out), the icons sit
        // right after the value (4 DIP, then 2 DIP apart), and everything is on one line.
        let margin = scale(theme::SPACE_XL, 96);
        assert_eq!(value_rect.x + VALUE_PAD_DIP, margin);
        assert_eq!(open_rect.x, value_rect.x + value_rect.w + 4);
        assert_eq!(link_rect.x, open_rect.x + open_rect.w + 2);
        assert!(link_rect.x + link_rect.w < 900 - margin);
        assert!(open_rect.y >= value_rect.y && open_rect.bottom() <= value_rect.bottom());
        assert_eq!(link_rect.y, open_rect.y);

        // 300 px: 42 characters do not fit beside the icons; on their own line they need two
        // lines of whole characters.
        let narrow = layout(std::slice::from_ref(&line), 300, 96, 0, &measure, &width);
        let (value, value_rect) = &narrow.controls[0];
        let lines = match &value.face {
            Some(Face::Value(lines)) => lines.clone(),
            _ => Vec::new(),
        };
        assert!(lines.len() >= 2, "{lines:?}");
        let joined: Vec<(String, bool)> = lines.iter().flatten().cloned().collect();
        let text: String = joined.iter().map(|(piece, _)| piece.as_str()).collect();
        assert_eq!(text, address);
        // The emphasis survives the break (a piece may end up on the next line).
        let strong: String = joined
            .iter()
            .filter(|(_, strong)| *strong)
            .map(|(piece, _)| piece.as_str())
            .collect();
        assert_eq!(strong, "F990f646");
        let (_, open_rect) = &narrow.controls[1];
        assert!(open_rect.y >= value_rect.bottom(), "icons under the value");
        assert_eq!(open_rect.x, value_rect.x + VALUE_PAD_DIP);
    }

    /// 2026-11-12: a copy is answered at its control and nothing else changes. The value's
    /// copy symbol becomes the check mark with a caption after the icons (an address keeps the
    /// paste check, or the short `복사됨` where that does not fit), an icon becomes the check
    /// mark, a text button says `복사됨` at its own width (an address: the paste check as a
    /// tag at the end of its row). The same controls at the same places, no new line.
    #[test]
    fn copied_mark_is_at_the_control_and_moves_nothing() {
        let measure = |_: &str, _: FontRole, _: i32| 20;
        let width = |text: &str| i32::try_from(text.len()).unwrap_or(0).saturating_mul(7);
        let address = "0xF9900bb6FF2D2C67858c3468d21c5f103C4Ff646";
        let spans =
            crate::ui::theme::own_address_spans(address, crate::ui::theme::AddressKind::Evm, false);
        let items = vec![
            Item::CopyLine {
                value: Ctl::value(7, "주소 복사", spans.clone()),
                actions: vec![
                    Ctl::icon(8, GLYPH_OPEN, "탐색기에서 열기"),
                    Ctl::icon(9, GLYPH_LINK, "탐색기 링크 복사"),
                ],
            },
            Item::Row(vec![
                Ctl::primary(10, "주소 복사"),
                Ctl::button(11, "QR 보기"),
            ]),
        ];
        let rects = |placed: &Placed| -> Vec<(u16, Rect)> {
            placed
                .controls
                .iter()
                .map(|(ctl, rect)| (ctl.id, *rect))
                .collect()
        };
        let captions = |placed: &Placed| -> Vec<PaintText> {
            placed
                .texts
                .iter()
                .filter(|text| text.text.starts_with(T_COPIED))
                .cloned()
                .collect()
        };
        let marked = |id: u16, address: bool| {
            let mut items = items.clone();
            mark_copied(&mut items, id, address);
            items
        };
        let plain = layout(&items, 900, 96, 0, &measure, &width);
        assert!(captions(&plain).is_empty());

        // The address: the check mark's face, the caption with the paste check after the icons.
        let placed = layout(&marked(7, true), 900, 96, 0, &measure, &width);
        assert_eq!(rects(&placed), rects(&plain));
        assert_eq!(placed.content_height, plain.content_height);
        let (value, _) = &placed.controls[0];
        assert_eq!(
            value.face,
            Some(Face::Copied(vec![spans.clone()], T_COPIED_ADDRESS))
        );
        assert_eq!(value.value_text().as_deref(), Some(address));
        let last = placed.controls[2].1;
        let end = last.x + last.w + 6;
        let notes = captions(&placed);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].text, T_COPIED_ADDRESS);
        assert_eq!(
            (notes[0].rect.x, notes[0].color),
            (end, theme::SUCCESS_TEXT.0)
        );
        assert_eq!(placed.texts.len(), plain.texts.len() + 1);

        // 100 px after the icons: the short caption; no room at all: none, and nothing moves.
        let margin = scale(theme::SPACE_XL, 96);
        for (room, caption) in [(100, Some(T_COPIED)), (20, None)] {
            let client = end + room + margin;
            let unmarked = layout(&items, client, 96, 0, &measure, &width);
            let placed = layout(&marked(7, true), client, 96, 0, &measure, &width);
            assert_eq!(rects(&placed), rects(&unmarked), "{room}");
            let notes = captions(&placed);
            assert_eq!(notes.first().map(|note| note.text.as_str()), caption);
        }

        // The value on its own lines (300 px): the caption after the icons under it.
        let unmarked = layout(&items, 300, 96, 0, &measure, &width);
        let narrow = layout(&marked(7, false), 300, 96, 0, &measure, &width);
        assert_eq!(rects(&narrow), rects(&unmarked));
        assert_eq!(narrow.content_height, unmarked.content_height);
        let last = narrow.controls[2].1;
        let notes = captions(&narrow);
        assert_eq!(notes[0].text, T_COPIED);
        assert_eq!(notes[0].rect.x, last.x + last.w + 6);
        assert!(notes[0].rect.y >= narrow.controls[0].1.bottom());

        // An icon (`탐색기 링크 복사`): the check mark in its place, the value as it was.
        let placed = layout(&marked(9, false), 900, 96, 0, &measure, &width);
        assert_eq!(rects(&placed), rects(&plain));
        assert_eq!(placed.controls[0].0.face, plain.controls[0].0.face);
        assert_eq!(placed.controls[2].0.face, Some(Face::Glyph(GLYPH_CHECK)));
        assert_eq!(
            placed.controls[2].0.tip.as_deref(),
            Some("탐색기 링크 복사")
        );
        assert_eq!(captions(&placed)[0].text, T_COPIED);

        // A text button: `복사됨` at its width; after an address the paste check is a tag at
        // the end of its row.
        let placed = layout(&marked(10, false), 900, 96, 0, &measure, &width);
        assert_eq!(rects(&placed), rects(&plain));
        assert_eq!(placed.controls[3].0.text, T_COPIED);
        assert_eq!(placed.texts, plain.texts);
        let placed = layout(&marked(10, true), 900, 96, 0, &measure, &width);
        assert_eq!(rects(&placed), rects(&plain));
        assert_eq!(placed.content_height, plain.content_height);
        let other = placed.controls[4].1;
        let tag = placed.texts.iter().find(|text| text.text == T_PASTE_CHECK);
        assert!(tag.is_some_and(|tag| tag.rect.x > other.x + other.w && tag.rect.y >= other.y));
    }

    #[test]
    fn break_spans_cuts_whole_characters() {
        let spans = vec![
            ("0x".to_owned(), false),
            ("AbCd".to_owned(), true),
            ("1234".to_owned(), false),
        ];
        assert_eq!(
            break_spans(&spans, 8),
            vec![
                vec![
                    ("0x".to_owned(), false),
                    ("AbCd".to_owned(), true),
                    ("12".to_owned(), false)
                ],
                vec![("34".to_owned(), false)],
            ]
        );
        assert_eq!(break_spans(&spans, 10).len(), 1);
    }
}
