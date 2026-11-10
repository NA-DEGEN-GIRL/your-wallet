//! Main window rendering (spec/04 §2): screens are described as a vertical list of [`Item`]s
//! (painted text, cards, banners, rows of standard controls for non-secret values); [`layout`]
//! places them for the current width, DPI and scroll offset, [`paint`] draws the text and shapes,
//! and [`ControlSet::sync`] creates or moves the child controls.
//!
//! The design system (spec/04 §1.6, `ui::theme`): a light-gray window with white cards
//! ([`Item::CardStart`] … [`Item::CardEnd`]), one type scale, a 4-DIP spacing grid, owner-drawn
//! primary / secondary / danger / link / tab buttons, and banners that always name their status
//! (정보·완료·주의·고위험·차단·오류·테스트넷) in a colored tag.

use yw_win::ui::controls::{ButtonIcon, ButtonStyle, Control, ControlKind, create_control};
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
        }
    }

    /// Draws a chain badge before a button's label (other kinds ignore it).
    #[must_use]
    pub const fn badge(mut self, badge: Badge) -> Self {
        self.badge = Some(badge);
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
    /// Monospace line (addresses, hashes). Grouped Solana/Bitcoin addresses get their bold groups.
    Mono(String),
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

const fn control_height(kind: ControlKind) -> i32 {
    match kind {
        ControlKind::Edit { .. } => 30,
        ControlKind::Button(_) => 34,
        ControlKind::CheckBox | ControlKind::Radio { .. } => 24,
        ControlKind::Label => 22,
    }
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
        });
        self.advance(height, self.px(theme::SPACE_S));
    }

    fn ctl_width(&self, ctl: &Ctl) -> i32 {
        if ctl.width > 0 {
            self.px(ctl.width)
        } else {
            let pad = if ctl.is_button() { 36 } else { 28 };
            let badge = if ctl.is_button() && ctl.badge.is_some() {
                BADGE_DIP + BADGE_GAP_DIP
            } else {
                0
            };
            (self.label_width)(&ctl.text)
                .saturating_add(self.px(pad + badge))
                .max(self.px(if ctl.is_button() { 88 } else { 60 }))
        }
    }

    fn row(&mut self, label: Option<&str>, ctls: &[Ctl]) {
        let frame = self.frame;
        let mut x = frame.x;
        let right = frame.x.saturating_add(frame.w);
        let mut row_h = ctls
            .iter()
            .map(|ctl| self.px(control_height(ctl.kind)))
            .max()
            .unwrap_or(self.px(24))
            .max(self.px(24));
        if let Some(label) = label {
            let label_w = self.px(170).min(frame.w / 3);
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
            });
            x = frame.x.saturating_add(label_w).saturating_add(self.px(8));
        }
        let line_start = x;
        for ctl in ctls {
            let w = self
                .ctl_width(ctl)
                .min(right.saturating_sub(line_start).max(self.px(40)));
            if x.saturating_add(w) > right && x > line_start {
                x = line_start;
                self.y = self.y.saturating_add(row_h).saturating_add(self.px(6));
            }
            let h = self.px(control_height(ctl.kind));
            let rect = Rect::new(
                x,
                self.y
                    .saturating_add((row_h - h) / 2)
                    .saturating_sub(self.scroll),
                w,
                h,
            );
            let mut placed = ctl.clone();
            placed.backdrop = Some(frame.backdrop);
            if let ControlKind::Button(style) = placed.kind
                && style.fill == theme::BG
                && frame.backdrop != theme::BG
            {
                // A link button on a card takes the card color.
                placed.kind = ControlKind::Button(theme::link_on(frame.backdrop));
            }
            self.placed.controls.push((placed, rect));
            x = x.saturating_add(w).saturating_add(self.px(8));
        }
        self.advance(row_h, self.px(10));
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
        });
        let mut x = self.margin.saturating_add(self.width);
        for ctl in ctls.iter().rev() {
            let w = self.ctl_width(ctl);
            let h = self.px(control_height(ctl.kind));
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
        });
        self.placed.texts.push(PaintText {
            rect: Rect::new(self.frame.x.saturating_add(value_x), top, value_w, value_h),
            text: value.to_owned(),
            font,
            color: theme::TEXT.0,
            fill: None,
            wrap: true,
            align: TextAlign::Wrap,
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
        if let Some((text, font, color, gap)) = text_style(item) {
            self.text(text, font, color, 0, px(gap));
            return;
        }
        let layouter = self;
        match item {
            // Handled by `text_style` above.
            Item::Title(_)
            | Item::Display(_)
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

/// The main window's child controls, recreated when the set changes and moved otherwise.
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

    /// Creates, moves and updates controls to match `placed`.
    pub fn sync(&mut self, window: &Window, placed: &Placed, fonts: &Fonts, client: Rect) {
        let wanted = Self::signature(&placed.controls);
        let current: Vec<(u16, ControlKind)> = self
            .controls
            .iter()
            .map(|(ctl, _)| (ctl.id, kind_class(ctl.kind)))
            .collect();
        let dpi = window.dpi();
        let fresh = wanted != current || self.icon_dpi != dpi;
        self.icon_dpi = dpi;
        if wanted != current {
            self.controls.clear();
            for (ctl, rect) in &placed.controls {
                if let Ok(control) = create_control(window, ctl.kind, ctl.id, &ctl.text, *rect) {
                    control.set_font(&fonts.body);
                    if let Some(limit) = ctl.limit {
                        control.set_limit(limit);
                    }
                    self.controls.push((ctl.clone(), control));
                }
            }
        }
        // One repaint for the whole batch: moving each control with its own repaint leaves
        // stale button images behind while scrolling.
        window.begin_batch();
        for ((ctl, control), (wanted_ctl, rect)) in self.controls.iter_mut().zip(&placed.controls) {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shift_equals_layout_at_the_new_offset() {
        let items = vec![
            Item::Title("제목".to_owned()),
            Item::Banner("주의 문구".to_owned(), Tone::Warn),
            Item::CardStart(Some("카드".to_owned())),
            Item::Field("주소".to_owned(), "0x1234".to_owned()),
            Item::Row(vec![Ctl::button(1, "보내기"), Ctl::primary(2, "받기")]),
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
}
