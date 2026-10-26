//! Main window rendering (spec/04 §2): screens are described as a vertical list of [`Item`]s
//! (painted text, banners, rows of standard controls for non-secret values); [`layout`] places
//! them for the current width, DPI and scroll offset, [`paint`] draws the text, and
//! [`ControlSet::sync`] creates or moves the child controls.

use yw_win::ui::controls::{Control, ControlKind, create_control};
use yw_win::ui::{DrawFlags, PaintDc, Rect, Window, scale};

use crate::ui::theme::{self, FontRole, Fonts, wide};

/// Banner tone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// `DANGER_BG`.
    Danger,
    /// `WARN_BG`.
    Warn,
    /// Neutral info.
    Info,
    /// `TESTNET_BG`.
    Testnet,
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
    /// Check state for check boxes and radios.
    pub checked: Option<bool>,
    /// Edit length limit.
    pub limit: Option<u32>,
}

impl Ctl {
    /// A push button.
    #[must_use]
    pub fn button(id: u16, text: &str) -> Self {
        Self {
            id,
            kind: ControlKind::Button,
            text: text.to_owned(),
            width: 0,
            enabled: true,
            checked: None,
            limit: None,
        }
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
        }
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
    /// Monospace line (addresses, hashes).
    Mono(String),
    /// Colored banner.
    Banner(String, Tone),
    /// Vertical space (DIP).
    Gap(i32),
    /// A horizontal row of controls.
    Row(Vec<Ctl>),
    /// A label on the left and controls on the right in one row.
    LabeledRow(String, Vec<Ctl>),
    /// A thin separator line.
    Rule,
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
    /// Background fill.
    pub fill: Option<theme_color::Value>,
    /// Wrap or single line.
    pub wrap: bool,
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
    /// Separator lines.
    pub rules: Vec<Rect>,
    /// Controls with their pixel rectangles.
    pub controls: Vec<(Ctl, Rect)>,
    /// Total content height (px, unscrolled).
    pub content_height: i32,
}

/// Measures `(text, font, width)` → height in pixels.
pub type Measure<'a> = &'a dyn Fn(&str, FontRole, i32) -> i32;
/// Measures a one-line label width in pixels.
pub type MeasureWidth<'a> = &'a dyn Fn(&str) -> i32;

const fn control_height(kind: ControlKind) -> i32 {
    match kind {
        ControlKind::Edit { .. } => 28,
        ControlKind::Button => 32,
        ControlKind::CheckBox | ControlKind::Radio { .. } => 24,
        ControlKind::Label => 22,
    }
}

/// Places `items` in a client area `client_w` pixels wide at `dpi`, scrolled by `scroll` px.
#[must_use]
#[expect(clippy::too_many_lines, reason = "one pass over the item kinds")]
pub fn layout(
    items: &[Item],
    client_w: i32,
    dpi: u32,
    scroll: i32,
    measure: Measure<'_>,
    label_width: MeasureWidth<'_>,
) -> Placed {
    let px = |dip: i32| scale(dip, dpi);
    let margin = px(24);
    let width = client_w
        .saturating_sub(margin.saturating_mul(2))
        .max(px(200));
    let mut y = margin;
    let mut placed = Placed::default();
    let push_text = |placed: &mut Placed,
                     y: &mut i32,
                     text: &str,
                     font: FontRole,
                     color: u32,
                     fill: Option<u32>,
                     gap: i32| {
        let pad = if fill.is_some() { px(10) } else { 0 };
        let inner = width.saturating_sub(pad.saturating_mul(2));
        let height = measure(text, font, inner).max(px(16));
        let rect = Rect::new(
            margin,
            y.saturating_sub(scroll),
            width,
            height.saturating_add(pad.saturating_mul(2)),
        );
        placed.texts.push(PaintText {
            rect,
            text: text.to_owned(),
            font,
            color,
            fill,
            wrap: true,
        });
        *y = y.saturating_add(rect.h).saturating_add(gap);
    };
    let ctl_width = |ctl: &Ctl| -> i32 {
        if ctl.width > 0 {
            px(ctl.width)
        } else {
            label_width(&ctl.text).saturating_add(px(28)).max(px(80))
        }
    };
    for item in items {
        match item {
            Item::Title(text) => push_text(
                &mut placed,
                &mut y,
                text,
                FontRole::Title,
                theme::TEXT.0,
                None,
                px(12),
            ),
            Item::Text(text) => push_text(
                &mut placed,
                &mut y,
                text,
                FontRole::Body,
                theme::TEXT.0,
                None,
                px(8),
            ),
            Item::Muted(text) => push_text(
                &mut placed,
                &mut y,
                text,
                FontRole::Body,
                theme::MUTED.0,
                None,
                px(8),
            ),
            Item::Mono(text) => push_text(
                &mut placed,
                &mut y,
                text,
                FontRole::Mono,
                theme::TEXT.0,
                None,
                px(8),
            ),
            Item::Banner(text, tone) => {
                let (fill, color) = match tone {
                    Tone::Danger => (theme::DANGER_BG, theme::DANGER_TEXT),
                    Tone::Warn => (theme::WARN_BG, theme::WARN_TEXT),
                    Tone::Info => (theme::DISABLED_BG, theme::TEXT),
                    Tone::Testnet => (theme::TESTNET_BG, theme::TEXT),
                };
                push_text(
                    &mut placed,
                    &mut y,
                    text,
                    FontRole::Body,
                    color.0,
                    Some(fill.0),
                    px(10),
                );
            }
            Item::Gap(dip) => y = y.saturating_add(px(*dip)),
            Item::Rule => {
                placed.rules.push(Rect::new(
                    margin,
                    y.saturating_add(px(4)).saturating_sub(scroll),
                    width,
                    1,
                ));
                y = y.saturating_add(px(12));
            }
            Item::Row(ctls) | Item::LabeledRow(_, ctls) => {
                let mut x = margin;
                let row_h = ctls
                    .iter()
                    .map(|ctl| px(control_height(ctl.kind)))
                    .max()
                    .unwrap_or(px(24))
                    .max(px(24));
                if let Item::LabeledRow(label, _) = item {
                    let label_w = px(180).min(width / 3);
                    placed.texts.push(PaintText {
                        rect: Rect::new(margin, y.saturating_sub(scroll), label_w, row_h),
                        text: label.clone(),
                        font: FontRole::Body,
                        color: theme::TEXT.0,
                        fill: None,
                        wrap: false,
                    });
                    x = margin.saturating_add(label_w).saturating_add(px(8));
                }
                for ctl in ctls {
                    let w = ctl_width(ctl)
                        .min(margin.saturating_add(width).saturating_sub(x).max(px(40)));
                    if x.saturating_add(w) > margin.saturating_add(width) && x > margin {
                        x = margin;
                        y = y.saturating_add(row_h).saturating_add(px(6));
                    }
                    let h = px(control_height(ctl.kind));
                    let rect = Rect::new(
                        x,
                        y.saturating_add((row_h - h) / 2).saturating_sub(scroll),
                        w,
                        h,
                    );
                    placed.controls.push((ctl.clone(), rect));
                    x = x.saturating_add(w).saturating_add(px(8));
                }
                y = y.saturating_add(row_h).saturating_add(px(8));
            }
        }
    }
    placed.content_height = y.saturating_add(margin);
    placed
}

/// Paints the placed texts.
pub fn paint(dc: &mut PaintDc<'_>, client: Rect, placed: &Placed, fonts: &Fonts) {
    dc.fill_rect(client, theme::BG);
    for rule in &placed.rules {
        dc.fill_rect(*rule, theme::BORDER);
    }
    for text in &placed.texts {
        if text.rect.bottom() < 0 || text.rect.y > client.h {
            continue;
        }
        if let Some(fill) = text.fill {
            dc.fill_rect(text.rect, yw_win::ui::Color(fill));
        }
        dc.select_font(fonts.get(text.font));
        dc.set_text_color(yw_win::ui::Color(text.color));
        let inner = if text.fill.is_some() {
            let pad = (text.rect.h
                - dc.measure_wrapped(&wide(&text.text), text.rect.w, DrawFlags::WRAP))
            .max(0)
                / 2;
            Rect::new(
                text.rect.x.saturating_add(pad),
                text.rect.y.saturating_add(pad),
                text.rect.w.saturating_sub(pad.saturating_mul(2)),
                text.rect.h,
            )
        } else {
            text.rect
        };
        dc.draw_text(
            &wide(&text.text),
            inner,
            if text.wrap {
                DrawFlags::WRAP
            } else {
                DrawFlags::LINE
            },
        );
    }
}

/// The main window's child controls, recreated when the set changes and moved otherwise.
#[derive(Debug, Default)]
pub struct ControlSet {
    controls: Vec<(Ctl, Control)>,
}

impl ControlSet {
    fn signature(controls: &[(Ctl, Rect)]) -> Vec<(u16, ControlKind)> {
        controls.iter().map(|(ctl, _)| (ctl.id, ctl.kind)).collect()
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
    }

    /// Reads an edit's text into a wiping buffer (RPC tokens and URLs).
    #[must_use]
    pub fn text_wiping(&self, id: u16, max_units: usize) -> Option<yw_win::mem::WipeBuf<u16>> {
        self.controls
            .iter()
            .find(|(ctl, _)| ctl.id == id)
            .map(|(_, control)| control.text_wiping(max_units))
    }

    /// Clears an edit.
    pub fn clear_text(&self, id: u16) {
        if let Some((_, control)) = self.controls.iter().find(|(ctl, _)| ctl.id == id) {
            control.set_text("");
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

    /// Creates, moves and updates controls to match `placed`.
    pub fn sync(&mut self, window: &Window, placed: &Placed, fonts: &Fonts, client: Rect) {
        let wanted = Self::signature(&placed.controls);
        let current: Vec<(u16, ControlKind)> = self
            .controls
            .iter()
            .map(|(ctl, _)| (ctl.id, ctl.kind))
            .collect();
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
        for ((ctl, control), (wanted_ctl, rect)) in self.controls.iter_mut().zip(&placed.controls) {
            control.set_rect(*rect);
            control.set_font(&fonts.body);
            let visible = rect.bottom() > 0 && rect.y < client.h;
            control.show(visible);
            if control.is_enabled() != wanted_ctl.enabled {
                control.enable(wanted_ctl.enabled);
            }
            if let Some(checked) = wanted_ctl.checked
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
    }
}
