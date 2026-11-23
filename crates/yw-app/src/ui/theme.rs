//! The design system (spec/04 §1.6): color tokens, the status colors 정보·주의·고위험·차단 (plus
//! 완료·오류·테스트넷), one type scale, the 4-DIP spacing grid and the button styles. Light theme
//! only. Every window (main, secret W01–W10, approval A01) draws from these tokens.

use std::collections::HashMap;

use yw_core::lang::Lang;
use yw_win::ui::controls::ButtonStyle;
use yw_win::ui::{Color, DrawFlags, Font, PaintDc, Rect};

// ----- surfaces ------------------------------------------------------------------------------

/// Window background (behind cards).
pub const BG: Color = Color(0x00F3_F4F6);
/// Card (section) background.
pub const CARD: Color = Color(0x00FF_FFFF);
/// Card outline.
pub const CARD_BORDER: Color = Color(0x00E1_E4E8);
/// Body text.
pub const TEXT: Color = Color(0x001F_1F1F);
/// Secondary text.
pub const MUTED: Color = Color(0x005F_6368);
/// Separators and field borders.
pub const BORDER: Color = Color(0x00C8_C8C8);
/// Focus and progress.
pub const FOCUS: Color = Color(0x000F_6CBD);
/// Escaped-character marks.
pub const ESCAPE_TEXT: Color = Color(0x00A4_262C);
/// Disabled control fill.
pub const DISABLED_BG: Color = Color(0x00F2_F2F2);
/// Disabled label.
pub const DISABLED_TEXT: Color = Color(0x009A_A0A6);
/// Primary button fill.
pub const PRIMARY_BG: Color = Color(0x000F_6CBD);
/// Primary button fill while pressed.
pub const PRIMARY_PRESSED: Color = Color(0x000B_5394);
/// Primary button text.
pub const PRIMARY_TEXT: Color = Color(0x00FF_FFFF);

// ----- status colors (one meaning each, spec/04 §1.6) ------------------------------------------

/// 정보 (information) background.
pub const INFO_BG: Color = Color(0x00E8_F1FB);
/// 정보 text.
pub const INFO_TEXT: Color = Color(0x000F_4C81);
/// 정보 accent bar.
pub const INFO_ACCENT: Color = Color(0x000F_6CBD);
/// 완료 (success) background.
pub const SUCCESS_BG: Color = Color(0x00DF_F6DD);
/// 완료 text.
pub const SUCCESS_TEXT: Color = Color(0x000E_700E);
/// 완료 accent bar.
pub const SUCCESS_ACCENT: Color = Color(0x0010_7C10);
/// 주의 (caution) background.
pub const WARN_BG: Color = Color(0x00FF_F4CE);
/// 주의 text.
pub const WARN_TEXT: Color = Color(0x007A_5C00);
/// 주의 accent bar.
pub const WARN_ACCENT: Color = Color(0x00C1_9C00);
/// 고위험 (high risk) and 오류 (error) background.
pub const DANGER_BG: Color = Color(0x00FD_E7E9);
/// 고위험 / 오류 text.
pub const DANGER_TEXT: Color = Color(0x00A4_262C);
/// 고위험 / 오류 accent bar.
pub const DANGER_ACCENT: Color = Color(0x00C4_2B1C);
/// 차단 (blocked) background: solid, so it is never mistaken for a warning.
pub const BLOCKED_BG: Color = Color(0x00A4_262C);
/// 차단 text.
pub const BLOCKED_TEXT: Color = Color(0x00FF_FFFF);
/// Testnet band.
pub const TESTNET_BG: Color = Color(0x00E8_F0FE);
/// Testnet accent bar.
pub const TESTNET_ACCENT: Color = Color(0x0066_8CD9);
/// Bitcoin mainnet banner (spec/08 §2 "빨강 배경").
pub const BTC_MAINNET_BG: Color = Color(0x00C4_2B1C);
/// Bitcoin testnet4 banner (spec/08 §2 "주황 배경").
pub const BTC_TESTNET4_BG: Color = Color(0x00F7_A23B);
/// Text on the Bitcoin mainnet banner.
pub const BTC_MAINNET_TEXT: Color = Color(0x00FF_FFFF);
/// The AI explanation panel (spec/04 §1.6, §3.8; spec/06 §6): set apart from the core display.
pub const AI_PANEL_BG: Color = Color(0x00F3_F0FA);
/// The AI panel's outline and title accent.
pub const AI_PANEL_BORDER: Color = Color(0x00D9_D0EE);

// ----- spacing grid (DIP) --------------------------------------------------------------------

/// 4 DIP: inside a control group.
pub const SPACE_XS: i32 = 4;
/// 8 DIP: between related lines.
pub const SPACE_S: i32 = 8;
/// 12 DIP: between items of a card.
pub const SPACE_M: i32 = 12;
/// 16 DIP: card padding, between cards.
pub const SPACE_L: i32 = 16;
/// 24 DIP: window margin.
pub const SPACE_XL: i32 = 24;
/// Card corner radius.
pub const RADIUS_CARD: i32 = 8;
/// Button and banner corner radius.
pub const RADIUS_CONTROL: i32 = 6;

// ----- buttons -------------------------------------------------------------------------------

/// The main action of a screen (one per screen: 보내기, 검토, 시작하기 …).
pub const BUTTON_PRIMARY: ButtonStyle = ButtonStyle {
    fill: PRIMARY_BG,
    text: PRIMARY_TEXT,
    border: PRIMARY_BG,
    pressed: PRIMARY_PRESSED,
    disabled_fill: Color(0x00C9_D8EA),
    disabled_text: CARD,
    disabled_border: Color(0x00C9_D8EA),
    focus: CARD,
    radius: RADIUS_CONTROL,
};
/// Every other action.
pub const BUTTON_SECONDARY: ButtonStyle = ButtonStyle {
    fill: CARD,
    text: TEXT,
    border: Color(0x00B8_BEC6),
    pressed: Color(0x00EB_EEF2),
    disabled_fill: DISABLED_BG,
    disabled_text: DISABLED_TEXT,
    disabled_border: CARD_BORDER,
    focus: FOCUS,
    radius: RADIUS_CONTROL,
};
/// Destructive actions (삭제, 연결 해제, 모두 해제, 폐기 …).
pub const BUTTON_DANGER: ButtonStyle = ButtonStyle {
    fill: CARD,
    text: DANGER_TEXT,
    border: DANGER_ACCENT,
    pressed: DANGER_BG,
    disabled_fill: DISABLED_BG,
    disabled_text: DISABLED_TEXT,
    disabled_border: CARD_BORDER,
    focus: DANGER_ACCENT,
    radius: RADIUS_CONTROL,
};
/// Navigation (← 메인으로) and show/hide toggles (고급 ▸, 자세히 ▸): text only. `fill` and
/// `border` are the window background; [`link_on`] makes the card variant.
pub const BUTTON_LINK: ButtonStyle = ButtonStyle {
    fill: BG,
    text: FOCUS,
    border: BG,
    pressed: Color(0x00E3_E8EF),
    disabled_fill: BG,
    disabled_text: DISABLED_TEXT,
    disabled_border: BG,
    focus: FOCUS,
    radius: RADIUS_CONTROL,
};
/// The selected segment of a tab or chip row (chain tabs, networks, settings sections).
pub const BUTTON_TAB_ON: ButtonStyle = ButtonStyle {
    fill: PRIMARY_BG,
    text: PRIMARY_TEXT,
    border: PRIMARY_BG,
    pressed: PRIMARY_PRESSED,
    disabled_fill: Color(0x00C9_D8EA),
    disabled_text: CARD,
    disabled_border: Color(0x00C9_D8EA),
    focus: CARD,
    radius: RADIUS_CONTROL,
};
/// An unselected segment.
pub const BUTTON_TAB_OFF: ButtonStyle = ButtonStyle {
    fill: CARD,
    text: TEXT,
    border: CARD_BORDER,
    pressed: Color(0x00EB_EEF2),
    disabled_fill: DISABLED_BG,
    disabled_text: DISABLED_TEXT,
    disabled_border: CARD_BORDER,
    focus: FOCUS,
    radius: RADIUS_CONTROL,
};
/// An entry of an open drop-down (2026-11-12): flat on the list panel, the hover fill shows
/// which one the pointer is on.
pub const BUTTON_ENTRY: ButtonStyle = ButtonStyle {
    fill: CARD,
    text: TEXT,
    border: CARD,
    pressed: Color(0x00DD_E3EB),
    disabled_fill: CARD,
    disabled_text: DISABLED_TEXT,
    disabled_border: CARD,
    focus: FOCUS,
    radius: 4,
};
/// The selected entry: a light tint (and a ✓ at its right end) instead of a solid bar.
pub const BUTTON_ENTRY_ON: ButtonStyle = ButtonStyle {
    fill: INFO_BG,
    border: INFO_BG,
    pressed: Color(0x00CF_E0F5),
    ..BUTTON_ENTRY
};

/// A link button drawn on `backdrop` (card or window background).
#[must_use]
pub const fn link_on(backdrop: Color) -> ButtonStyle {
    ButtonStyle {
        fill: backdrop,
        border: backdrop,
        disabled_fill: backdrop,
        disabled_border: backdrop,
        ..BUTTON_LINK
    }
}

/// Font roles (the type scale, spec/04 §1.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FontRole {
    /// Body, labels, buttons: 10 pt (Malgun Gothic in Korean, Segoe UI in English).
    Body,
    /// Screen title: bold 14 pt.
    Title,
    /// Addresses, hex, keys: Consolas 10 pt.
    Mono,
    /// Mnemonic display: Consolas 14 pt.
    MonoLarge,
    /// Approval title: bold 12 pt.
    ApprovalTitle,
    /// Bold body 10 pt (sections, band head).
    BodyBold,
    /// Raw hex (calldata): Consolas 9 pt.
    MonoSmall,
    /// Emphasized address groups: Consolas bold 10 pt (spec/07 §12.3, spec/04 §3.3).
    MonoBold,
    /// Help lines and captions: 9 pt.
    Caption,
    /// Card headings: bold 11 pt.
    Subtitle,
    /// Balances and the welcome headline: bold 20 pt.
    Display,
}

/// The fonts of one DPI.
#[derive(Debug)]
pub struct Fonts {
    /// Caption.
    pub caption: Font,
    /// Subtitle.
    pub subtitle: Font,
    /// Display.
    pub display: Font,
    /// Body.
    pub body: Font,
    /// Title.
    pub title: Font,
    /// Mono.
    pub mono: Font,
    /// Large mono.
    pub mono_large: Font,
    /// Approval title.
    pub approval_title: Font,
    /// Bold body.
    pub body_bold: Font,
    /// Small mono.
    pub mono_small: Font,
    /// Bold mono.
    pub mono_bold: Font,
    /// Icon symbols (Segoe UI Symbol 11 pt: the icon buttons' ⧉ ↗ 🔗 ☆ and the copy symbol of a
    /// copyable value, 2026-11-11).
    pub symbol: Font,
}

/// The body face of `lang` and its fallback (spec/04 §1.6, spec/14 §2). Korean is Malgun Gothic.
/// English is Segoe UI (2026-11-15: before, both languages used Malgun Gothic, which draws `\` as
/// `₩`, so English paths read `%LOCALAPPDATA%₩YourWallet`); Hangul in English text (a user's
/// label, `한국어` in the language card) still draws through the system font link to Malgun Gothic.
const fn body_faces(lang: Lang) -> [&'static str; 2] {
    match lang {
        Lang::Ko => ["Malgun Gothic", "Segoe UI"],
        Lang::En => ["Segoe UI", "Malgun Gothic"],
    }
}

fn body_font(lang: Lang, size: u16, bold: bool, dpi: u32) -> Option<Font> {
    let [face, fallback] = body_faces(lang);
    Font::create(face, size, bold, dpi)
        .or_else(|_| Font::create(fallback, size, bold, dpi))
        .ok()
}

impl Fonts {
    /// Creates the fonts for `dpi` and the UI language `lang`.
    #[must_use]
    pub fn create(dpi: u32, lang: Lang) -> Option<Self> {
        Some(Self {
            caption: body_font(lang, 9, false, dpi)?,
            subtitle: body_font(lang, 11, true, dpi)?,
            display: body_font(lang, 20, true, dpi)?,
            body: body_font(lang, 10, false, dpi)?,
            title: body_font(lang, 14, true, dpi)?,
            mono: Font::create("Consolas", 10, false, dpi).ok()?,
            mono_large: Font::create("Consolas", 14, false, dpi).ok()?,
            approval_title: body_font(lang, 12, true, dpi)?,
            body_bold: body_font(lang, 10, true, dpi)?,
            mono_small: Font::create("Consolas", 9, false, dpi).ok()?,
            mono_bold: Font::create("Consolas", 10, true, dpi).ok()?,
            symbol: Font::create("Segoe UI Symbol", 11, false, dpi).ok()?,
        })
    }

    /// The font of a role.
    #[must_use]
    pub const fn get(&self, role: FontRole) -> &Font {
        match role {
            FontRole::Body => &self.body,
            FontRole::Title => &self.title,
            FontRole::Mono => &self.mono,
            FontRole::MonoLarge => &self.mono_large,
            FontRole::ApprovalTitle => &self.approval_title,
            FontRole::BodyBold => &self.body_bold,
            FontRole::MonoSmall => &self.mono_small,
            FontRole::MonoBold => &self.mono_bold,
            FontRole::Caption => &self.caption,
            FontRole::Subtitle => &self.subtitle,
            FontRole::Display => &self.display,
        }
    }
}

/// Fonts per DPI (windows on different monitors) and language (an approval window keeps the
/// language it opened in while the main window may switch).
#[derive(Debug, Default)]
pub struct FontCache {
    by_dpi: HashMap<(u32, Lang), Fonts>,
}

impl FontCache {
    /// The fonts for `dpi` in `lang`, created on first use.
    pub fn for_dpi(&mut self, dpi: u32, lang: Lang) -> Option<&Fonts> {
        if let std::collections::hash_map::Entry::Vacant(entry) = self.by_dpi.entry((dpi, lang)) {
            entry.insert(Fonts::create(dpi, lang)?);
        }
        self.by_dpi.get(&(dpi, lang))
    }
}

/// UTF-16 for drawing (non-secret text).
#[must_use]
pub fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

/// Draws `(text, emphasized)` spans on one line from `rect`'s left edge: emphasized spans in
/// bold mono and `strong`, the rest in regular mono and `color`. Returns `false` (nothing
/// drawn) when the line is wider than `rect.w`. 2026-11-24 (spec/15 §11.4 S5-2): the span helpers
/// that cut an address into these spans (`address_spans`, `own_address_spans`, `whole_address`,
/// `address_with_notes`, `AddressKind`) moved unchanged to `yw_engine::screen::address`, with
/// their tests; the drawing stays here.
pub fn paint_spans(
    dc: &mut PaintDc<'_>,
    fonts: &Fonts,
    spans: &[(String, bool)],
    rect: Rect,
    color: Color,
    strong: Color,
) -> bool {
    let measured: Vec<(Vec<u16>, bool, i32)> = spans
        .iter()
        .map(|(text, emphasized)| {
            dc.select_font(fonts.get(if *emphasized {
                FontRole::MonoBold
            } else {
                FontRole::Mono
            }));
            let units = wide(text);
            let (_, width) = dc.measure(&units, i32::MAX);
            (units, *emphasized, width)
        })
        .collect();
    let total = measured
        .iter()
        .fold(0_i32, |sum, (_, _, width)| sum.saturating_add(*width));
    if total > rect.w {
        return false;
    }
    let mut x = rect.x;
    for (units, emphasized, width) in &measured {
        dc.select_font(fonts.get(if *emphasized {
            FontRole::MonoBold
        } else {
            FontRole::Mono
        }));
        dc.set_text_color(if *emphasized { strong } else { color });
        dc.draw_text(
            units,
            Rect::new(x, rect.y, width.saturating_add(4), rect.h),
            DrawFlags::LINE,
        );
        x = x.saturating_add(*width);
    }
    true
}
