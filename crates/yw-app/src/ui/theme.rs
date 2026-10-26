//! Colors and fonts (spec/04 §1.6). Light theme only.

use std::collections::HashMap;

use yw_win::ui::{Color, Font};

/// Window background.
pub const BG: Color = Color(0x00FF_FFFF);
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
/// High-risk / blocked background.
pub const DANGER_BG: Color = Color(0x00FD_E7E9);
/// High-risk / blocked text.
pub const DANGER_TEXT: Color = Color(0x00A4_262C);
/// Caution background.
pub const WARN_BG: Color = Color(0x00FF_F4CE);
/// Caution text.
pub const WARN_TEXT: Color = Color(0x007A_5C00);
/// Testnet band.
pub const TESTNET_BG: Color = Color(0x00E8_F0FE);
/// Disabled control fill.
pub const DISABLED_BG: Color = Color(0x00F2_F2F2);
/// Primary button fill.
pub const PRIMARY_BG: Color = Color(0x000F_6CBD);
/// Primary button text.
pub const PRIMARY_TEXT: Color = Color(0x00FF_FFFF);

/// Font roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FontRole {
    /// Body, labels, buttons: Malgun Gothic 10 pt.
    Body,
    /// Screen title: bold 13 pt.
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
}

/// The fonts of one DPI.
#[derive(Debug)]
pub struct Fonts {
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
}

fn body_font(size: u16, bold: bool, dpi: u32) -> Option<Font> {
    Font::create("Malgun Gothic", size, bold, dpi)
        .or_else(|_| Font::create("Segoe UI", size, bold, dpi))
        .ok()
}

impl Fonts {
    /// Creates the fonts for `dpi`.
    #[must_use]
    pub fn create(dpi: u32) -> Option<Self> {
        Some(Self {
            body: body_font(10, false, dpi)?,
            title: body_font(13, true, dpi)?,
            mono: Font::create("Consolas", 10, false, dpi).ok()?,
            mono_large: Font::create("Consolas", 14, false, dpi).ok()?,
            approval_title: body_font(12, true, dpi)?,
            body_bold: body_font(10, true, dpi)?,
            mono_small: Font::create("Consolas", 9, false, dpi).ok()?,
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
        }
    }
}

/// Fonts per DPI (windows on different monitors).
#[derive(Debug, Default)]
pub struct FontCache {
    by_dpi: HashMap<u32, Fonts>,
}

impl FontCache {
    /// The fonts for `dpi`, created on first use.
    pub fn for_dpi(&mut self, dpi: u32) -> Option<&Fonts> {
        if let std::collections::hash_map::Entry::Vacant(entry) = self.by_dpi.entry(dpi) {
            entry.insert(Fonts::create(dpi)?);
        }
        self.by_dpi.get(&dpi)
    }
}

/// UTF-16 for drawing (non-secret text).
#[must_use]
pub fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}
