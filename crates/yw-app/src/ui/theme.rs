//! Colors and fonts (spec/04 §1.6). Light theme only.

use std::collections::HashMap;

use yw_win::ui::{Color, DrawFlags, Font, PaintDc, Rect};

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
/// Bitcoin mainnet banner (spec/08 §2 "빨강 배경").
pub const BTC_MAINNET_BG: Color = Color(0x00C4_2B1C);
/// Bitcoin testnet4 banner (spec/08 §2 "주황 배경").
pub const BTC_TESTNET4_BG: Color = Color(0x00F7_A23B);
/// Text on the Bitcoin mainnet banner.
pub const BTC_MAINNET_TEXT: Color = Color(0x00FF_FFFF);
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
    /// Emphasized address groups: Consolas bold 10 pt (spec/07 §12.3, spec/04 §3.3).
    MonoBold,
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
    /// Bold mono.
    pub mono_bold: Font,
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
            mono_bold: Font::create("Consolas", 10, true, dpi).ok()?,
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

/// The segments of a grouped Solana address line (spec/07 §12.3: the whole address in 4-character
/// groups, first and last group regular, the middle groups bold): `(text, bold)` with the
/// separating spaces as regular segments. `None` unless `text` is exactly
/// [`yw_core::sol::address::grouped`] of a valid address, so no other text changes weight.
#[must_use]
pub fn sol_address_segments(text: &str) -> Option<Vec<(&str, bool)>> {
    let groups: Vec<&str> = text.split(' ').collect();
    if groups.len() < 3
        || groups
            .iter()
            .any(|group| group.is_empty() || group.len() > 4)
    {
        return None;
    }
    let address = yw_core::sol::SolAddress::parse(&groups.concat()).ok()?;
    if yw_core::sol::address::grouped(&address) != text {
        return None;
    }
    let last = groups.len().saturating_sub(1);
    let mut segments = Vec::with_capacity(groups.len().saturating_mul(2));
    for (index, group) in groups.into_iter().enumerate() {
        if index != 0 {
            segments.push((" ", false));
        }
        segments.push((group, index != 0 && index != last));
    }
    Some(segments)
}

/// Characters drawn bold at each end of a Bitcoin address (spec/04 §3.3, spec/08 §10).
pub const BTC_BOLD_ENDS: usize = 6;

/// The segments of a grouped Bitcoin address line (spec/04 §3.3: the whole address in
/// 4-character groups, the first 6 and the last 6 characters bold): `(text, bold)` with the
/// separating spaces as regular segments; a group crossing a boundary is split there. `None`
/// unless `text` is exactly [`crate::ui::screens_btc::grouped`] of an address that parses on
/// mainnet or testnet4, so no other text changes weight.
#[must_use]
pub fn btc_address_segments(text: &str) -> Option<Vec<(&str, bool)>> {
    let groups: Vec<&str> = text.split(' ').collect();
    if groups.len() < 3
        || groups
            .iter()
            .any(|group| group.is_empty() || group.len() > 4 || !group.is_ascii())
    {
        return None;
    }
    let address = groups.concat();
    let parses = yw_core::btc::BtcNetwork::ALL
        .into_iter()
        .any(|net| yw_core::btc::parse_address(&address, net).is_ok());
    if !parses || crate::ui::screens_btc::grouped(&address) != text {
        return None;
    }
    let tail = address.len().checked_sub(BTC_BOLD_ENDS)?;
    let mut segments = Vec::with_capacity(groups.len().saturating_mul(3));
    let mut start = 0_usize;
    for (index, group) in groups.into_iter().enumerate() {
        if index != 0 {
            segments.push((" ", false));
        }
        let end = start.saturating_add(group.len());
        let mut cuts = vec![0_usize];
        for boundary in [BTC_BOLD_ENDS, tail] {
            if boundary > start && boundary < end {
                cuts.push(boundary.saturating_sub(start));
            }
        }
        cuts.push(group.len());
        cuts.dedup();
        for pair in cuts.windows(2) {
            let (Some(&from), Some(&to)) = (pair.first(), pair.get(1)) else {
                continue;
            };
            let piece = group.get(from..to)?;
            let at = start.saturating_add(from);
            segments.push((piece, at < BTC_BOLD_ENDS || at >= tail));
        }
        start = end;
    }
    Some(segments)
}

/// The emphasized segments of a grouped Solana or Bitcoin address line, if `text` is one.
#[must_use]
pub fn address_segments(text: &str) -> Option<Vec<(&str, bool)>> {
    sol_address_segments(text).or_else(|| btc_address_segments(text))
}

/// Draws `segments` on one line from `(x, y)` with the regular / bold mono fonts in the current
/// text color. Returns `false` (nothing drawn) when the line is wider than `rect.w`.
pub fn paint_sol_address(
    dc: &mut PaintDc<'_>,
    fonts: &Fonts,
    segments: &[(&str, bool)],
    rect: Rect,
) -> bool {
    let measured: Vec<(Vec<u16>, FontRole, i32)> = segments
        .iter()
        .map(|(text, bold)| {
            let role = if *bold {
                FontRole::MonoBold
            } else {
                FontRole::Mono
            };
            dc.select_font(fonts.get(role));
            let units = wide(text);
            let (_, width) = dc.measure(&units, i32::MAX);
            (units, role, width)
        })
        .collect();
    let total = measured
        .iter()
        .fold(0_i32, |sum, (_, _, width)| sum.saturating_add(*width));
    if total > rect.w {
        return false;
    }
    let mut x = rect.x;
    for (units, role, width) in &measured {
        dc.select_font(fonts.get(*role));
        dc.draw_text(
            units,
            Rect::new(x, rect.y, width.saturating_add(4), rect.h),
            DrawFlags::LINE,
        );
        x = x.saturating_add(*width);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::sol_address_segments;

    #[test]
    fn only_grouped_solana_addresses_get_bold_middle_groups() {
        let segments =
            sol_address_segments("HAgk 14Jp MQLg t6rV gv7c BQFJ WFto 5Dqx i472 uT3D Kpqk")
                .unwrap_or_default();
        assert_eq!(segments.len(), 21);
        let bold: Vec<&str> = segments
            .iter()
            .filter(|(_, bold)| *bold)
            .map(|(text, _)| *text)
            .collect();
        assert_eq!(
            bold,
            [
                "14Jp", "MQLg", "t6rV", "gv7c", "BQFJ", "WFto", "5Dqx", "i472", "uT3D"
            ]
        );
        assert_eq!(segments.first(), Some(&("HAgk", false)));
        assert_eq!(segments.last(), Some(&("Kpqk", false)));
        let joined: String = segments.iter().map(|(text, _)| *text).collect();
        assert_eq!(
            joined,
            "HAgk 14Jp MQLg t6rV gv7c BQFJ WFto 5Dqx i472 uT3D Kpqk"
        );
        // Ungrouped, regrouped, altered or non-address text keeps its weight.
        for text in [
            "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
            "HAgk 14Jp MQLg t6rV gv7c BQFJ WFto 5Dqx i472 uT3D Kpq0",
            "HAg k14J pMQL gt6r Vgv7 cBQF JWFt o5Dq xi47 2uT3 DKpq k",
            "HAgk  14Jp MQLg t6rV gv7c BQFJ WFto 5Dqx i472 uT3D Kpqk",
            "0x98 58Ef FD23",
            "새 계정(아직 없음)",
            "",
        ] {
            assert!(sol_address_segments(text).is_none(), "{text}");
        }
    }
}
