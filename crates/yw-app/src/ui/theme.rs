//! The design system (spec/04 §1.6): color tokens, the status colors 정보·주의·고위험·차단 (plus
//! 완료·오류·테스트넷), one type scale, the 4-DIP spacing grid and the button styles. Light theme
//! only. Every window (main, secret W01–W10, approval A01) draws from these tokens.

use std::collections::HashMap;

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
    /// Body, labels, buttons: Malgun Gothic 10 pt.
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
            caption: body_font(9, false, dpi)?,
            subtitle: body_font(11, true, dpi)?,
            display: body_font(20, true, dpi)?,
            body: body_font(10, false, dpi)?,
            title: body_font(14, true, dpi)?,
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
            FontRole::Caption => &self.caption,
            FontRole::Subtitle => &self.subtitle,
            FontRole::Display => &self.display,
        }
    }
}

/// Korean object particle for `word` (`을` after a final consonant, `를` otherwise), judged by
/// how the last character is read: Hangul by its final consonant, digits and Latin letters by
/// their Korean names (L·M·N·R and 0·1·3·6·7·8 end in a consonant).
#[must_use]
pub fn object_particle(word: &str) -> &'static str {
    if ends_in_consonant(word, false) {
        "을"
    } else {
        "를"
    }
}

/// Korean direction particle for `word` (`으로` after a final consonant other than ㄹ, `로`
/// otherwise).
#[must_use]
pub fn direction_particle(word: &str) -> &'static str {
    if ends_in_consonant(word, true) {
        "으로"
    } else {
        "로"
    }
}

fn ends_in_consonant(word: &str, rieul_is_vowel: bool) -> bool {
    let Some(last) = word.trim_end().chars().last() else {
        return false;
    };
    let code = u32::from(last);
    if (0xAC00..=0xD7A3).contains(&code) {
        let final_index = (code - 0xAC00) % 28;
        return final_index != 0 && !(rieul_is_vowel && final_index == 8);
    }
    match last.to_ascii_uppercase() {
        'L' | 'R' | '1' | '7' | '8' => !rieul_is_vowel,
        'M' | 'N' | '0' | '3' | '6' => true,
        _ => false,
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
    use super::{direction_particle, object_particle, sol_address_segments};

    #[test]
    fn particles_follow_the_last_sound() {
        assert_eq!(object_particle("0.01 ETH"), "를");
        assert_eq!(object_particle("1 SOL"), "을");
        assert_eq!(object_particle("10 USDC"), "를");
        assert_eq!(object_particle("계정"), "을");
        assert_eq!(object_particle("주소"), "를");
        assert_eq!(direction_particle("서울"), "로");
        assert_eq!(direction_particle("계정"), "으로");
        assert_eq!(direction_particle("0x1cdb"), "로");
        assert_eq!(direction_particle("…EcaE da94"), "로");
        assert_eq!(direction_particle("abc0"), "으로");
        assert_eq!(direction_particle("abc8"), "로");
    }

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
