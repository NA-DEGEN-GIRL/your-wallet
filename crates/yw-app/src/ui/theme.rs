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
    /// Icon symbols (Segoe UI Symbol 11 pt: the icon buttons' ⧉ ↗ 🔗 ☆ and the copy symbol of a
    /// copyable value, 2026-11-11).
    pub symbol: Font,
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

/// Korean-only helpers (spec/14 §2): the particles are written as escapes, so the i18n scan (Hangul
/// string literals outside the catalogues) does not count them — they have no English counterpart
/// and only Korean templates use them.
///
/// Korean object particle for `word` (`을` after a final consonant, `를` otherwise), judged by
/// how the last character is read: Hangul by its final consonant, digits and Latin letters by
/// their Korean names (L·M·N·R and 0·1·3·6·7·8 end in a consonant).
#[must_use]
pub fn object_particle(word: &str) -> &'static str {
    if ends_in_consonant(word, false) {
        "\u{C744}" // 을
    } else {
        "\u{B97C}" // 를
    }
}

/// Korean direction particle for `word` (`으로` after a final consonant other than ㄹ, `로`
/// otherwise).
#[must_use]
pub fn direction_particle(word: &str) -> &'static str {
    if ends_in_consonant(word, true) {
        "\u{C73C}\u{B85C}" // 으로
    } else {
        "\u{B85C}" // 로
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

/// The family of `text` when it is one whole address without spaces: `0x` + 40 hex digits, a
/// Bitcoin address of mainnet or testnet4, a Zcash address or a Solana address.
#[must_use]
pub fn address_kind(text: &str) -> Option<AddressKind> {
    if text.is_empty() || !text.is_ascii() || text.contains(char::is_whitespace) {
        return None;
    }
    if let Some(digits) = text.strip_prefix("0x") {
        return (digits.len() == 40 && digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .then_some(AddressKind::Evm);
    }
    if yw_core::btc::BtcNetwork::ALL
        .into_iter()
        .any(|net| yw_core::btc::parse_address(text, net).is_ok())
    {
        return Some(AddressKind::Bitcoin);
    }
    if yw_core::zec::ZecNetwork::ALL
        .into_iter()
        .any(|net| yw_core::zec::parse_recipient(text, net).is_ok())
    {
        return Some(AddressKind::Zcash);
    }
    yw_core::sol::SolAddress::parse(text)
        .is_ok()
        .then_some(AddressKind::Solana)
}

/// `address` in the 4-character groups the screens drew before 2026-11-12 (EVM: `0x`, then
/// groups of the 40 digits; the others from the first character).
fn grouped_form(address: &str, kind: AddressKind) -> String {
    let (head, rest) = match kind {
        AddressKind::Evm => (
            address.get(..2).unwrap_or(""),
            address.get(2..).unwrap_or(""),
        ),
        AddressKind::Solana | AddressKind::Bitcoin | AddressKind::Zcash => ("", address),
    };
    let mut out = String::with_capacity(address.len().saturating_add(address.len() / 4));
    out.push_str(head);
    for (index, character) in rest.chars().enumerate() {
        if index != 0 && index % 4 == 0 {
            out.push(' ');
        }
        out.push(character);
    }
    out
}

/// `text` as one whole address and its family: the address itself ([`address_kind`]) or that
/// address in exactly the 4-character groups of [`grouped_form`] (the approval display model's
/// EVM addresses, `yw_core::sol::address::grouped`, `ui::screens_btc::grouped`), so only an
/// address line is redrawn, never other text with spaces.
#[must_use]
pub fn whole_address(text: &str) -> Option<(String, AddressKind)> {
    if !text.contains(' ') {
        return address_kind(text).map(|kind| (text.to_owned(), kind));
    }
    let joined: String = text.split(' ').collect();
    let kind = address_kind(&joined)?;
    (grouped_form(&joined, kind) == text).then_some((joined, kind))
}

/// A line that is one address ([`whole_address`]) followed by its bracketed notes (the approval
/// display model's `0x… [일반 계정(EOA)] [주소록: A]`): the address part and the notes, so the
/// address is drawn whole on its own line (2026-11-14, spec/04 §3.3; before, the notes kept such
/// a line in its 4-character groups).
#[must_use]
pub fn address_with_notes(text: &str) -> Option<(&str, &str)> {
    let (address, notes) = text.split_once(" [")?;
    whole_address(address)?;
    (!notes.is_empty()).then_some(())?;
    Some((address, text.get(address.len().saturating_add(1)..)?))
}

/// How every address line is drawn (2026-11-12, spec/04 §3.3): the [`own_address_spans`] of
/// [`whole_address`]: the whole address without spaces, the 4 characters after its family's
/// prefix and the last 4 emphasized. `None` for any other text.
#[must_use]
pub fn address_spans(text: &str) -> Option<Vec<(String, bool)>> {
    whole_address(text).map(|(address, kind)| own_address_spans(&address, kind, false))
}

/// The address family of an own-account address line ([`own_address_spans`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressKind {
    /// `0x` + 40 hex (checksum case kept).
    Evm,
    /// Base58, no prefix.
    Solana,
    /// Bech32 (`bc1q`/`bc1p`/`tb1q`/`tb1p`, prefix of 4) or base58 (`1…`/`3…`/`m…`/`n…`/`2…`).
    Bitcoin,
    /// Transparent `t1…`/`t3…` (testnet `tm…`/`t2…`), prefix of 2.
    Zcash,
}

/// Characters emphasized at each end of an own-account address (after the prefix).
pub const OWN_ADDRESS_ENDS: usize = 4;

/// The part of `address` that is a fixed prefix of its family, not emphasized: `0x`, the
/// bech32 `bc1q`·`bc1p`·`tb1q`·`tb1p`, Zcash `t1`·`t3`·`tm`·`t2`; none for base58.
fn own_address_prefix(address: &str, kind: AddressKind) -> usize {
    let starts = |prefix: &str| {
        address
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    };
    match kind {
        AddressKind::Evm if starts("0x") => 2,
        AddressKind::Bitcoin if ["bc1q", "bc1p", "tb1q", "tb1p"].into_iter().any(starts) => 4,
        AddressKind::Zcash if ["t1", "t3", "tm", "t2"].into_iter().any(starts) => 2,
        _ => 0,
    }
}

/// How every address is drawn (the account cards since 2026-11-11, spec/04 §2.6; every screen
/// and approval window since 2026-11-12, §3.3 and [`address_spans`]): the whole address without
/// spaces (case kept), the [`OWN_ADDRESS_ENDS`] characters after the family's prefix and the
/// last [`OWN_ADDRESS_ENDS`] emphasized: `(text, emphasized)` spans. With `short`, the middle is replaced by `…` (`0x0Bd7…AD73`; no screen uses it
/// since the copy lines of 2026-11-11 show every address whole).
/// An address too short to have a middle is one plain span.
#[must_use]
pub fn own_address_spans(address: &str, kind: AddressKind, short: bool) -> Vec<(String, bool)> {
    let prefix = own_address_prefix(address, kind);
    let ends = OWN_ADDRESS_ENDS;
    let chars: Vec<char> = address.chars().collect();
    let total = chars.len();
    if !address.is_ascii()
        || total
            < prefix
                .saturating_add(ends.saturating_mul(2))
                .saturating_add(1)
    {
        return vec![(address.to_owned(), false)];
    }
    let piece =
        |from: usize, to: usize| -> String { address.get(from..to).unwrap_or("").to_owned() };
    let head_end = prefix.saturating_add(ends);
    let tail_start = total.saturating_sub(ends);
    let mut spans = Vec::with_capacity(5);
    if prefix > 0 {
        spans.push((piece(0, prefix), false));
    }
    spans.push((piece(prefix, head_end), true));
    spans.push((
        if short {
            "…".to_owned()
        } else {
            piece(head_end, tail_start)
        },
        false,
    ));
    spans.push((piece(tail_start, total), true));
    spans
}

/// Draws `(text, emphasized)` spans on one line from `rect`'s left edge: emphasized spans in
/// bold mono and `strong`, the rest in regular mono and `color`. Returns `false` (nothing
/// drawn) when the line is wider than `rect.w`.
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

#[cfg(test)]
mod tests {
    use super::{
        AddressKind, address_spans, address_with_notes, direction_particle, object_particle,
        own_address_spans, whole_address,
    };

    /// `(joined text, emphasized pieces)` of an own-address line.
    fn own(address: &str, kind: AddressKind, short: bool) -> (String, Vec<String>) {
        let spans = own_address_spans(address, kind, short);
        (
            spans.iter().map(|(text, _)| text.as_str()).collect(),
            spans
                .into_iter()
                .filter(|(_, strong)| *strong)
                .map(|(text, _)| text)
                .collect(),
        )
    }

    #[test]
    fn own_evm_address_emphasizes_four_after_0x_and_the_last_four() {
        let address = "0xF9900bb6FF2D2C67858c3468d21c5f103C4Ff646";
        let (joined, strong) = own(address, AddressKind::Evm, false);
        assert_eq!(joined, address, "no spaces, case kept");
        assert_eq!(strong, ["F990", "f646"]);
        let (short, strong) = own(
            "0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73",
            AddressKind::Evm,
            true,
        );
        assert_eq!(short, "0x0Bd7…AD73");
        assert_eq!(strong, ["0Bd7", "AD73"]);
    }

    #[test]
    fn own_solana_address_emphasizes_its_first_and_last_four() {
        let address = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
        let (joined, strong) = own(address, AddressKind::Solana, false);
        assert_eq!(joined, address);
        assert_eq!(strong, ["HAgk", "Kpqk"]);
    }

    #[test]
    fn own_bitcoin_address_skips_the_bech32_prefix_only() {
        for (address, first) in [
            ("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "cr8t"),
            (
                "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
                "5d7r",
            ),
            ("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "w508"),
        ] {
            let (joined, strong) = own(address, AddressKind::Bitcoin, false);
            assert_eq!(joined, address);
            assert_eq!(strong.first().map(String::as_str), Some(first), "{address}");
            assert_eq!(strong.get(1).map(String::len), Some(4));
        }
        // Base58 (legacy, nested segwit): no prefix.
        let (_, strong) = own(
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            AddressKind::Bitcoin,
            false,
        );
        assert_eq!(strong, ["1BvB", "NVN2"]);
        let (_, strong) = own(
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
            AddressKind::Bitcoin,
            false,
        );
        assert_eq!(strong, ["3J98", "WNLy"]);
    }

    #[test]
    fn own_zcash_address_skips_the_two_character_prefix() {
        let (joined, strong) = own(
            "t1Rv4exT7bqhZqi2j7xz8bUHDMxwosrjADU",
            AddressKind::Zcash,
            false,
        );
        assert_eq!(joined, "t1Rv4exT7bqhZqi2j7xz8bUHDMxwosrjADU");
        assert_eq!(strong, ["Rv4e", "jADU"]);
        let (_, strong) = own(
            "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd",
            AddressKind::Zcash,
            false,
        );
        assert_eq!(strong, ["Vz22", "9ojd"]);
        // Too short to have a middle: one plain span.
        assert_eq!(
            own_address_spans("t1abc", AddressKind::Zcash, false),
            [("t1abc".to_owned(), false)]
        );
    }

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
    fn address_lines_are_drawn_whole_with_their_ends_emphasized() {
        let strong = |text: &str| -> Option<(String, Vec<String>)> {
            address_spans(text).map(|spans| {
                (
                    spans.iter().map(|(piece, _)| piece.as_str()).collect(),
                    spans
                        .into_iter()
                        .filter(|(_, strong)| *strong)
                        .map(|(piece, _)| piece)
                        .collect(),
                )
            })
        };
        let evm = "0xF9900bb6FF2D2C67858c3468d21c5f103C4Ff646";
        for text in [evm, "0xF990 0bb6 FF2D 2C67 858c 3468 d21c 5f10 3C4F f646"] {
            assert_eq!(
                strong(text),
                Some((evm.to_owned(), vec!["F990".to_owned(), "f646".to_owned()])),
                "{text}"
            );
        }
        let sol = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
        for text in [
            sol,
            "HAgk 14Jp MQLg t6rV gv7c BQFJ WFto 5Dqx i472 uT3D Kpqk",
        ] {
            assert_eq!(
                whole_address(text),
                Some((sol.to_owned(), AddressKind::Solana))
            );
        }
        for (text, kind) in [
            (
                "tb1q w508 d6qe jxtd g4y5 r3za rvar y0c5 xw7k xpjz sx",
                AddressKind::Bitcoin,
            ),
            ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", AddressKind::Bitcoin),
            (
                "t1Kg n7v5 a2rK kxC2 4LoX NyHR n4q4 Gs3K EEF",
                AddressKind::Zcash,
            ),
        ] {
            assert_eq!(
                whole_address(text).map(|(_, kind)| kind),
                Some(kind),
                "{text}"
            );
        }
        // Other groupings, altered addresses and other text keep their look.
        for text in [
            "HAgk 14Jp MQLg t6rV gv7c BQFJ WFto 5Dqx i472 uT3D Kpq0",
            "HAg k14J pMQL gt6r Vgv7 cBQF JWFt o5Dq xi47 2uT3 DKpq k",
            "HAgk  14Jp MQLg t6rV gv7c BQFJ WFto 5Dqx i472 uT3D Kpqk",
            "0x F990 0bb6 FF2D 2C67 858c 3468 d21c 5f10 3C4F f646",
            "0xF9900bb6FF2D2C67858c3468d21c5f103C4Ff64",
            "0x98 58Ef FD23",
            "새 계정(아직 없음)",
            "m/44'/60'/0'/0/0",
            "",
        ] {
            assert!(address_spans(text).is_none(), "{text}");
        }
        // An address with its notes (2026-11-14): the address part and the notes.
        let grouped = "0xF990 0bb6 FF2D 2C67 858c 3468 d21c 5f10 3C4F f646";
        assert_eq!(
            address_with_notes(&format!("{grouped} [일반 계정(EOA)] [주소록: A]")),
            Some((grouped, "[일반 계정(EOA)] [주소록: A]"))
        );
        assert_eq!(
            address_with_notes(&format!("{evm} [컨트랙트]")),
            Some((evm, "[컨트랙트]"))
        );
        for text in [
            grouped,
            "0xF990 0bb6 FF2D [일반 계정(EOA)]",
            "새 계정 [일반 계정(EOA)]",
            "",
        ] {
            assert!(address_with_notes(text).is_none(), "{text}");
        }
    }
}
