//! Risk levels, warnings and the display-character rules shared by every chain (spec/03 §9.2,
//! §10.1, §11.2; spec/04 §3.3).
//!
//! The forbidden-character list is `is_forbidden_display_character` of
//! `archive/spec-v2.4:crates/approval-wire/src/lib.rs:1277-1300`, and the empty/whitespace rule is
//! its `validate_text` (`:1266-1275`), except that LF is allowed inside values.

use core::fmt::Write as _;

/// Risk level of a warning or a whole request (spec/03 §10.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum RiskLevel {
    /// 정보: click or Enter.
    Info = 0,
    /// 주의: as Info, shown in yellow.
    Caution = 1,
    /// 고위험: one acknowledgement checkbox + 2 s hold (D16).
    High = 2,
    /// 차단: approve disabled, reject only.
    Blocked = 3,
}

impl RiskLevel {
    /// The `u8` code used in display bytes.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// A rule identifier: high byte = rule family letter (`E`, `T`, `P`, `S`, later `L`, `B`), low
/// byte = number (spec/03 §10.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleId(pub u16);

impl RuleId {
    /// Builds `<family><number>`, e.g. `RuleId::new(b'E', 1)` = E01.
    #[must_use]
    pub const fn new(family: u8, number: u8) -> Self {
        Self(u16::from_be_bytes([family, number]))
    }

    /// Family letter.
    #[must_use]
    pub const fn family(self) -> u8 {
        self.0.to_be_bytes()[0]
    }

    /// Rule number within the family.
    #[must_use]
    pub const fn number(self) -> u8 {
        self.0.to_be_bytes()[1]
    }

    /// `"E01"`-style label.
    #[must_use]
    pub fn label(self) -> String {
        format!("{}{:02}", char::from(self.family()), self.number())
    }
}

/// One warning in the approval display. There is no per-warning acknowledgement (D16).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    /// Rule.
    pub rule: RuleId,
    /// Level.
    pub level: RiskLevel,
    /// Fixed text, optionally followed by LF and a cause line.
    pub text: String,
}

/// Whether `character` must never be rendered as-is (controls and invisible/bidi characters).
#[must_use]
pub fn is_forbidden_display_char(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00AD}'
                | '\u{034F}'
                | '\u{061C}'
                | '\u{115F}'
                | '\u{1160}'
                | '\u{17B4}'..='\u{17B5}'
                | '\u{180B}'..='\u{180F}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{3164}'
                | '\u{FE00}'..='\u{FE0F}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0000}'..='\u{E0FFF}'
        )
}

fn push_escape(out: &mut String, character: char) {
    let _ = write!(out, "[U+{:04X}]", u32::from(character));
}

/// Result of escaping untrusted text (spec/03 §9.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Escaped {
    /// Text with every forbidden character replaced by `[U+XXXX]` (LF kept).
    pub text: String,
    /// A character other than TAB or CR was replaced (P02/T17).
    pub hidden: bool,
}

/// Escapes untrusted text: LF stays, TAB, CR, other controls and forbidden display characters
/// become `[U+XXXX]` (uppercase, 4–6 digits).
#[must_use]
pub fn escape_untrusted(text: &str) -> Escaped {
    let mut out = String::with_capacity(text.len());
    let mut hidden = false;
    for character in text.chars() {
        if character == '\n' {
            out.push('\n');
        } else if is_forbidden_display_char(character) {
            if character != '\t' && character != '\r' {
                hidden = true;
            }
            push_escape(&mut out, character);
        } else {
            out.push(character);
        }
    }
    Escaped { text: out, hidden }
}

/// Escapes leading and trailing whitespace so a display value satisfies the "no surrounding
/// whitespace" rule without hiding the characters (spec/03 §11.2).
#[must_use]
pub fn escape_edges(text: &str) -> String {
    let characters: Vec<char> = text.chars().collect();
    let first = characters
        .iter()
        .position(|character| !character.is_whitespace());
    let last = characters
        .iter()
        .rposition(|character| !character.is_whitespace());
    let mut out = String::with_capacity(text.len());
    for (index, character) in characters.iter().enumerate() {
        let inside = match (first, last) {
            (Some(first), Some(last)) => index >= first && index <= last,
            _ => false,
        };
        if inside {
            out.push(*character);
        } else {
            push_escape(&mut out, *character);
        }
    }
    out
}

/// Whether `text` is a valid display string: no forbidden character except LF inside, no
/// surrounding whitespace, at most `max_bytes`. `allow_empty` permits `""`.
#[must_use]
pub fn is_valid_display_text(text: &str, max_bytes: usize, allow_empty: bool) -> bool {
    (allow_empty || !text.is_empty())
        && text.len() <= max_bytes
        && text.trim() == text
        && !text
            .chars()
            .any(|character| character != '\n' && is_forbidden_display_char(character))
}

#[cfg(test)]
mod tests {
    use super::{RiskLevel, RuleId, escape_edges, escape_untrusted, is_valid_display_text};

    #[test]
    fn escape_rules() {
        let escaped = escape_untrusted("a\nb\tc\rd\u{202E}e\u{200B}f\u{FEFF}\u{E0001}");
        assert_eq!(
            escaped.text,
            "a\nb[U+0009]c[U+000D]d[U+202E]e[U+200B]f[U+FEFF][U+E0001]"
        );
        assert!(escaped.hidden);
        let tabs = escape_untrusted("x\ty\r");
        assert_eq!(tabs.text, "x[U+0009]y[U+000D]");
        assert!(!tabs.hidden);
        assert_eq!(escape_untrusted("평문 ok").text, "평문 ok");
        assert!(is_valid_display_text(&escaped.text, 1_000, false));
    }

    #[test]
    fn edges_and_validation() {
        assert_eq!(escape_edges(" a b\n"), "[U+0020]a b[U+000A]");
        assert_eq!(escape_edges("  "), "[U+0020][U+0020]");
        assert_eq!(escape_edges("ab"), "ab");
        assert!(!is_valid_display_text(" a", 10, false));
        assert!(!is_valid_display_text("a\u{202E}", 10, false));
        assert!(!is_valid_display_text("", 10, false));
        assert!(is_valid_display_text("", 10, true));
        assert!(is_valid_display_text("a\nb", 10, false));
        assert!(!is_valid_display_text("abc", 2, false));
    }

    #[test]
    fn rule_ids_and_levels() {
        assert_eq!(RuleId::new(b'E', 1), RuleId(0x4501));
        assert_eq!(RuleId::new(b'T', 16).label(), "T16");
        assert!(RiskLevel::Blocked > RiskLevel::High);
        assert_eq!(RiskLevel::High.code(), 2);
    }
}
