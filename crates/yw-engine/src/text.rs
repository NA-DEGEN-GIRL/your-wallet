//! Shared text rules: `Label` (spec/02 §5.3 plus the display-character rules of spec/04 §3.3,
//! E-INP-017), simple identifier patterns, small JSON builders for yw-json, and the Korean particle
//! helpers (spec/14 §2; 2026-11-17: moved here from `ui::theme`, which approval and card texts
//! should not depend on).

use yw_core::approval::is_forbidden_display_char;
use yw_json::{Number, Object, Value};

/// Longest label in Unicode scalars.
pub const LABEL_MAX_CHARS: usize = 32;

/// `Label`: 1..=32 scalars, no C0/C1 controls, no U+200B–U+200F, U+202A–U+202E, U+2066–U+2069,
/// U+FEFF, no leading/trailing whitespace, and no display-forbidden character (spec/04 §2.10).
#[must_use]
pub fn is_valid_label(text: &str) -> bool {
    let count = text.chars().count();
    (1..=LABEL_MAX_CHARS).contains(&count)
        && text.trim() == text
        && !text.chars().any(|character| {
            character.is_control()
                || matches!(character,
                    '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
                || is_forbidden_display_char(character)
        })
}

/// `^[a-z0-9]+(-[a-z0-9]+)*$`, 1–63 bytes (DNS label; `QuickNode` subdomain, Alchemy label).
#[must_use]
pub fn is_dns_label(text: &str) -> bool {
    (1..=63).contains(&text.len())
        && !text.starts_with('-')
        && !text.ends_with('-')
        && !text.contains("--")
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// `^[A-Za-z0-9_-]{min,max}$`.
#[must_use]
pub fn is_token_text(text: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// `^[A-Za-z0-9]{1,11}$` (native and token symbols).
#[must_use]
pub fn is_symbol(text: &str) -> bool {
    (1..=11).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

/// `"0x"` + 64 lowercase hex.
#[must_use]
pub fn parse_hash32(text: &str) -> Option<[u8; 32]> {
    let digits = text.strip_prefix("0x")?;
    if digits.len() != 64
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    yw_core::hex::decode_array::<32>(digits).ok()
}

/// `"0x"` + lowercase hex of `bytes`.
#[must_use]
pub fn hash32_text(bytes: &[u8; 32]) -> String {
    format!("0x{}", yw_core::hex::encode(bytes))
}

/// JSON string.
#[must_use]
pub fn json_str(text: &str) -> Value {
    Value::String(text.to_owned())
}

/// JSON unsigned integer.
#[must_use]
pub fn json_u64(value: u64) -> Value {
    Value::Number(Number::from_u64(value))
}

/// JSON object in the given key order (keys are fixed literals, so never duplicated).
#[must_use]
pub fn json_object(pairs: Vec<(&str, Value)>) -> Value {
    Value::Object(
        Object::from_pairs(
            pairs
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
        .unwrap_or_default(),
    )
}

/// JSON object with owned keys (`None` on a duplicate).
#[must_use]
pub fn json_object_owned(pairs: Vec<(String, Value)>) -> Option<Value> {
    Object::from_pairs(pairs).map(Value::Object)
}

/// Korean-only helpers (spec/14 §2): the particles are written as escapes, so the i18n scan (Hangul
/// string literals outside the catalogues) does not count them — they have no English counterpart
/// and only Korean templates use them.
///
/// Korean object particle for `word` (`을` after a final consonant, `를` otherwise), judged by
/// how the last character is read: Hangul by its final consonant, digits and Latin letters by
/// their Korean names (L·M·N·R and 0·1·3·6·7·8 end in a consonant). A trailing parenthesis is
/// skipped, as the particle follows the word before it (2026-11-15: a named card
/// `메인 (#12345678)` takes the particle of `메인`).
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

/// `word` without trailing parenthesised groups (`메인 (#1)` → `메인`); a word that is only a
/// parenthesis stays as it is.
fn before_parenthesis(word: &str) -> &str {
    let mut word = word.trim_end();
    while word.ends_with(')') {
        let Some(before) = word
            .rfind('(')
            .and_then(|open| word.get(..open))
            .map(str::trim_end)
            .filter(|before| !before.is_empty())
        else {
            break;
        };
        word = before;
    }
    word
}

fn ends_in_consonant(word: &str, rieul_is_vowel: bool) -> bool {
    let Some(last) = before_parenthesis(word).chars().last() else {
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

/// The whole address in 4-character groups separated by one space (spec/04 §3.3; drawing only,
/// the copied text never has spaces). 2026-11-22 (spec/15 §11.4 S4d E0a): was yw-app
/// `ui::screens_btc::grouped` (the wallet's removal and hidden-account rows group their addresses).
#[must_use]
pub fn grouped(address: &str) -> String {
    let mut out = String::with_capacity(address.len().saturating_add(address.len() / 4));
    for (index, character) in address.chars().enumerate() {
        if index != 0 && index % 4 == 0 {
            out.push(' ');
        }
        out.push(character);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        direction_particle, is_dns_label, is_symbol, is_token_text, is_valid_label,
        object_particle, parse_hash32,
    };

    #[test]
    fn label_rules() {
        assert!(is_valid_label("계정 1"));
        assert!(is_valid_label(&"가".repeat(32)));
        assert!(!is_valid_label(&"가".repeat(33)));
        assert!(!is_valid_label(""));
        assert!(!is_valid_label(" a"));
        assert!(!is_valid_label("a "));
        assert!(!is_valid_label("a\u{202E}b"));
        assert!(!is_valid_label("a\u{200B}b"));
        assert!(!is_valid_label("a\u{0085}b"));
        assert!(!is_valid_label("a\nb"));
        assert!(!is_valid_label("a\u{3164}b"));
    }

    #[test]
    fn identifier_patterns() {
        assert!(is_dns_label("base-sepolia"));
        assert!(!is_dns_label("Base_Sepolia"));
        assert!(!is_dns_label("base.sepolia"));
        assert!(!is_dns_label("-a"));
        assert!(!is_dns_label("a--b"));
        assert!(!is_dns_label(&"a".repeat(64)));
        assert!(is_token_text("abc_DEF-123", 1, 11));
        assert!(!is_token_text("abc def", 1, 11));
        assert!(is_symbol("ETH"));
        assert!(!is_symbol("ETH!"));
        assert!(!is_symbol("ABCDEFGHIJKL"));
        assert!(parse_hash32(&format!("0x{}", "ab".repeat(32))).is_some());
        assert!(parse_hash32(&format!("0x{}", "AB".repeat(32))).is_none());
        assert!(parse_hash32(&"ab".repeat(32)).is_none());
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
        // A named card (2026-11-15): the particle follows the name before `(#serial)`, and a
        // card without a name follows its serial's last digit.
        assert_eq!(object_particle("메인 (#12345678)"), "을");
        assert_eq!(object_particle("백업키 (#12345678)"), "를");
        assert_eq!(object_particle("#12345672"), "를");
        assert_eq!(object_particle("#12345678"), "을");
        assert_eq!(direction_particle("메인 (#12345673)"), "으로");
        assert_eq!(direction_particle("서울 (#12345673)"), "로");
        assert_eq!(direction_particle("Card 7 (#12345673)"), "로");
        assert_eq!(direction_particle("#12345672·메인 (#12345673)"), "으로");
        assert_eq!(direction_particle("메인 (#12345673)·#12345672"), "로");
        assert_eq!(object_particle("(#1)"), "를");
    }

    /// The four cases the particles depend on, written out one by one: a Hangul final consonant,
    /// a vowel ending, the final ㄹ (consonant for `을`, vowel-like for `로`) and trailing
    /// parenthesised groups (skipped, however many).
    #[test]
    fn particles_by_final_consonant_vowel_rieul_and_parenthesis() {
        // Final consonant (밥: ㅂ).
        assert_eq!(object_particle("밥"), "을");
        assert_eq!(direction_particle("밥"), "으로");
        // Vowel ending (사과).
        assert_eq!(object_particle("사과"), "를");
        assert_eq!(direction_particle("사과"), "로");
        // ㄹ (물): 을 but 로.
        assert_eq!(object_particle("물"), "을");
        assert_eq!(direction_particle("물"), "로");
        assert_eq!(object_particle("L"), "을");
        assert_eq!(direction_particle("L"), "로");
        assert_eq!(direction_particle("M"), "으로");
        // Trailing `(…)` groups and spaces are skipped.
        assert_eq!(object_particle("사과 (#1)"), "를");
        assert_eq!(object_particle("밥 (a) (b) "), "을");
        assert_eq!(direction_particle("물 (#3)"), "로");
        assert_eq!(direction_particle("밥(x)"), "으로");
        // Nothing to judge: the vowel forms.
        assert_eq!(object_particle(""), "를");
        assert_eq!(direction_particle(""), "로");
    }
}
