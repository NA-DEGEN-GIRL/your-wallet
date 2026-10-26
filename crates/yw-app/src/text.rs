//! Shared text rules: `Label` (spec/02 §5.3 plus the display-character rules of spec/04 §3.3,
//! E-INP-017), simple identifier patterns, and small JSON builders for yw-json.

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

#[cfg(test)]
mod tests {
    use super::{is_dns_label, is_symbol, is_token_text, is_valid_label, parse_hash32};

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
}
