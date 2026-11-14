//! Shared message-body display of the Solana and Bitcoin dApp message approvals (spec/07 §19.3,
//! spec/08 §17.4): readable strict UTF-8 is shown as escaped text (P02 when a hidden or bidi
//! character was escaped), anything else as hex lines (P01, or P04 for 32 bytes / C0 controls),
//! then the byte count. The rules and texts are those of `personal_sign` (spec/03 §9.2). Every
//! fixed text is in the request's language (spec/14).

use super::display::{DisplayError, DisplayField, FieldKey, MAX_DISPLAY_VALUE_BYTES};
use super::text::{Warning, escape_edges, escape_untrusted};
use crate::evm::eip191::{HexReason, hex_reason};
use crate::evm::risk::{self, P01, P02, P04};
use crate::lang::Lang;

/// The fixed texts of the shared message display (Korean and English, spec/14).
pub mod text {
    crate::texts! {
        /// The value of an empty message.
        EMPTY_MESSAGE = "(빈 메시지)" / "(empty message)";
        /// The value of an empty single-line field.
        EMPTY_VALUE = "(빈 값)" / "(empty value)";
        /// P04 cause: 32 bytes.
        HASH32 = "정확히 32바이트입니다 — 해시에 서명하는 것일 수 있습니다"
            / "Exactly 32 bytes — this may be signing a hash";
        /// P04 cause: C0 controls.
        CONTROL = "TAB·줄바꿈 외의 제어 문자가 있습니다"
            / "Contains control characters other than TAB·line break";
        /// `MESSAGE_BYTES` value.
        BYTES(1) = "{0}바이트" / "{0} bytes";
    }
}

/// Hex in 32-byte lines (`0x` on the first).
#[must_use]
pub(crate) fn hex_lines(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "0x".to_owned();
    }
    let lines: Vec<String> = bytes.chunks(32).map(crate::hex::encode).collect();
    format!("0x{}", lines.join("\n"))
}

/// A multi-line message value: edges escaped, every inner LF marked `[U+000A]` before the break.
fn message_value(lang: Lang, escaped_text: &str) -> String {
    let value = escape_edges(escaped_text);
    if value.is_empty() {
        text::EMPTY_MESSAGE.get(lang).to_owned()
    } else {
        value.replace('\n', "[U+000A]\n")
    }
}

/// An untrusted single-line value (labels, SIWS fields): LF shown as `[U+000A]`, edges escaped;
/// an empty value is shown as "(빈 값)" in `lang`.
#[must_use]
pub(crate) fn inline_value(lang: Lang, text: &str) -> String {
    let escaped = escape_untrusted(text).text.replace('\n', "[U+000A]");
    let value = escape_edges(&escaped);
    if value.is_empty() {
        self::text::EMPTY_VALUE.get(lang).to_owned()
    } else {
        value
    }
}

/// Whether the bytes are shown as text (strict UTF-8 without the P04 reasons).
#[must_use]
pub(crate) fn readable_text(bytes: &[u8]) -> Option<&str> {
    let text = core::str::from_utf8(bytes).ok()?;
    hex_reason(bytes).is_none().then_some(text)
}

/// Pushes `MESSAGE_TEXT` or `MESSAGE_HEX`, then `MESSAGE_BYTES`, and the matching warnings, in
/// `lang`.
///
/// # Errors
///
/// [`DisplayError`] (defensive).
pub(crate) fn push_message_body(
    lang: Lang,
    fields: &mut Vec<DisplayField>,
    warnings: &mut Vec<Warning>,
    bytes: &[u8],
) -> Result<(), DisplayError> {
    let readable = readable_text(bytes).map(escape_untrusted);
    let value = readable
        .as_ref()
        .map(|escaped| message_value(lang, &escaped.text))
        .filter(|value| value.len() <= MAX_DISPLAY_VALUE_BYTES);
    if let (Some(value), Some(escaped)) = (value, &readable) {
        fields.push(DisplayField::new(FieldKey::MESSAGE_TEXT, "", value)?);
        if escaped.hidden {
            warnings.push(risk::warning(lang, P02, None));
        }
    } else {
        fields.push(DisplayField::new(
            FieldKey::MESSAGE_HEX,
            "",
            hex_lines(bytes),
        )?);
        if readable.is_some() {
            // Readable but too long once escaped.
            warnings.push(risk::warning(lang, P02, None));
        } else {
            match core::str::from_utf8(bytes).ok().and(hex_reason(bytes)) {
                Some(HexReason::Hash32) => {
                    warnings.push(risk::warning(lang, P04, Some(text::HASH32.get(lang))));
                }
                Some(HexReason::Control) => {
                    warnings.push(risk::warning(lang, P04, Some(text::CONTROL.get(lang))));
                }
                None => warnings.push(risk::warning(lang, P01, None)),
            }
        }
    }
    fields.push(DisplayField::new(
        FieldKey::MESSAGE_BYTES,
        "",
        text::BYTES.fill(lang, [&bytes.len().to_string()]),
    )?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{inline_value, push_message_body, text};
    use crate::approval::{MAX_DISPLAY_VALUE_BYTES, is_valid_display_text};
    use crate::lang::{Lang, has_hangul, placeholders};

    #[test]
    fn catalogue_entries_are_well_formed() {
        for entry in text::ALL {
            let expected: Vec<usize> = (0..entry.args).collect();
            for template in [entry.ko, entry.en] {
                let mut found = placeholders(template);
                found.sort_unstable();
                assert_eq!(found, expected, "{}", entry.name);
            }
            assert!(!has_hangul(entry.en), "{}", entry.name);
            assert!(
                is_valid_display_text(entry.en, MAX_DISPLAY_VALUE_BYTES, true),
                "{}",
                entry.name
            );
        }
    }

    #[test]
    fn english_message_body_has_no_hangul() {
        for bytes in [
            b"hello\nworld".as_slice(),
            b"",
            &[0xab; 32],
            b"a\x01b",
            &[0xff, 0xfe, 0x00],
            "x\u{202E}y".as_bytes(),
        ] {
            let (mut fields, mut warnings) = (Vec::new(), Vec::new());
            push_message_body(Lang::En, &mut fields, &mut warnings, bytes).unwrap();
            for field in &fields {
                assert!(!has_hangul(&field.value), "{:?}", field.value);
            }
            for warning in &warnings {
                assert!(!has_hangul(&warning.text), "{:?}", warning.text);
            }
            let (mut ko_fields, mut ko_warnings) = (Vec::new(), Vec::new());
            push_message_body(Lang::Ko, &mut ko_fields, &mut ko_warnings, bytes).unwrap();
            assert_eq!(ko_fields.len(), fields.len());
            assert_eq!(ko_warnings.len(), warnings.len());
        }
        assert_eq!(inline_value(Lang::En, ""), "(empty value)");
        assert_eq!(inline_value(Lang::Ko, ""), "(빈 값)");
    }
}
