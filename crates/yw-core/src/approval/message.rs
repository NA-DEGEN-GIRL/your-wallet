//! Shared message-body display of the Solana and Bitcoin dApp message approvals (spec/07 §19.3,
//! spec/08 §17.4): readable strict UTF-8 is shown as escaped text (P02 when a hidden or bidi
//! character was escaped), anything else as hex lines (P01, or P04 for 32 bytes / C0 controls),
//! then the byte count. The rules and texts are those of `personal_sign` (spec/03 §9.2).

use super::display::{DisplayError, DisplayField, FieldKey, MAX_DISPLAY_VALUE_BYTES};
use super::text::{Warning, escape_edges, escape_untrusted};
use crate::evm::eip191::{HexReason, hex_reason};
use crate::evm::risk::{self, P01, P02, P04};

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
fn message_value(escaped_text: &str) -> String {
    let value = escape_edges(escaped_text);
    if value.is_empty() {
        "(빈 메시지)".to_owned()
    } else {
        value.replace('\n', "[U+000A]\n")
    }
}

/// An untrusted single-line value (labels, SIWS fields): LF shown as `[U+000A]`, edges escaped.
#[must_use]
pub(crate) fn inline_value(text: &str) -> String {
    let escaped = escape_untrusted(text).text.replace('\n', "[U+000A]");
    let value = escape_edges(&escaped);
    if value.is_empty() {
        "(빈 값)".to_owned()
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

/// Pushes `MESSAGE_TEXT` or `MESSAGE_HEX`, then `MESSAGE_BYTES`, and the matching warnings.
///
/// # Errors
///
/// [`DisplayError`] (defensive).
pub(crate) fn push_message_body(
    fields: &mut Vec<DisplayField>,
    warnings: &mut Vec<Warning>,
    bytes: &[u8],
) -> Result<(), DisplayError> {
    let text = readable_text(bytes).map(escape_untrusted);
    let value = text
        .as_ref()
        .map(|escaped| message_value(&escaped.text))
        .filter(|value| value.len() <= MAX_DISPLAY_VALUE_BYTES);
    if let (Some(value), Some(escaped)) = (value, &text) {
        fields.push(DisplayField::new(FieldKey::MESSAGE_TEXT, "", value)?);
        if escaped.hidden {
            warnings.push(risk::warning(P02, None));
        }
    } else {
        fields.push(DisplayField::new(
            FieldKey::MESSAGE_HEX,
            "",
            hex_lines(bytes),
        )?);
        if text.is_some() {
            // Readable but too long once escaped.
            warnings.push(risk::warning(P02, None));
        } else {
            match core::str::from_utf8(bytes).ok().and(hex_reason(bytes)) {
                Some(HexReason::Hash32) => warnings.push(risk::warning(
                    P04,
                    Some("정확히 32바이트입니다 — 해시에 서명하는 것일 수 있습니다"),
                )),
                Some(HexReason::Control) => warnings.push(risk::warning(
                    P04,
                    Some("TAB·줄바꿈 외의 제어 문자가 있습니다"),
                )),
                None => warnings.push(risk::warning(P01, None)),
            }
        }
    }
    fields.push(DisplayField::new(
        FieldKey::MESSAGE_BYTES,
        "",
        format!("{}바이트", bytes.len()),
    )?);
    Ok(())
}
