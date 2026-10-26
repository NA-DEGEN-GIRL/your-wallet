//! Deterministic writer: no whitespace, object members in insertion order, minimal escapes.

use crate::value::Value;

/// Serializes `value` without whitespace. Objects keep insertion order and strings use the
/// RFC 8259 minimal escapes (`"`, `\`, and control characters below U+0020).
#[must_use]
pub fn to_vec(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut Vec<u8>, value: &Value) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => out.extend_from_slice(number.as_str().as_bytes()),
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                write_value(out, item);
            }
            out.push(b']');
        }
        Value::Object(object) => {
            out.push(b'{');
            for (index, (key, item)) in object.iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                write_string(out, key);
                out.push(b':');
                write_value(out, item);
            }
            out.push(b'}');
        }
    }
}

fn write_string(out: &mut Vec<u8>, text: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    for &byte in text.as_bytes() {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x00..=0x1f => {
                out.extend_from_slice(b"\\u00");
                out.push(HEX.get(usize::from(byte >> 4)).copied().unwrap_or(b'0'));
                out.push(HEX.get(usize::from(byte & 0x0f)).copied().unwrap_or(b'0'));
            }
            _ => out.push(byte),
        }
    }
    out.push(b'"');
}
