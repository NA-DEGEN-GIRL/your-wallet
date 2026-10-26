//! A custom-drawn secret text field (D11, spec/01 §7.7): input comes only from `WM_CHAR` units,
//! the bytes live in a fixed-capacity [`WipeBuf`], and painting uses a short-lived wiping UTF-16
//! copy. Ported from `SecureAsciiBuffer` in
//! `archive/spec-v2.4:crates/secret-input-ui/src/recovery_native.rs:118-178` with per-policy
//! character sets.

use super::paint::{Color, DrawFlags, PaintDc, Rect};
use crate::mem::WipeBuf;

const MASK: u16 = 0x25CF;
const FOCUS: Color = Color(0x000F_6CBD);
const BORDER: Color = Color(0x00C8_C8C8);
const TEXT: Color = Color(0x001F_1F1F);

/// Accepted characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CharPolicy {
    /// 0x20–0x7E: passwords and passphrases.
    PrintableAscii,
    /// `a`–`z` and space: mnemonic text.
    LowerWords,
    /// `0-9a-fA-F`, with an optional leading `0x`: private keys.
    Hex,
}

/// Result of one `WM_CHAR` unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CharResult {
    /// Appended.
    Accepted,
    /// Outside the policy, non-ASCII, a surrogate, or the field is full; buffer unchanged.
    Rejected,
    /// 0x08: the last byte was wiped.
    Backspace,
    /// 0x0D.
    Submit,
    /// Other control units (ignored).
    Ignored,
}

/// A fixed-capacity secret field.
#[derive(Debug)]
pub struct SecureTextField {
    buf: WipeBuf<u8>,
    policy: CharPolicy,
    masked: bool,
}

impl SecureTextField {
    /// An empty field holding at most `max_len` bytes.
    #[must_use]
    pub fn new(policy: CharPolicy, max_len: usize) -> Self {
        Self {
            buf: WipeBuf::with_capacity(max_len),
            policy,
            masked: matches!(policy, CharPolicy::PrintableAscii),
        }
    }

    fn accepts(&self, byte: u8) -> bool {
        match self.policy {
            CharPolicy::PrintableAscii => (0x20..=0x7E).contains(&byte),
            CharPolicy::LowerWords => byte.is_ascii_lowercase() || byte == b' ',
            CharPolicy::Hex => {
                byte.is_ascii_hexdigit() || (byte == b'x' && self.buf.as_slice() == b"0")
            }
        }
    }

    /// Applies one `WM_CHAR` UTF-16 unit.
    pub fn on_char(&mut self, unit: u16) -> CharResult {
        match unit {
            0x08 => {
                if self.buf.pop().is_some() {
                    CharResult::Backspace
                } else {
                    CharResult::Ignored
                }
            }
            0x0D => CharResult::Submit,
            0x00..=0x1F | 0x7F => CharResult::Ignored,
            _ => {
                let Ok(byte) = u8::try_from(unit) else {
                    return CharResult::Rejected;
                };
                if !byte.is_ascii() || !self.accepts(byte) || self.buf.push(byte).is_err() {
                    return CharResult::Rejected;
                }
                CharResult::Accepted
            }
        }
    }

    /// Number of bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the field is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Wipes the contents.
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    /// Draws `●` × len instead of the text when on.
    pub fn set_masked(&mut self, on: bool) {
        self.masked = on;
    }

    /// Paints the field frame and its (masked) contents into `rect`.
    pub fn paint(&self, dc: &mut PaintDc<'_>, rect: Rect, focused: bool) {
        dc.frame_rect(rect, if focused { FOCUS } else { BORDER });
        let mut units = WipeBuf::<u16>::with_capacity(self.buf.len());
        for byte in self.buf.as_slice() {
            let _ = units.push(if self.masked { MASK } else { u16::from(*byte) });
        }
        dc.set_text_color(TEXT);
        dc.draw_text(units.as_slice(), rect.inset(4), DrawFlags::LINE);
    }

    /// Lends the bytes to `f` (the yw-win → yw-core boundary, spec/01 §5.3).
    pub fn with_secret<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(self.buf.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::{CharPolicy, CharResult, SecureTextField};

    #[test]
    fn printable_policy_rejects_controls_non_ascii_and_surrogates() {
        let mut field = SecureTextField::new(CharPolicy::PrintableAscii, 4);
        assert_eq!(field.on_char(u16::from(b'a')), CharResult::Accepted);
        assert_eq!(field.on_char(0x1F), CharResult::Ignored);
        assert_eq!(field.on_char(0x7F), CharResult::Ignored);
        assert_eq!(field.on_char(0xAC00), CharResult::Rejected);
        assert_eq!(field.on_char(0xD83D), CharResult::Rejected);
        assert_eq!(field.on_char(0xE9), CharResult::Rejected);
        field.with_secret(|bytes| assert_eq!(bytes, b"a"));
    }

    #[test]
    fn capacity_backspace_and_submit() {
        let mut field = SecureTextField::new(CharPolicy::LowerWords, 2);
        assert_eq!(field.on_char(u16::from(b'a')), CharResult::Accepted);
        assert_eq!(field.on_char(u16::from(b' ')), CharResult::Accepted);
        assert_eq!(field.on_char(u16::from(b'b')), CharResult::Rejected);
        assert_eq!(field.on_char(u16::from(b'A')), CharResult::Rejected);
        assert_eq!(field.on_char(0x08), CharResult::Backspace);
        assert_eq!(field.len(), 1);
        assert_eq!(field.on_char(0x0D), CharResult::Submit);
        field.clear();
        assert!(field.is_empty());
        assert_eq!(field.on_char(0x08), CharResult::Ignored);
    }

    #[test]
    fn hex_policy_allows_only_leading_0x() {
        let mut field = SecureTextField::new(CharPolicy::Hex, 66);
        assert_eq!(field.on_char(u16::from(b'x')), CharResult::Rejected);
        assert_eq!(field.on_char(u16::from(b'0')), CharResult::Accepted);
        assert_eq!(field.on_char(u16::from(b'x')), CharResult::Accepted);
        assert_eq!(field.on_char(u16::from(b'x')), CharResult::Rejected);
        assert_eq!(field.on_char(u16::from(b'F')), CharResult::Accepted);
        assert_eq!(field.on_char(u16::from(b'g')), CharResult::Rejected);
        field.with_secret(|bytes| assert_eq!(bytes, b"0xF"));
    }
}
