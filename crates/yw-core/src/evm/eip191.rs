//! `personal_sign` (EIP-191 version 0x45) messages (spec/03 §9.1–§9.2, D18).
//!
//! The preimage follows `archive/spec-v2.4:crates/wallet-model/src/operation.rs:398-415`
//! (decimal byte length). `eth_sign` is not supported.

use core::fmt;

use sha3::{Digest, Keccak256};

use super::siwe::{SiweMessage, SiweParse, parse_siwe};
use crate::approval::escape_untrusted;

/// Maximum message bytes (spec/03 §9.1).
pub const MAX_PERSONAL_MESSAGE: usize = 65_536;
const PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n";

/// `personal_sign` parameter failure (-32602).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageError {
    /// More than 65,536 bytes.
    TooLarge,
}

impl fmt::Display for MessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("message too large")
    }
}

impl std::error::Error for MessageError {}

/// `0x19 ‖ "Ethereum Signed Message:\n" ‖ decimal(len) ‖ message`.
#[must_use]
pub fn personal_preimage(message: &[u8]) -> Vec<u8> {
    let length = message.len().to_string();
    let mut preimage = Vec::with_capacity(
        PREFIX
            .len()
            .saturating_add(length.len())
            .saturating_add(message.len()),
    );
    preimage.extend_from_slice(PREFIX);
    preimage.extend_from_slice(length.as_bytes());
    preimage.extend_from_slice(message);
    preimage
}

/// `keccak256(personal_preimage(message))`.
#[must_use]
pub fn personal_digest(message: &[u8]) -> [u8; 32] {
    Keccak256::digest(personal_preimage(message)).into()
}

/// The message bytes of a `personal_sign` parameter: `^0x([0-9a-fA-F]{2})*$` is hex-decoded,
/// anything else is taken as its UTF-8 bytes (spec/03 §9.1).
///
/// # Errors
///
/// [`MessageError::TooLarge`] above 65,536 bytes.
pub fn parse_personal_param(param: &str) -> Result<Vec<u8>, MessageError> {
    let hex = param.strip_prefix("0x").filter(|digits| {
        digits.len() % 2 == 0 && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
    });
    let bytes = match hex {
        Some(digits) => {
            if digits.len() / 2 > MAX_PERSONAL_MESSAGE {
                return Err(MessageError::TooLarge);
            }
            let mut out = vec![0_u8; digits.len() / 2];
            crate::hex::decode_into(digits.as_bytes(), &mut out, true)
                .map_err(|_| MessageError::TooLarge)?;
            out
        }
        None => param.as_bytes().to_vec(),
    };
    if bytes.len() > MAX_PERSONAL_MESSAGE {
        return Err(MessageError::TooLarge);
    }
    Ok(bytes)
}

/// Why a strict UTF-8 message is still shown as hex (P04, spec/03 §9.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HexReason {
    /// Exactly 32 bytes: most likely a hash signed blindly.
    Hash32,
    /// A C0 control (or DEL) other than TAB, LF and CR.
    Control,
}

/// A decoded `personal_sign` message (spec/03 §9.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedPersonalMessage {
    /// Message bytes.
    pub bytes: Vec<u8>,
    /// Escaped text when the bytes are strict UTF-8 and readable (`None` → hex display with P01,
    /// or P04 when `hex_reason` is set).
    pub text: Option<String>,
    /// A hidden or bidi character was escaped (P02).
    pub escaped: bool,
    /// Parsed SIWE message.
    pub siwe: Option<SiweMessage>,
    /// The SIWE marker is present but the grammar failed (S08; S01/S02 still apply).
    pub siwe_marker_only: bool,
    /// Strict UTF-8 shown as hex anyway (P04).
    pub hex_reason: Option<HexReason>,
}

/// The P04 reason of strict UTF-8 message bytes, if any.
#[must_use]
pub fn hex_reason(bytes: &[u8]) -> Option<HexReason> {
    if bytes.len() == 32 {
        Some(HexReason::Hash32)
    } else if bytes
        .iter()
        .any(|byte| (*byte < 0x20 && !matches!(byte, b'\t' | b'\n' | b'\r')) || *byte == 0x7f)
    {
        Some(HexReason::Control)
    } else {
        None
    }
}

/// Decodes message bytes: strict UTF-8 → escaped text and SIWE parsing; otherwise hex. A
/// 32-byte message or one with C0 controls other than TAB/LF/CR is also shown as hex (P04), but
/// its SIWE marker is still detected so the domain checks apply.
#[must_use]
pub fn decode_personal_message(bytes: Vec<u8>) -> DecodedPersonalMessage {
    let Ok(raw) = core::str::from_utf8(&bytes) else {
        return DecodedPersonalMessage {
            bytes,
            text: None,
            escaped: false,
            siwe: None,
            siwe_marker_only: false,
            hex_reason: None,
        };
    };
    let (siwe, siwe_marker_only) = match parse_siwe(raw) {
        SiweParse::NotSiwe => (None, false),
        SiweParse::MarkerOnly => (None, true),
        SiweParse::Message(message) => (Some(*message), false),
    };
    let reason = hex_reason(&bytes);
    let (text, escaped) = if reason.is_some() {
        (None, false)
    } else {
        let escaped = escape_untrusted(raw);
        (Some(escaped.text), escaped.hidden)
    };
    DecodedPersonalMessage {
        text,
        escaped,
        siwe,
        siwe_marker_only,
        hex_reason: reason,
        bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HexReason, MessageError, decode_personal_message, parse_personal_param, personal_preimage,
    };

    // archive/spec-v2.4:crates/wallet-model/src/operation.rs:593-604
    #[test]
    fn prefix_uses_decimal_length() {
        assert!(personal_preimage(&[0; 12]).starts_with(b"\x19Ethereum Signed Message:\n12"));
    }

    #[test]
    fn params() {
        assert_eq!(parse_personal_param("0xff00fe"), Ok(vec![0xff, 0x00, 0xfe]));
        assert_eq!(parse_personal_param("0xFF"), Ok(vec![0xff]));
        assert_eq!(parse_personal_param("0x"), Ok(vec![]));
        assert_eq!(parse_personal_param("0xf"), Ok(b"0xf".to_vec()));
        assert_eq!(parse_personal_param("hello"), Ok(b"hello".to_vec()));
        assert_eq!(
            parse_personal_param(&"a".repeat(65_537)),
            Err(MessageError::TooLarge)
        );
        assert!(parse_personal_param(&format!("0x{}", "00".repeat(65_536))).is_ok());
        assert_eq!(
            parse_personal_param(&format!("0x{}", "00".repeat(65_537))),
            Err(MessageError::TooLarge)
        );
    }

    #[test]
    fn decoding() {
        let hex = decode_personal_message(vec![0xff, 0x00, 0xfe]);
        assert_eq!(hex.text, None);
        let bidi = decode_personal_message("a\u{202E}b".as_bytes().to_vec());
        assert_eq!(bidi.text.as_deref(), Some("a[U+202E]b"));
        assert!(bidi.escaped);
        let plain = decode_personal_message(b"Some data".to_vec());
        assert_eq!(plain.text.as_deref(), Some("Some data"));
        assert!(!plain.escaped && plain.siwe.is_none() && !plain.siwe_marker_only);
        assert_eq!(plain.hex_reason, None);
    }

    #[test]
    fn binary_looking_utf8_is_hex() {
        // Exactly 32 bytes (a hash), even when every byte is printable ASCII.
        let hash = decode_personal_message(b"0123456789abcdef0123456789abcdef".to_vec());
        assert_eq!(hash.text, None);
        assert_eq!(hash.hex_reason, Some(HexReason::Hash32));
        let short = decode_personal_message(b"0123456789abcdef0123456789abcde".to_vec());
        assert_eq!(short.hex_reason, None);
        // C0 controls other than TAB/LF/CR, and DEL.
        for byte in [0x00_u8, 0x01, 0x08, 0x0b, 0x0c, 0x1b, 0x1f, 0x7f] {
            let message = decode_personal_message(vec![b'h', b'i', byte, b'!']);
            assert_eq!(message.text, None, "{byte:#x}");
            assert_eq!(message.hex_reason, Some(HexReason::Control), "{byte:#x}");
        }
        for byte in [b'\t', b'\n', b'\r'] {
            let message = decode_personal_message(vec![b'h', b'i', byte, b'!']);
            assert!(message.text.is_some(), "{byte:#x}");
            assert_eq!(message.hex_reason, None);
        }
        // The SIWE marker is still detected for the domain checks.
        let siwe = decode_personal_message(
            b"evil.example wants you to sign in with your Ethereum account:\n\x01".to_vec(),
        );
        assert_eq!(siwe.hex_reason, Some(HexReason::Control));
        assert!(siwe.siwe_marker_only);
    }
}
