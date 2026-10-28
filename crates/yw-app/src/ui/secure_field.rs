//! Secret input buffers (spec/04 §4.2, §4.7, D11), ported from `SecureAsciiBuffer` of
//! `archive/spec-v2.4:crates/secret-input-ui/src/recovery_native.rs:118-178` and widened to the
//! five character sets. Input comes only from `WM_CHAR` units; the bytes live in a fixed
//! zeroed buffer of exactly `limit` bytes (no reallocation); removed bytes are overwritten with 0;
//! painting uses a short-lived zeroizing UTF-16 copy.

use yw_core::secret::{Zeroize, Zeroizing};

use crate::errors::ErrorCode;

/// Character set of a field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charset {
    /// 0x20–0x7E (passwords, passphrases).
    Printable,
    /// `a`–`z` and single spaces (mnemonic; `A`–`Z` lowercased).
    MnemonicText,
    /// `0`–`9`, `a`–`f` (`A`–`F` lowercased), `x` only as `0x` prefix.
    PrivateKeyHex,
    /// `a`–`z` (`A`–`Z` lowercased): backup words.
    BackupWord,
    /// `0-9a-fA-F` as typed: address suffix.
    HexSuffix,
    /// The base58 alphabet (Bitcoin WIF).
    Base58,
    /// ASCII letters, digits, `[`, `]`, `,` and single spaces: a Solana base58 keypair or a
    /// `solana-keygen` JSON array (the core parser decides).
    KeyText,
}

/// Why a unit was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// ≥ 0x80 (including surrogates): E-INP-008.
    NonAscii,
    /// Outside the set.
    NotAllowed,
    /// Leading or repeated space in mnemonic text (silently ignored).
    DoubleSpace,
    /// `x` not in the `0x` position.
    Position,
}

/// Result of one unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushResult {
    /// Stored.
    Accepted,
    /// At the limit.
    Full,
    /// Not stored.
    Rejected(RejectReason),
}

/// The field cannot be created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldError;

/// A fixed-capacity secret field.
pub struct SecretField {
    bytes: Zeroizing<Vec<u8>>,
    len: usize,
    charset: Charset,
}

impl core::fmt::Debug for SecretField {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "SecretField({:?}, len={}, [REDACTED])",
            self.charset, self.len
        )
    }
}

impl SecretField {
    /// An empty field of exactly `limit` bytes.
    ///
    /// # Errors
    ///
    /// [`FieldError`] for `limit == 0` or if the storage cannot be exactly `limit` bytes.
    pub fn new(charset: Charset, limit: usize) -> Result<Self, FieldError> {
        if limit == 0 {
            return Err(FieldError);
        }
        let bytes = Zeroizing::new(vec![0_u8; limit]);
        if bytes.len() != limit {
            return Err(FieldError);
        }
        Ok(Self {
            bytes,
            len: 0,
            charset,
        })
    }

    /// The character set.
    #[must_use]
    pub const fn charset(&self) -> Charset {
        self.charset
    }

    /// Stored length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Capacity (`limit`).
    #[must_use]
    pub fn limit(&self) -> usize {
        self.bytes.len()
    }

    /// The stored bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }

    fn last(&self) -> Option<u8> {
        self.len
            .checked_sub(1)
            .and_then(|index| self.bytes.get(index).copied())
    }

    fn convert(&self, unit: u16) -> Result<u8, RejectReason> {
        let byte = u8::try_from(unit).map_err(|_| RejectReason::NonAscii)?;
        if !byte.is_ascii() {
            return Err(RejectReason::NonAscii);
        }
        match self.charset {
            Charset::Printable => (0x20..=0x7E)
                .contains(&byte)
                .then_some(byte)
                .ok_or(RejectReason::NotAllowed),
            Charset::MnemonicText => match byte {
                b' ' if self.len == 0 || self.last() == Some(b' ') => {
                    Err(RejectReason::DoubleSpace)
                }
                b' ' | b'a'..=b'z' => Ok(byte),
                b'A'..=b'Z' => Ok(byte.to_ascii_lowercase()),
                _ => Err(RejectReason::NotAllowed),
            },
            Charset::PrivateKeyHex => match byte {
                b'0'..=b'9' | b'a'..=b'f' => Ok(byte),
                b'A'..=b'F' => Ok(byte.to_ascii_lowercase()),
                b'x' if self.len == 1 && self.as_bytes() == b"0" => Ok(byte),
                b'x' => Err(RejectReason::Position),
                _ => Err(RejectReason::NotAllowed),
            },
            Charset::BackupWord => match byte {
                b'a'..=b'z' => Ok(byte),
                b'A'..=b'Z' => Ok(byte.to_ascii_lowercase()),
                _ => Err(RejectReason::NotAllowed),
            },
            Charset::HexSuffix => byte
                .is_ascii_hexdigit()
                .then_some(byte)
                .ok_or(RejectReason::NotAllowed),
            Charset::Base58 => is_base58(byte)
                .then_some(byte)
                .ok_or(RejectReason::NotAllowed),
            Charset::KeyText => match byte {
                b' ' if self.len == 0 || self.last() == Some(b' ') => {
                    Err(RejectReason::DoubleSpace)
                }
                b' ' | b'[' | b']' | b',' => Ok(byte),
                _ if byte.is_ascii_alphanumeric() => Ok(byte),
                _ => Err(RejectReason::NotAllowed),
            },
        }
    }

    /// Applies one `WM_CHAR` unit.
    pub fn push_unit(&mut self, unit: u16) -> PushResult {
        let byte = match self.convert(unit) {
            Ok(byte) => byte,
            Err(reason) => return PushResult::Rejected(reason),
        };
        match self.bytes.get_mut(self.len) {
            Some(slot) => {
                *slot = byte;
                self.len = self.len.saturating_add(1);
                PushResult::Accepted
            }
            None => PushResult::Full,
        }
    }

    /// Removes the last byte, overwriting it with 0.
    pub fn backspace(&mut self) -> bool {
        let Some(index) = self.len.checked_sub(1) else {
            return false;
        };
        if let Some(slot) = self.bytes.get_mut(index) {
            *slot = 0;
        }
        self.len = index;
        true
    }

    /// Overwrites everything with 0.
    pub fn clear(&mut self) {
        self.bytes.as_mut_slice().zeroize();
        self.len = 0;
    }

    /// Replaces the contents with already-normalized bytes (paste); all-or-nothing.
    #[must_use]
    pub fn replace_with(&mut self, normalized: &[u8]) -> bool {
        let Some(target) = self.bytes.get_mut(..normalized.len()) else {
            return false;
        };
        target.copy_from_slice(normalized);
        if let Some(rest) = self.bytes.get_mut(normalized.len()..) {
            rest.zeroize();
        }
        self.len = normalized.len();
        true
    }

    /// Moves the bytes out (to a worker); the field's storage is wiped.
    #[must_use]
    pub fn take(mut self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(self.len));
        out.extend_from_slice(self.as_bytes());
        self.clear();
        out
    }

    /// A copy without consuming the field (e.g. confirm-twice comparison, preview).
    #[must_use]
    pub fn copy(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(self.len));
        out.extend_from_slice(self.as_bytes());
        out
    }

    /// A short-lived UTF-16 copy for `DrawTextW`; `masked` draws U+25CF per byte.
    #[must_use]
    pub fn render_utf16(&self, masked: bool) -> Zeroizing<Vec<u16>> {
        let mut out = Zeroizing::new(Vec::with_capacity(self.len));
        for byte in self.as_bytes() {
            out.push(if masked { 0x25CF } else { u16::from(*byte) });
        }
        out
    }

    /// Test access to the raw storage (V-SW-2: wiped positions are 0).
    #[cfg(test)]
    pub(crate) fn raw_storage(&self) -> &[u8] {
        &self.bytes
    }
}

fn is_blank(unit: u16) -> bool {
    matches!(unit, 0x20 | 0x09 | 0x0D | 0x0A)
}

/// Bitcoin base58 alphabet (no `0`, `O`, `I`, `l`).
const fn is_base58(byte: u8) -> bool {
    matches!(byte, b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' | b'a'..=b'k' | b'm'..=b'z')
}

/// Normalizes clipboard text for a field (spec/04 §4.7-2): trim space/tab/CR/LF; for mnemonic
/// text collapse runs of them into one space (and lowercase); every unit must pass the field's
/// character set and the whole value must fit, otherwise nothing is inserted (E-INP-018).
///
/// # Errors
///
/// [`ErrorCode::Inp018`].
pub fn normalize_paste(
    units: &[u16],
    charset: Charset,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
    let start = units
        .iter()
        .position(|unit| !is_blank(*unit))
        .unwrap_or(units.len());
    let end = units
        .iter()
        .rposition(|unit| !is_blank(*unit))
        .map_or(start, |index| index.saturating_add(1));
    let trimmed = units.get(start..end).unwrap_or(&[]);
    if trimmed.is_empty() {
        return Err(ErrorCode::Inp018);
    }
    let mut field = SecretField::new(charset, limit).map_err(|_| ErrorCode::Inp018)?;
    let mut previous_blank = false;
    for unit in trimmed {
        let collapses = matches!(charset, Charset::MnemonicText | Charset::KeyText);
        let unit = if collapses && is_blank(*unit) {
            if previous_blank {
                continue;
            }
            previous_blank = true;
            0x20
        } else {
            previous_blank = false;
            *unit
        };
        if field.push_unit(unit) != PushResult::Accepted {
            return Err(ErrorCode::Inp018);
        }
    }
    Ok(field.take())
}

/// Finishes a private-key entry (spec/04 §4.2): drop `0x`, exactly 64 hex (E-INP-006).
///
/// # Errors
///
/// [`ErrorCode::Inp006`].
pub fn finalize_private_key(field: &SecretField) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
    let bytes = field.as_bytes();
    let digits = bytes.strip_prefix(b"0x").unwrap_or(bytes);
    if digits.len() != 64 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return Err(ErrorCode::Inp006);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(64));
    out.extend_from_slice(digits);
    Ok(out)
}

/// Mnemonic text as words (trailing space dropped at confirmation).
#[must_use]
pub fn mnemonic_words(field: &SecretField) -> Vec<&[u8]> {
    field
        .as_bytes()
        .split(|byte| *byte == b' ')
        .filter(|word| !word.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        Charset, PushResult, RejectReason, SecretField, finalize_private_key, normalize_paste,
    };
    use crate::errors::ErrorCode;

    fn feed(field: &mut SecretField, text: &str) -> Vec<PushResult> {
        text.encode_utf16()
            .map(|unit| field.push_unit(unit))
            .collect()
    }

    #[test]
    fn sw2_printable_rejects_controls_and_non_ascii() {
        let mut field = SecretField::new(Charset::Printable, 128).unwrap();
        feed(&mut field, "ab");
        for unit in [0x1F_u16, 0x7F, 0xAC00, 0xD83D, 0x80] {
            assert!(
                matches!(field.push_unit(unit), PushResult::Rejected(_)),
                "{unit:#x}"
            );
        }
        assert_eq!(
            field.push_unit(0xAC00),
            PushResult::Rejected(RejectReason::NonAscii)
        );
        assert_eq!(field.as_bytes(), b"ab");
    }

    #[test]
    fn sw2_mnemonic_text_normalizes_case_and_spaces() {
        let mut field = SecretField::new(Charset::MnemonicText, 216).unwrap();
        feed(&mut field, "  Abandon  ABOUT ");
        assert_eq!(field.as_bytes(), b"abandon about ");
        assert_eq!(
            field.push_unit(u16::from(b'1')),
            PushResult::Rejected(RejectReason::NotAllowed)
        );
    }

    #[test]
    fn sw2_private_key_hex_rules() {
        let mut field = SecretField::new(Charset::PrivateKeyHex, 66).unwrap();
        assert_eq!(
            feed(&mut field, "0X")[1],
            PushResult::Rejected(RejectReason::NotAllowed)
        );
        field.clear();
        feed(&mut field, "0x12");
        assert_eq!(
            field.push_unit(u16::from(b'x')),
            PushResult::Rejected(RejectReason::Position)
        );
        field.clear();
        feed(&mut field, &"A".repeat(65));
        assert_eq!(field.as_bytes(), "a".repeat(65).as_bytes());
        assert_eq!(
            finalize_private_key(&field).map(|_| ()),
            Err(ErrorCode::Inp006)
        );
        field.clear();
        feed(&mut field, &format!("0x{}", "f".repeat(64)));
        assert_eq!(field.push_unit(u16::from(b'f')), PushResult::Full);
        assert_eq!(
            finalize_private_key(&field).unwrap().as_slice(),
            "f".repeat(64).as_bytes()
        );
    }

    #[test]
    fn sw2_backspace_zeroes_the_removed_position() {
        let mut field = SecretField::new(Charset::Printable, 8).unwrap();
        feed(&mut field, "abc");
        assert!(field.backspace());
        assert_eq!(field.raw_storage()[2], 0);
        assert_eq!(field.as_bytes(), b"ab");
        assert_eq!(field.raw_storage().len(), 8);
        field.clear();
        assert!(field.raw_storage().iter().all(|byte| *byte == 0));
        assert_eq!(field.raw_storage().len(), 8);
        assert!(!field.backspace());
    }

    #[test]
    fn sw3_paste_normalization() {
        let units: Vec<u16> = "abandon\r\n abandon\tabout".encode_utf16().collect();
        assert_eq!(
            normalize_paste(&units, Charset::MnemonicText, 216)
                .unwrap()
                .as_slice(),
            b"abandon abandon about"
        );
        let bad: Vec<u16> = "abandon 1".encode_utf16().collect();
        assert_eq!(
            normalize_paste(&bad, Charset::MnemonicText, 216).map(|_| ()),
            Err(ErrorCode::Inp018)
        );
        let long: Vec<u16> = "a".repeat(129).encode_utf16().collect();
        assert_eq!(
            normalize_paste(&long, Charset::Printable, 128).map(|_| ()),
            Err(ErrorCode::Inp018)
        );
        let padded: Vec<u16> = "  pass word \r\n".encode_utf16().collect();
        assert_eq!(
            normalize_paste(&padded, Charset::Printable, 128)
                .unwrap()
                .as_slice(),
            b"pass word"
        );
        assert!(normalize_paste(&[0x20, 0x0A], Charset::Printable, 128).is_err());
        let mut field = SecretField::new(Charset::MnemonicText, 216).unwrap();
        assert!(field.replace_with(b"abandon about"));
        assert_eq!(field.as_bytes(), b"abandon about");
    }
}
