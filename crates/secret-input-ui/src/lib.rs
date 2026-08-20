//! One-shot native secret-input protocol.
//!
//! This crate accepts only a fixed prompt enum and bounded sizes over inherited
//! standard handles. It never persists, logs, formats, or displays the secret.

use std::fmt;
use std::io::{self, Read, Write};

use zeroize::{Zeroize, Zeroizing};

#[doc(hidden)]
pub mod bootstrap;
#[doc(hidden)]
pub mod recovery;
#[cfg(windows)]
mod recovery_native;

const REQUEST_MAGIC: &[u8; 8] = b"YWSECR01";
const RESPONSE_MAGIC: &[u8; 8] = b"YWSECRS1";
const VERSION: u16 = 1;
const MAX_REQUEST_BYTES: u64 = 80;
const MAX_PHRASE_BYTES: usize = 64;
const RESPONSE_HEADER_BYTES: usize = 13;

/// Maximum secret bytes allowed by the vault password/import contracts.
pub const MAX_SECRET_BYTES: usize = 1_024;

/// Maximum complete response frame accepted by the parent-side codec.
pub const MAX_RESPONSE_BYTES: usize = RESPONSE_HEADER_BYTES + MAX_SECRET_BYTES;

/// Fixed prompts initiated only by the Key Agent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PromptKind {
    /// Unlock an existing encrypted vault.
    UnlockPassword = 1,
    /// Set and confirm a new vault password in separate helper invocations.
    NewVaultPassword = 2,
    /// Import a BIP-39 English mnemonic.
    ImportMnemonic = 3,
    /// Supply the optional BIP-39 passphrase for this unlock session.
    Bip39Passphrase = 4,
    /// Import a strict 32-byte hexadecimal private key.
    ImportRawPrivateKey = 5,
}

impl TryFrom<u8> for PromptKind {
    type Error = SecretInputError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::UnlockPassword),
            2 => Ok(Self::NewVaultPassword),
            3 => Ok(Self::ImportMnemonic),
            4 => Ok(Self::Bip39Passphrase),
            5 => Ok(Self::ImportRawPrivateKey),
            _ => Err(SecretInputError::Malformed),
        }
    }
}

impl PromptKind {
    /// Returns the one canonical UTF-8 byte policy for this prompt kind.
    #[must_use]
    pub const fn canonical_byte_bounds(self) -> (u16, u16) {
        match self {
            Self::UnlockPassword | Self::NewVaultPassword => (12, 64),
            Self::ImportMnemonic => (47, 256),
            Self::Bip39Passphrase => (0, 256),
            Self::ImportRawPrivateKey => (64, 64),
        }
    }
}

/// Bounded request decoded from the private Key Agent channel.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretPrompt {
    /// Fixed reason for input.
    kind: PromptKind,
    /// Minimum UTF-8 byte length, inclusive.
    minimum_bytes: u16,
    /// Maximum UTF-8 byte length, inclusive.
    maximum_bytes: u16,
    /// Local anti-phishing phrase shown in the signed helper caption.
    anti_phishing_phrase: String,
}

impl Drop for SecretPrompt {
    fn drop(&mut self) {
        self.anti_phishing_phrase.zeroize();
    }
}

impl SecretPrompt {
    /// Creates one canonical prompt for a Key-Agent-owned reason.
    ///
    /// The byte bounds are fixed by [`PromptKind`] and cannot be selected by a
    /// broker or other caller.
    ///
    /// # Errors
    ///
    /// Returns [`SecretInputError::Malformed`] for an empty, oversized, or
    /// display-unsafe local anti-phishing phrase.
    pub fn new(kind: PromptKind, anti_phishing_phrase: String) -> Result<Self, SecretInputError> {
        let (minimum_bytes, maximum_bytes) = kind.canonical_byte_bounds();
        let prompt = Self {
            kind,
            minimum_bytes,
            maximum_bytes,
            anti_phishing_phrase,
        };
        validate_prompt(&prompt)?;
        Ok(prompt)
    }

    /// Returns the fixed reason for input.
    #[must_use]
    pub const fn kind(&self) -> PromptKind {
        self.kind
    }

    /// Returns the canonical inclusive UTF-8 byte range.
    #[must_use]
    pub const fn byte_bounds(&self) -> (u16, u16) {
        (self.minimum_bytes, self.maximum_bytes)
    }
}

impl fmt::Debug for SecretPrompt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretPrompt")
            .field("kind", &self.kind)
            .field("minimum_bytes", &self.minimum_bytes)
            .field("maximum_bytes", &self.maximum_bytes)
            .field("anti_phishing_phrase", &"[REDACTED]")
            .finish()
    }
}

/// Secret input outcome.
pub enum SecretOutcome {
    /// User accepted a bounded input. Memory is zeroized on drop.
    Accepted(Zeroizing<Vec<u8>>),
    /// User cancelled or closed the native dialog.
    Cancelled,
}

impl fmt::Debug for SecretOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted(_) => formatter.write_str("SecretOutcome::Accepted([REDACTED])"),
            Self::Cancelled => formatter.write_str("SecretOutcome::Cancelled"),
        }
    }
}

/// Secret helper failure.
pub enum SecretInputError {
    /// Private channel I/O failed.
    Io(io::Error),
    /// Request structure or a fixed bound is invalid.
    Malformed,
    /// Input does not satisfy the requested UTF-8 byte bounds.
    InvalidLength,
    /// Native dialog failed without exposing platform details.
    NativeFailure,
}

impl fmt::Debug for SecretInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Io(_) => "SecretInputError::Io([REDACTED])",
            Self::Malformed => "SecretInputError::Malformed",
            Self::InvalidLength => "SecretInputError::InvalidLength",
            Self::NativeFailure => "SecretInputError::NativeFailure",
        })
    }
}

impl fmt::Display for SecretInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Io(_) => "secret-input channel I/O failed",
            Self::Malformed => "secret-input request is malformed",
            Self::InvalidLength => "secret input length is invalid",
            Self::NativeFailure => "native secret-input dialog failed",
        })
    }
}

impl From<io::Error> for SecretInputError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Encode one validated prompt in the only accepted request format.
///
/// # Errors
///
/// Rejects invalid byte bounds or an empty, oversized, or display-unsafe
/// anti-phishing phrase.
pub fn encode_prompt(prompt: &SecretPrompt) -> Result<Vec<u8>, SecretInputError> {
    validate_prompt(prompt)?;
    let phrase = prompt.anti_phishing_phrase.as_bytes();
    let phrase_length = u8::try_from(phrase.len()).map_err(|_| SecretInputError::Malformed)?;
    let mut bytes = Vec::with_capacity(16 + phrase.len());
    bytes.extend_from_slice(REQUEST_MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(prompt.kind as u8);
    bytes.extend_from_slice(&prompt.minimum_bytes.to_be_bytes());
    bytes.extend_from_slice(&prompt.maximum_bytes.to_be_bytes());
    bytes.push(phrase_length);
    bytes.extend_from_slice(phrase);
    Ok(bytes)
}

/// Read one fixed prompt from the inherited channel.
///
/// # Errors
///
/// Returns an I/O error or rejects malformed, oversized, or invalid prompt fields.
pub fn read_prompt(reader: &mut impl Read) -> Result<SecretPrompt, SecretInputError> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader.take(MAX_REQUEST_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() > usize::try_from(MAX_REQUEST_BYTES).map_err(|_| SecretInputError::Malformed)? {
        return Err(SecretInputError::Malformed);
    }
    decode_prompt(&bytes)
}

/// Return a result exactly once. Accepted secret bytes are zeroized after write.
///
/// # Errors
///
/// Returns an error if a secret exceeds the response bound or the channel cannot be flushed.
pub fn write_outcome(
    writer: &mut impl Write,
    mut outcome: SecretOutcome,
) -> Result<(), SecretInputError> {
    let mut header = Vec::with_capacity(RESPONSE_HEADER_BYTES);
    header.extend_from_slice(RESPONSE_MAGIC);
    header.extend_from_slice(&VERSION.to_be_bytes());
    match &mut outcome {
        SecretOutcome::Accepted(secret) => {
            if secret.len() > MAX_SECRET_BYTES || std::str::from_utf8(secret).is_err() {
                secret.zeroize();
                return Err(SecretInputError::InvalidLength);
            }
            let length =
                u16::try_from(secret.len()).map_err(|_| SecretInputError::InvalidLength)?;
            header.push(1);
            header.extend_from_slice(&length.to_be_bytes());
            writer.write_all(&header)?;
            writer.write_all(secret)?;
            writer.flush()?;
            secret.zeroize();
        }
        SecretOutcome::Cancelled => {
            header.push(0);
            header.extend_from_slice(&0_u16.to_be_bytes());
            writer.write_all(&header)?;
            writer.flush()?;
        }
    }
    Ok(())
}

/// Decode one complete response frame received for the exact launched prompt.
///
/// The owned frame is zeroized on every malformed/cancelled path. For an
/// accepted result, the same allocation is reduced to the secret payload and
/// remains protected by [`Zeroizing`] in [`SecretOutcome::Accepted`]. No
/// trailing bytes, alternate response shapes, or accepted payloads outside the
/// prompt's exact byte bounds are accepted.
///
/// # Errors
///
/// Rejects an oversized, truncated, trailing, invalid-tag, invalid-length, or
/// non-UTF-8 response.
pub fn decode_outcome(
    prompt: &SecretPrompt,
    mut bytes: Zeroizing<Vec<u8>>,
) -> Result<SecretOutcome, SecretInputError> {
    validate_prompt(prompt)?;
    if bytes.len() > MAX_RESPONSE_BYTES
        || bytes.len() < RESPONSE_HEADER_BYTES
        || bytes.get(..8) != Some(RESPONSE_MAGIC)
        || bytes.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
    {
        return Err(SecretInputError::Malformed);
    }

    let tag = bytes[10];
    let declared_length = usize::from(u16::from_be_bytes([bytes[11], bytes[12]]));
    let exact_length = RESPONSE_HEADER_BYTES
        .checked_add(declared_length)
        .ok_or(SecretInputError::Malformed)?;
    if bytes.len() != exact_length || declared_length > MAX_SECRET_BYTES {
        return Err(SecretInputError::Malformed);
    }

    match tag {
        0 if declared_length == 0 => Ok(SecretOutcome::Cancelled),
        1 => {
            std::str::from_utf8(&bytes[RESPONSE_HEADER_BYTES..])
                .map_err(|_| SecretInputError::Malformed)?;
            if declared_length < usize::from(prompt.minimum_bytes)
                || declared_length > usize::from(prompt.maximum_bytes)
            {
                return Err(SecretInputError::InvalidLength);
            }
            bytes.copy_within(RESPONSE_HEADER_BYTES.., 0);
            bytes[declared_length..].zeroize();
            bytes.truncate(declared_length);
            Ok(SecretOutcome::Accepted(bytes))
        }
        _ => Err(SecretInputError::Malformed),
    }
}

/// Read one bounded parent-side response through EOF and decode it.
///
/// The receive buffer is zeroized on error/cancellation or retained only as the
/// zeroizing accepted outcome.
///
/// # Errors
///
/// Returns an I/O error or rejects an oversized or malformed complete frame.
pub fn read_outcome(
    prompt: &SecretPrompt,
    reader: &mut impl Read,
) -> Result<SecretOutcome, SecretInputError> {
    let maximum = u64::try_from(MAX_RESPONSE_BYTES).map_err(|_| SecretInputError::Malformed)?;
    // Keep one byte beyond the overflow sentinel so `read_to_end` can observe
    // `Take` EOF without growing and abandoning a secret-bearing allocation.
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_RESPONSE_BYTES + 2));
    reader.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(SecretInputError::Malformed);
    }
    decode_outcome(prompt, bytes)
}

fn decode_prompt(bytes: &[u8]) -> Result<SecretPrompt, SecretInputError> {
    let mut remaining = bytes;
    if take(&mut remaining, 8)? != REQUEST_MAGIC
        || u16::from_be_bytes(array(&mut remaining)?) != VERSION
    {
        return Err(SecretInputError::Malformed);
    }
    let kind = PromptKind::try_from(byte(&mut remaining)?)?;
    let minimum_bytes = u16::from_be_bytes(array(&mut remaining)?);
    let maximum_bytes = u16::from_be_bytes(array(&mut remaining)?);
    let phrase_length = usize::from(byte(&mut remaining)?);
    if phrase_length == 0 || phrase_length > MAX_PHRASE_BYTES {
        return Err(SecretInputError::Malformed);
    }
    let phrase = std::str::from_utf8(take(&mut remaining, phrase_length)?)
        .map_err(|_| SecretInputError::Malformed)?;
    if !remaining.is_empty() {
        return Err(SecretInputError::Malformed);
    }
    let prompt = SecretPrompt {
        kind,
        minimum_bytes,
        maximum_bytes,
        anti_phishing_phrase: phrase.to_owned(),
    };
    validate_prompt(&prompt)?;
    Ok(prompt)
}

fn validate_prompt(prompt: &SecretPrompt) -> Result<(), SecretInputError> {
    if (prompt.minimum_bytes, prompt.maximum_bytes) != prompt.kind.canonical_byte_bounds()
        || prompt.minimum_bytes > prompt.maximum_bytes
        || usize::from(prompt.maximum_bytes) > MAX_SECRET_BYTES
        || (prompt.kind != PromptKind::Bip39Passphrase && prompt.minimum_bytes == 0)
        || !is_safe_anti_phishing_phrase(&prompt.anti_phishing_phrase)
    {
        return Err(SecretInputError::Malformed);
    }
    Ok(())
}

pub(crate) fn is_safe_anti_phishing_phrase(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_PHRASE_BYTES && !value.chars().any(is_display_unsafe)
}

fn is_display_unsafe(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00ad}'
                | '\u{034f}'
                | '\u{061c}'
                | '\u{115f}'
                | '\u{1160}'
                | '\u{17b4}'
                | '\u{17b5}'
                | '\u{180b}'..='\u{180f}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{3164}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{feff}'
                | '\u{ffa0}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0000}'..='\u{e0fff}'
        )
}

fn take<'a>(remaining: &mut &'a [u8], count: usize) -> Result<&'a [u8], SecretInputError> {
    if remaining.len() < count {
        return Err(SecretInputError::Malformed);
    }
    let (value, rest) = remaining.split_at(count);
    *remaining = rest;
    Ok(value)
}

fn array<const N: usize>(remaining: &mut &[u8]) -> Result<[u8; N], SecretInputError> {
    take(remaining, N)?
        .try_into()
        .map_err(|_| SecretInputError::Malformed)
}

fn byte(remaining: &mut &[u8]) -> Result<u8, SecretInputError> {
    take(remaining, 1)?
        .first()
        .copied()
        .ok_or(SecretInputError::Malformed)
}

fn validate_outcome(
    prompt: &SecretPrompt,
    secret: Zeroizing<Vec<u8>>,
) -> Result<SecretOutcome, SecretInputError> {
    if secret.len() < usize::from(prompt.minimum_bytes)
        || secret.len() > usize::from(prompt.maximum_bytes)
    {
        return Err(SecretInputError::InvalidLength);
    }
    std::str::from_utf8(&secret).map_err(|_| SecretInputError::InvalidLength)?;
    Ok(SecretOutcome::Accepted(secret))
}

#[cfg(windows)]
mod native {
    use std::mem::size_of;

    use windows::Win32::Foundation::{ERROR_CANCELLED, ERROR_SUCCESS, HWND};
    use windows::Win32::Graphics::Gdi::HBITMAP;
    use windows::Win32::Security::Credentials::{
        CREDUI_FLAGS_ALWAYS_SHOW_UI, CREDUI_FLAGS_DO_NOT_PERSIST,
        CREDUI_FLAGS_EXCLUDE_CERTIFICATES, CREDUI_FLAGS_GENERIC_CREDENTIALS,
        CREDUI_FLAGS_PASSWORD_ONLY_OK, CREDUI_INFOW, CredUIPromptForCredentialsW,
    };
    use windows::core::PCWSTR;
    use zeroize::{Zeroize, Zeroizing};

    use super::{PromptKind, SecretInputError, SecretOutcome, SecretPrompt, validate_outcome};

    fn wide(text: &str) -> Zeroizing<Vec<u16>> {
        Zeroizing::new(text.encode_utf16().chain([0]).collect())
    }

    fn utf16_secret(input: &[u16]) -> Result<Zeroizing<Vec<u8>>, SecretInputError> {
        let utf8_length =
            char::decode_utf16(input.iter().copied()).try_fold(0_usize, |length, decoded| {
                let character = decoded.map_err(|_| SecretInputError::InvalidLength)?;
                length
                    .checked_add(character.len_utf8())
                    .ok_or(SecretInputError::InvalidLength)
            })?;
        let mut output = Zeroizing::new(Vec::with_capacity(utf8_length));
        let initial_capacity = output.capacity();
        for decoded in char::decode_utf16(input.iter().copied()) {
            let character = decoded.map_err(|_| SecretInputError::InvalidLength)?;
            let mut encoded = [0_u8; 4];
            let encoded_length = character.encode_utf8(&mut encoded).len();
            output.extend_from_slice(&encoded[..encoded_length]);
            encoded.zeroize();
        }
        if output.len() != utf8_length || output.capacity() != initial_capacity {
            return Err(SecretInputError::NativeFailure);
        }
        Ok(output)
    }

    fn prompt_text(kind: PromptKind) -> &'static str {
        match kind {
            PromptKind::UnlockPassword => "Enter the password that unlocks the local wallet vault.",
            PromptKind::NewVaultPassword => {
                "Enter the new local vault password. It will not be saved by Windows."
            }
            PromptKind::ImportMnemonic => {
                "Enter the BIP-39 English recovery words. Verify this signed helper first."
            }
            PromptKind::Bip39Passphrase => {
                "Enter the optional BIP-39 passphrase for this unlock session only."
            }
            PromptKind::ImportRawPrivateKey => {
                "Enter one 32-byte hexadecimal private key for local encrypted import."
            }
        }
    }

    pub(super) fn present(prompt: &SecretPrompt) -> Result<SecretOutcome, SecretInputError> {
        let mut caption = Zeroizing::new(Vec::with_capacity(
            48_usize.saturating_add(prompt.anti_phishing_phrase.encode_utf16().count()),
        ));
        caption.extend("Your Wallet - ".encode_utf16());
        caption.extend(prompt.anti_phishing_phrase.encode_utf16());
        caption.extend(" - signed secret helper".encode_utf16());
        caption.push(0);
        let message = wide(prompt_text(prompt.kind));
        let target = wide("YourWalletLocalSecretInput");
        let mut username = Zeroizing::new(vec![0_u16; 2]);
        let maximum_utf16 = usize::from(prompt.maximum_bytes).saturating_add(1);
        let mut password = Zeroizing::new(vec![0_u16; maximum_utf16]);
        let info = CREDUI_INFOW {
            cbSize: u32::try_from(size_of::<CREDUI_INFOW>())
                .map_err(|_| SecretInputError::NativeFailure)?,
            hwndParent: HWND::default(),
            pszMessageText: PCWSTR(message.as_ptr()),
            pszCaptionText: PCWSTR(caption.as_ptr()),
            hbmBanner: HBITMAP::default(),
        };
        let flags = CREDUI_FLAGS_GENERIC_CREDENTIALS
            | CREDUI_FLAGS_ALWAYS_SHOW_UI
            | CREDUI_FLAGS_DO_NOT_PERSIST
            | CREDUI_FLAGS_EXCLUDE_CERTIFICATES
            | CREDUI_FLAGS_PASSWORD_ONLY_OK;

        // SAFETY: All pointers reference initialized, writable buffers whose
        // sizes exactly match the counts. CredUI is synchronous. DO_NOT_PERSIST
        // suppresses Credential Manager persistence and its save checkbox.
        let result = unsafe {
            CredUIPromptForCredentialsW(
                Some(&raw const info),
                PCWSTR(target.as_ptr()),
                None,
                0,
                &mut username,
                &mut password,
                None,
                flags,
            )
        };
        username.zeroize();
        if result == ERROR_CANCELLED {
            password.zeroize();
            return Ok(SecretOutcome::Cancelled);
        }
        if result != ERROR_SUCCESS {
            password.zeroize();
            return Err(SecretInputError::NativeFailure);
        }

        let end = password
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(password.len());
        let secret = utf16_secret(&password[..end]);
        password.zeroize();
        validate_outcome(prompt, secret?)
    }

    #[cfg(test)]
    mod tests {
        use super::utf16_secret;

        #[test]
        fn utf16_secret_uses_one_exact_zeroizing_allocation() {
            let encoded = [0x0061_u16, 0xD55C, 0xAE00];
            let secret = utf16_secret(&encoded).unwrap_or_else(|_| unreachable!("valid UTF-16"));
            assert_eq!(secret.as_slice(), "a\u{D55C}\u{AE00}".as_bytes());
            assert_eq!(secret.capacity(), secret.len());
        }

        #[test]
        fn utf16_secret_rejects_unpaired_surrogates() {
            assert!(utf16_secret(&[0xD800]).is_err());
        }
    }
}

/// Present the native one-shot secret input surface only after the inherited
/// parent and channel have been authenticated.
///
/// # Errors
///
/// Returns an error when the native dialog fails or accepted input violates fixed bounds.
#[doc(hidden)]
pub fn present_authenticated(
    session: &bootstrap::AuthenticatedSession,
) -> Result<SecretOutcome, SecretInputError> {
    let prompt = session.prompt();
    #[cfg(windows)]
    {
        native::present(prompt)
    }
    #[cfg(not(windows))]
    {
        let _ = prompt;
        Ok(SecretOutcome::Cancelled)
    }
}

/// Produce the stage-correct fail-closed cancellation for an authenticated
/// recovery capability without exposing or cloning its request.
#[doc(hidden)]
#[must_use]
pub fn cancel_authenticated_recovery(
    session: &bootstrap::AuthenticatedRecoverySession,
) -> recovery::RecoveryOutcome {
    recovery::cancelled_for(session.request())
}

/// Present one authenticated recovery stage.
///
/// # Errors
///
/// Returns an error when the native surface cannot establish capture exclusion,
/// foreground/focus integrity, bounded input controls, or another required
/// fail-closed security property.
#[doc(hidden)]
pub fn present_authenticated_recovery(
    session: &bootstrap::AuthenticatedRecoverySession,
) -> Result<recovery::RecoveryOutcome, SecretInputError> {
    let request = session.request();
    #[cfg(windows)]
    {
        recovery_native::present(request)
    }
    #[cfg(not(windows))]
    {
        Ok(recovery::cancelled_for(request))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use zeroize::Zeroizing;

    use super::{
        MAX_RESPONSE_BYTES, MAX_SECRET_BYTES, PromptKind, SecretInputError, SecretOutcome,
        SecretPrompt, VERSION, decode_outcome, decode_prompt, encode_prompt, read_outcome,
        validate_outcome, write_outcome,
    };

    fn request(kind: PromptKind, minimum: u16, maximum: u16) -> Vec<u8> {
        let phrase = b"blue comet";
        let mut bytes = b"YWSECR01".to_vec();
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.push(kind as u8);
        bytes.extend_from_slice(&minimum.to_be_bytes());
        bytes.extend_from_slice(&maximum.to_be_bytes());
        bytes.push(u8::try_from(phrase.len()).unwrap_or(u8::MAX));
        bytes.extend_from_slice(phrase);
        bytes
    }

    #[test]
    fn secret_input_error_formatting_never_repeats_io_details() {
        let error = SecretInputError::Io(std::io::Error::other("private-local-path-marker"));
        assert_eq!(format!("{error:?}"), "SecretInputError::Io([REDACTED])");
        assert_eq!(error.to_string(), "secret-input channel I/O failed");
        assert!(!format!("{error:?}").contains("private-local-path-marker"));
        assert!(!error.to_string().contains("private-local-path-marker"));
    }

    #[test]
    fn fixed_prompt_round_trip() -> Result<(), SecretInputError> {
        let bytes = request(PromptKind::UnlockPassword, 12, 64);
        let prompt = decode_prompt(&bytes)?;
        assert_eq!(prompt.kind, PromptKind::UnlockPassword);
        assert_eq!(encode_prompt(&prompt)?, bytes);
        Ok(())
    }

    #[test]
    fn parent_decodes_exact_accepted_response() -> Result<(), SecretInputError> {
        let secret = b"bounded secret";
        let mut bytes = b"YWSECRS1".to_vec();
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.push(1);
        bytes.extend_from_slice(
            &u16::try_from(secret.len())
                .map_err(|_| SecretInputError::Malformed)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(secret);

        let prompt = decode_prompt(&request(PromptKind::UnlockPassword, 12, 64))?;
        let outcome = decode_outcome(&prompt, Zeroizing::new(bytes))?;
        match outcome {
            SecretOutcome::Accepted(decoded) => assert_eq!(decoded.as_slice(), secret),
            SecretOutcome::Cancelled => return Err(SecretInputError::Malformed),
        }
        Ok(())
    }

    #[test]
    fn parent_requires_exact_response_eof() {
        let prompt = SecretPrompt::new(PromptKind::UnlockPassword, "blue comet".to_owned())
            .unwrap_or_else(|_| unreachable!("test prompt is canonical"));
        let mut bytes = b"YWSECRS1".to_vec();
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.push(0);

        assert!(matches!(
            decode_outcome(&prompt, Zeroizing::new(bytes)),
            Err(SecretInputError::Malformed)
        ));
    }

    #[test]
    fn parent_read_caps_response_before_decode() {
        let prompt = SecretPrompt::new(PromptKind::UnlockPassword, "blue comet".to_owned())
            .unwrap_or_else(|_| unreachable!("test prompt is canonical"));
        let bytes = vec![0; MAX_RESPONSE_BYTES + 1];
        assert!(matches!(
            read_outcome(&prompt, &mut Cursor::new(bytes)),
            Err(SecretInputError::Malformed)
        ));
    }

    #[test]
    fn parent_enforces_exact_prompt_bounds() -> Result<(), SecretInputError> {
        let secret = b"short";
        let mut bytes = b"YWSECRS1".to_vec();
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.push(1);
        bytes.extend_from_slice(
            &u16::try_from(secret.len())
                .map_err(|_| SecretInputError::Malformed)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(secret);
        let prompt = decode_prompt(&request(PromptKind::UnlockPassword, 12, 64))?;

        assert!(matches!(
            decode_outcome(&prompt, Zeroizing::new(bytes)),
            Err(SecretInputError::InvalidLength)
        ));
        Ok(())
    }

    #[test]
    fn only_passphrase_may_be_empty() {
        assert!(decode_prompt(&request(PromptKind::UnlockPassword, 0, 64)).is_err());
        assert!(decode_prompt(&request(PromptKind::Bip39Passphrase, 0, 256)).is_ok());
    }

    #[test]
    fn rejects_out_of_range_result() {
        let prompt = decode_prompt(&request(PromptKind::UnlockPassword, 12, 64)).ok();
        let result = prompt.map(|value| validate_outcome(&value, Zeroizing::new(vec![1; 3])));
        assert!(matches!(result, Some(Err(SecretInputError::InvalidLength))));
    }

    #[test]
    fn anti_phishing_phrase_rejects_format_and_bidi_spoofing() {
        for character in ['\n', '\u{200b}', '\u{202e}', '\u{2066}', '\u{feff}'] {
            let mut bytes = request(PromptKind::UnlockPassword, 12, 64);
            bytes.truncate(15);
            let phrase = format!("blue{character}comet");
            bytes.push(u8::try_from(phrase.len()).unwrap_or(u8::MAX));
            bytes.extend_from_slice(phrase.as_bytes());
            assert!(decode_prompt(&bytes).is_err());
        }
    }

    #[test]
    fn cancelled_response_contains_no_payload() -> Result<(), SecretInputError> {
        let mut bytes = Vec::new();
        write_outcome(&mut bytes, SecretOutcome::Cancelled)?;
        assert_eq!(bytes.len(), 13);
        assert_eq!(bytes[10], 0);
        Ok(())
    }

    #[test]
    fn accepted_outcome_debug_never_contains_secret_bytes() {
        let outcome = SecretOutcome::Accepted(Zeroizing::new(vec![91, 92, 93]));
        let debug = format!("{outcome:?}");
        assert_eq!(debug, "SecretOutcome::Accepted([REDACTED])");
        assert!(!debug.contains("91"));
    }

    #[test]
    fn prompt_debug_never_contains_anti_phishing_phrase() {
        let prompt = SecretPrompt::new(PromptKind::UnlockPassword, "blue comet".to_owned())
            .unwrap_or_else(|_| unreachable!("test prompt is canonical"));
        let debug = format!("{prompt:?}");
        assert!(!debug.contains("blue comet"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn response_rejects_secret_above_global_bound() {
        let mut output = Vec::new();
        let outcome = SecretOutcome::Accepted(Zeroizing::new(vec![1; MAX_SECRET_BYTES + 1]));
        assert!(matches!(
            write_outcome(&mut output, outcome),
            Err(SecretInputError::InvalidLength)
        ));
        assert!(output.is_empty());
    }
}
