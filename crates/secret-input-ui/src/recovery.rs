//! Strict typed protocol for the two-stage BIP-39 recovery ceremony.
//!
//! Display and confirmation are deliberately different one-shot requests. The
//! display request contains the recovery phrase and first address but no
//! challenge positions. The later confirmation request contains four positions
//! but never the expected words or address. This preserves the Key Agent's
//! requirement that the user answer from an independently retained backup.
//!
//! These bounded canonical frames are carried by stage-specific authenticated
//! child sessions and rendered by a capture-resistant native surface. Production
//! activation remains blocked until the Windows parent channel and crate-private
//! Key Agent recovery lifecycle are connected and release evidence supplies the
//! compiled parent policy.

use core::fmt;
use std::io::{Read, Write};

use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::{SecretInputError, is_safe_anti_phishing_phrase};

const REQUEST_MAGIC: &[u8; 8] = b"YWRECRQ1";
const RESPONSE_MAGIC: &[u8; 8] = b"YWRECRS1";
const VERSION: u16 = 1;
const REQUEST_HEADER_BYTES: usize = 14;
const RESPONSE_HEADER_BYTES: usize = 14;
/// Exact byte length of the opaque cross-stage recovery ceremony identifier.
pub const RECOVERY_CEREMONY_ID_BYTES: usize = 32;
const DISPLAY_FIXED_BYTES: usize = 28 + RECOVERY_CEREMONY_ID_BYTES;
const CONFIRM_FIXED_BYTES: usize = 10 + RECOVERY_CEREMONY_ID_BYTES;
const CONFIRMED_FIXED_BYTES: usize = 24;
const MAX_ANTI_PHISHING_BYTES: usize = 64;
const MAX_MNEMONIC_BYTES: usize = 256;
pub(crate) const CHALLENGE_WORDS: usize = 4;
pub(crate) const MAX_BIP39_WORD_BYTES: usize = 8;
const WORDLIST_ENGLISH: u8 = 1;
const DERIVATION_EVM_BIP44_INDEX_ZERO: u8 = 1;
const PASSPHRASE_NOT_REQUIRED: u8 = 0;

/// Largest complete recovery request accepted through EOF.
pub const MAX_RECOVERY_REQUEST_BYTES: usize =
    REQUEST_HEADER_BYTES + DISPLAY_FIXED_BYTES + MAX_ANTI_PHISHING_BYTES + MAX_MNEMONIC_BYTES;
/// Largest complete recovery response accepted through EOF.
pub const MAX_RECOVERY_RESPONSE_BYTES: usize =
    RESPONSE_HEADER_BYTES + CONFIRMED_FIXED_BYTES + CHALLENGE_WORDS * MAX_BIP39_WORD_BYTES;

/// Supported generated recovery phrase sizes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RecoveryWordCount {
    /// A 128-bit, twelve-word BIP-39 phrase.
    Twelve = 12,
    /// A 256-bit, twenty-four-word BIP-39 phrase.
    TwentyFour = 24,
}

impl RecoveryWordCount {
    /// Returns the exact number of English words.
    #[must_use]
    pub const fn get(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for RecoveryWordCount {
    type Error = SecretInputError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            12 => Ok(Self::Twelve),
            24 => Ok(Self::TwentyFour),
            _ => Err(SecretInputError::Malformed),
        }
    }
}

/// Fresh opaque identifier shared by exactly one display/confirmation ceremony.
///
/// The Key Agent must supply 32 bytes from the operating-system CSPRNG. The raw
/// value is deliberately unavailable after construction; callers can only bind
/// it into typed requests or compare two identifiers in constant time.
///
/// Arbitrary bytes cannot be promoted into a ceremony identifier:
///
/// ```compile_fail
/// use secret_input_ui::recovery::{RECOVERY_CEREMONY_ID_BYTES, RecoveryCeremonyId};
///
/// let _ = RecoveryCeremonyId([7_u8; RECOVERY_CEREMONY_ID_BYTES]);
/// ```
///
/// Ceremony identifiers are deliberately non-cloneable:
///
/// ```compile_fail
/// use secret_input_ui::recovery::RecoveryCeremonyId;
///
/// let ceremony = RecoveryCeremonyId::generate().expect("OS CSPRNG");
/// let _duplicate = ceremony.clone();
/// ```
pub struct RecoveryCeremonyId([u8; RECOVERY_CEREMONY_ID_BYTES]);

impl RecoveryCeremonyId {
    /// Generates one nonzero identifier from the operating-system CSPRNG.
    ///
    /// # Errors
    ///
    /// Fails closed if secure randomness is unavailable or returns the all-zero
    /// sentinel. There is deliberately no public arbitrary-byte constructor.
    pub fn generate() -> Result<Self, SecretInputError> {
        let mut bytes = [0_u8; RECOVERY_CEREMONY_ID_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| SecretInputError::NativeFailure)?;
        Self::from_bytes(bytes).map_err(|_| SecretInputError::NativeFailure)
    }

    fn from_bytes(bytes: [u8; RECOVERY_CEREMONY_ID_BYTES]) -> Result<Self, SecretInputError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(SecretInputError::Malformed);
        }
        Ok(Self(bytes))
    }

    /// Compares two opaque ceremony identifiers without exposing their bytes.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }

    fn duplicate(&self) -> Self {
        Self(self.0)
    }
}

impl fmt::Debug for RecoveryCeremonyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryCeremonyId([REDACTED])")
    }
}

/// Secret-bearing first stage shown before challenge positions are selected.
pub struct RecoveryDisplayRequest {
    ceremony_id: RecoveryCeremonyId,
    anti_phishing_phrase: Zeroizing<String>,
    word_count: RecoveryWordCount,
    first_address: [u8; 20],
    mnemonic: Zeroizing<String>,
}

impl RecoveryDisplayRequest {
    /// Creates an exact English BIP-39 display request.
    ///
    /// # Errors
    ///
    /// Rejects an unsafe anti-phishing phrase, wrong word count, non-canonical
    /// lowercase words, or an oversized phrase.
    pub fn new(
        ceremony_id: &RecoveryCeremonyId,
        anti_phishing_phrase: Zeroizing<String>,
        word_count: RecoveryWordCount,
        first_address: [u8; 20],
        mnemonic: Zeroizing<String>,
    ) -> Result<Self, SecretInputError> {
        let request = Self {
            ceremony_id: ceremony_id.duplicate(),
            anti_phishing_phrase,
            word_count,
            first_address,
            mnemonic,
        };
        validate_display(&request)?;
        Ok(request)
    }

    /// Confirms an opaque ceremony binding without exposing its raw identifier.
    #[must_use]
    pub fn matches_ceremony(&self, expected: &RecoveryCeremonyId) -> bool {
        self.ceremony_id.matches(expected)
    }

    pub(crate) fn anti_phishing_phrase(&self) -> &str {
        &self.anti_phishing_phrase
    }

    pub(crate) const fn word_count(&self) -> RecoveryWordCount {
        self.word_count
    }

    pub(crate) const fn first_address(&self) -> [u8; 20] {
        self.first_address
    }

    pub(crate) fn mnemonic(&self) -> &str {
        &self.mnemonic
    }
}

impl fmt::Debug for RecoveryDisplayRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryDisplayRequest")
            .field("ceremony_id", &"[REDACTED]")
            .field("anti_phishing_phrase", &"[REDACTED]")
            .field("word_count", &self.word_count)
            .field("first_address", &"[REDACTED]")
            .field("mnemonic", &"[REDACTED]")
            .finish()
    }
}

/// Secret-free second-stage prompt. Expected answers are intentionally absent.
pub struct RecoveryConfirmRequest {
    ceremony_id: RecoveryCeremonyId,
    anti_phishing_phrase: Zeroizing<String>,
    word_count: RecoveryWordCount,
    positions: [u8; CHALLENGE_WORDS],
}

impl RecoveryConfirmRequest {
    /// Creates a confirmation request with four sorted one-based positions.
    ///
    /// # Errors
    ///
    /// Rejects unsafe captions, duplicate/unsorted positions, zero, or a
    /// position outside the selected phrase size.
    pub fn new(
        ceremony_id: &RecoveryCeremonyId,
        anti_phishing_phrase: Zeroizing<String>,
        word_count: RecoveryWordCount,
        positions: [u8; CHALLENGE_WORDS],
    ) -> Result<Self, SecretInputError> {
        let request = Self {
            ceremony_id: ceremony_id.duplicate(),
            anti_phishing_phrase,
            word_count,
            positions,
        };
        validate_confirm(&request)?;
        Ok(request)
    }

    /// Confirms an opaque ceremony binding without exposing its raw identifier.
    #[must_use]
    pub fn matches_ceremony(&self, expected: &RecoveryCeremonyId) -> bool {
        self.ceremony_id.matches(expected)
    }

    pub(crate) fn anti_phishing_phrase(&self) -> &str {
        &self.anti_phishing_phrase
    }

    pub(crate) const fn word_count(&self) -> RecoveryWordCount {
        self.word_count
    }

    pub(crate) const fn positions(&self) -> [u8; CHALLENGE_WORDS] {
        self.positions
    }
}

impl fmt::Debug for RecoveryConfirmRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryConfirmRequest")
            .field("ceremony_id", &"[REDACTED]")
            .field("anti_phishing_phrase", &"[REDACTED]")
            .field("word_count", &self.word_count)
            .field("positions", &self.positions)
            .finish()
    }
}

/// Exact typed request accepted by the recovery helper.
pub enum RecoveryRequest {
    /// Show recovery material and wait for a deliberate acknowledgement.
    Display(RecoveryDisplayRequest),
    /// Collect four words and the first address without expected answers.
    Confirm(RecoveryConfirmRequest),
}

impl fmt::Debug for RecoveryRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Display(request) => request.fmt(formatter),
            Self::Confirm(request) => request.fmt(formatter),
        }
    }
}

/// Payload returned only by the confirmation stage.
pub struct RecoveryConfirmationInput {
    words: [Zeroizing<String>; CHALLENGE_WORDS],
    first_address: [u8; 20],
}

impl RecoveryConfirmationInput {
    /// Constructs exact lowercase English-shaped answers.
    ///
    /// Membership and equality are intentionally verified later by the Key
    /// Agent against its hidden challenge, never by this DTO.
    ///
    /// # Errors
    ///
    /// Rejects empty, non-lowercase-ASCII, or oversized answer words.
    pub fn new(
        words: [Zeroizing<String>; CHALLENGE_WORDS],
        first_address: [u8; 20],
    ) -> Result<Self, SecretInputError> {
        if !words.iter().all(|word| is_canonical_word(word)) {
            return Err(SecretInputError::Malformed);
        }
        Ok(Self {
            words,
            first_address,
        })
    }

    /// Consumes the response into Key-Agent-owned zeroizing words and address.
    #[must_use]
    pub fn into_parts(self) -> ([Zeroizing<String>; CHALLENGE_WORDS], [u8; 20]) {
        (self.words, self.first_address)
    }
}

impl fmt::Debug for RecoveryConfirmationInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryConfirmationInput([REDACTED WORDS AND ADDRESS])")
    }
}

/// One outcome whose variant must match the launched request kind.
pub enum RecoveryOutcome {
    /// The user deliberately acknowledged the displayed recovery material.
    DisplayAcknowledged,
    /// The display window was cancelled or closed.
    DisplayCancelled,
    /// The user submitted four answers and one address.
    Confirmed(RecoveryConfirmationInput),
    /// The confirmation window was cancelled or closed.
    ConfirmCancelled,
}

pub(crate) const fn cancelled_for(request: &RecoveryRequest) -> RecoveryOutcome {
    match request {
        RecoveryRequest::Display(_) => RecoveryOutcome::DisplayCancelled,
        RecoveryRequest::Confirm(_) => RecoveryOutcome::ConfirmCancelled,
    }
}

impl fmt::Debug for RecoveryOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DisplayAcknowledged => "RecoveryOutcome::DisplayAcknowledged",
            Self::DisplayCancelled => "RecoveryOutcome::DisplayCancelled",
            Self::Confirmed(_) => "RecoveryOutcome::Confirmed([REDACTED])",
            Self::ConfirmCancelled => "RecoveryOutcome::ConfirmCancelled",
        })
    }
}

/// Encodes one canonical request in a zeroizing exact-capacity allocation.
///
/// # Errors
///
/// Revalidates all semantic bounds and rejects size conversion overflow.
pub fn encode_request(request: &RecoveryRequest) -> Result<Zeroizing<Vec<u8>>, SecretInputError> {
    let (kind, payload_length) = match request {
        RecoveryRequest::Display(display) => {
            validate_display(display)?;
            (
                1_u8,
                DISPLAY_FIXED_BYTES
                    .checked_add(display.anti_phishing_phrase.len())
                    .and_then(|value| value.checked_add(display.mnemonic.len()))
                    .ok_or(SecretInputError::Malformed)?,
            )
        }
        RecoveryRequest::Confirm(confirm) => {
            validate_confirm(confirm)?;
            (
                2_u8,
                CONFIRM_FIXED_BYTES
                    .checked_add(confirm.anti_phishing_phrase.len())
                    .ok_or(SecretInputError::Malformed)?,
            )
        }
    };
    let total = REQUEST_HEADER_BYTES
        .checked_add(payload_length)
        .ok_or(SecretInputError::Malformed)?;
    if total > MAX_RECOVERY_REQUEST_BYTES {
        return Err(SecretInputError::Malformed);
    }
    let mut output = Zeroizing::new(Vec::with_capacity(total));
    output.extend_from_slice(REQUEST_MAGIC);
    output.extend_from_slice(&VERSION.to_be_bytes());
    output.push(kind);
    output.push(0);
    output.extend_from_slice(
        &u16::try_from(payload_length)
            .map_err(|_| SecretInputError::Malformed)?
            .to_be_bytes(),
    );
    match request {
        RecoveryRequest::Display(display) => encode_display_payload(&mut output, display)?,
        RecoveryRequest::Confirm(confirm) => encode_confirm_payload(&mut output, confirm)?,
    }
    if output.len() != total || output.capacity() != total {
        return Err(SecretInputError::Malformed);
    }
    Ok(output)
}

/// Decodes one complete canonical request.
///
/// # Errors
///
/// Rejects every truncation, trailing byte, unknown field, nonzero reserved
/// value, unsafe caption, or malformed phrase/position set.
#[allow(clippy::needless_pass_by_value)] // Ownership zeroizes the full secret-bearing frame.
pub fn decode_request(bytes: Zeroizing<Vec<u8>>) -> Result<RecoveryRequest, SecretInputError> {
    if bytes.len() < REQUEST_HEADER_BYTES || bytes.len() > MAX_RECOVERY_REQUEST_BYTES {
        return Err(SecretInputError::Malformed);
    }
    let mut cursor = Cursor::new(&bytes);
    if cursor.take::<8>()? != *REQUEST_MAGIC || cursor.read_u16()? != VERSION {
        return Err(SecretInputError::Malformed);
    }
    let kind = cursor.read_u8()?;
    if cursor.read_u8()? != 0 {
        return Err(SecretInputError::Malformed);
    }
    let payload_length = usize::from(cursor.read_u16()?);
    if cursor.remaining() != payload_length {
        return Err(SecretInputError::Malformed);
    }
    match kind {
        1 => decode_display_payload(&mut cursor),
        2 => decode_confirm_payload(&mut cursor),
        _ => Err(SecretInputError::Malformed),
    }
}

/// Reads one request through EOF with a hard allocation bound.
///
/// # Errors
///
/// Returns channel I/O failures or rejects oversized/malformed frames.
pub fn read_request(reader: &mut impl Read) -> Result<RecoveryRequest, SecretInputError> {
    let maximum =
        u64::try_from(MAX_RECOVERY_REQUEST_BYTES).map_err(|_| SecretInputError::Malformed)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_RECOVERY_REQUEST_BYTES + 1));
    reader.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RECOVERY_REQUEST_BYTES {
        return Err(SecretInputError::Malformed);
    }
    decode_request(bytes)
}

/// Encodes an outcome only when its stage matches the exact request.
///
/// # Errors
///
/// Rejects cross-stage outcomes and malformed confirmation fields.
pub fn encode_outcome(
    request: &RecoveryRequest,
    outcome: &RecoveryOutcome,
) -> Result<Zeroizing<Vec<u8>>, SecretInputError> {
    let (kind, disposition, payload_length) = match (request, outcome) {
        (RecoveryRequest::Display(_), RecoveryOutcome::DisplayCancelled) => (1_u8, 0_u8, 0),
        (RecoveryRequest::Display(_), RecoveryOutcome::DisplayAcknowledged) => (1, 1, 0),
        (RecoveryRequest::Confirm(_), RecoveryOutcome::ConfirmCancelled) => (2, 0, 0),
        (RecoveryRequest::Confirm(_), RecoveryOutcome::Confirmed(input)) => {
            if !input.words.iter().all(|word| is_canonical_word(word)) {
                return Err(SecretInputError::Malformed);
            }
            let words_length = input.words.iter().try_fold(0_usize, |total, word| {
                total
                    .checked_add(word.len())
                    .ok_or(SecretInputError::Malformed)
            })?;
            (
                2,
                1,
                CONFIRMED_FIXED_BYTES
                    .checked_add(words_length)
                    .ok_or(SecretInputError::Malformed)?,
            )
        }
        _ => return Err(SecretInputError::Malformed),
    };
    let total = RESPONSE_HEADER_BYTES
        .checked_add(payload_length)
        .ok_or(SecretInputError::Malformed)?;
    if total > MAX_RECOVERY_RESPONSE_BYTES {
        return Err(SecretInputError::Malformed);
    }
    let mut output = Zeroizing::new(Vec::with_capacity(total));
    output.extend_from_slice(RESPONSE_MAGIC);
    output.extend_from_slice(&VERSION.to_be_bytes());
    output.push(kind);
    output.push(disposition);
    output.extend_from_slice(
        &u16::try_from(payload_length)
            .map_err(|_| SecretInputError::Malformed)?
            .to_be_bytes(),
    );
    if let RecoveryOutcome::Confirmed(input) = outcome {
        for word in &input.words {
            output.push(u8::try_from(word.len()).map_err(|_| SecretInputError::Malformed)?);
        }
        output.extend_from_slice(&input.first_address);
        for word in &input.words {
            output.extend_from_slice(word.as_bytes());
        }
    }
    if output.len() != total || output.capacity() != total {
        return Err(SecretInputError::Malformed);
    }
    Ok(output)
}

/// Decodes a response only for the exact launched stage.
///
/// # Errors
///
/// Rejects cross-stage, oversized, malformed, truncated, or trailing data.
#[allow(clippy::needless_pass_by_value)] // Ownership zeroizes every rejected answer frame.
pub fn decode_outcome(
    request: &RecoveryRequest,
    bytes: Zeroizing<Vec<u8>>,
) -> Result<RecoveryOutcome, SecretInputError> {
    if bytes.len() < RESPONSE_HEADER_BYTES || bytes.len() > MAX_RECOVERY_RESPONSE_BYTES {
        return Err(SecretInputError::Malformed);
    }
    let mut cursor = Cursor::new(&bytes);
    if cursor.take::<8>()? != *RESPONSE_MAGIC || cursor.read_u16()? != VERSION {
        return Err(SecretInputError::Malformed);
    }
    let kind = cursor.read_u8()?;
    let disposition = cursor.read_u8()?;
    let payload_length = usize::from(cursor.read_u16()?);
    if cursor.remaining() != payload_length {
        return Err(SecretInputError::Malformed);
    }
    match (request, kind, disposition, payload_length) {
        (RecoveryRequest::Display(_), 1, 0, 0) => Ok(RecoveryOutcome::DisplayCancelled),
        (RecoveryRequest::Display(_), 1, 1, 0) => Ok(RecoveryOutcome::DisplayAcknowledged),
        (RecoveryRequest::Confirm(_), 2, 0, 0) => Ok(RecoveryOutcome::ConfirmCancelled),
        (RecoveryRequest::Confirm(_), 2, 1, _) => decode_confirmation(&mut cursor),
        _ => Err(SecretInputError::Malformed),
    }
}

/// Writes one exact outcome and flushes the inherited channel.
///
/// # Errors
///
/// Returns encoding or channel failures.
pub fn write_outcome(
    writer: &mut impl Write,
    request: &RecoveryRequest,
    outcome: &RecoveryOutcome,
) -> Result<(), SecretInputError> {
    let encoded = encode_outcome(request, outcome)?;
    writer.write_all(&encoded)?;
    writer.flush().map_err(Into::into)
}

/// Reads one exact response through EOF with a hard allocation bound.
///
/// # Errors
///
/// Returns channel I/O failures or rejects oversized/malformed frames.
pub fn read_outcome(
    reader: &mut impl Read,
    request: &RecoveryRequest,
) -> Result<RecoveryOutcome, SecretInputError> {
    let maximum =
        u64::try_from(MAX_RECOVERY_RESPONSE_BYTES).map_err(|_| SecretInputError::Malformed)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_RECOVERY_RESPONSE_BYTES + 1));
    reader.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RECOVERY_RESPONSE_BYTES {
        return Err(SecretInputError::Malformed);
    }
    decode_outcome(request, bytes)
}

fn encode_display_payload(
    output: &mut Vec<u8>,
    request: &RecoveryDisplayRequest,
) -> Result<(), SecretInputError> {
    output.push(
        u8::try_from(request.anti_phishing_phrase.len())
            .map_err(|_| SecretInputError::Malformed)?,
    );
    output.push(request.word_count.get());
    output.push(WORDLIST_ENGLISH);
    output.push(DERIVATION_EVM_BIP44_INDEX_ZERO);
    output.push(PASSPHRASE_NOT_REQUIRED);
    output.push(0);
    output.extend_from_slice(&request.ceremony_id.0);
    output.extend_from_slice(&request.first_address);
    output.extend_from_slice(
        &u16::try_from(request.mnemonic.len())
            .map_err(|_| SecretInputError::Malformed)?
            .to_be_bytes(),
    );
    output.extend_from_slice(request.anti_phishing_phrase.as_bytes());
    output.extend_from_slice(request.mnemonic.as_bytes());
    Ok(())
}

fn encode_confirm_payload(
    output: &mut Vec<u8>,
    request: &RecoveryConfirmRequest,
) -> Result<(), SecretInputError> {
    output.push(
        u8::try_from(request.anti_phishing_phrase.len())
            .map_err(|_| SecretInputError::Malformed)?,
    );
    output.push(request.word_count.get());
    output.push(WORDLIST_ENGLISH);
    output.push(DERIVATION_EVM_BIP44_INDEX_ZERO);
    output.push(PASSPHRASE_NOT_REQUIRED);
    output.push(0);
    output.extend_from_slice(&request.ceremony_id.0);
    output.extend_from_slice(&request.positions);
    output.extend_from_slice(request.anti_phishing_phrase.as_bytes());
    Ok(())
}

fn decode_display_payload(cursor: &mut Cursor<'_>) -> Result<RecoveryRequest, SecretInputError> {
    let anti_length = usize::from(cursor.read_u8()?);
    let word_count = RecoveryWordCount::try_from(cursor.read_u8()?)?;
    validate_fixed_profile(cursor)?;
    let ceremony_id = RecoveryCeremonyId::from_bytes(cursor.take::<RECOVERY_CEREMONY_ID_BYTES>()?)?;
    let first_address = cursor.take::<20>()?;
    let phrase_length = usize::from(cursor.read_u16()?);
    if anti_length == 0
        || anti_length > MAX_ANTI_PHISHING_BYTES
        || phrase_length == 0
        || phrase_length > MAX_MNEMONIC_BYTES
        || cursor.remaining() != anti_length.saturating_add(phrase_length)
    {
        return Err(SecretInputError::Malformed);
    }
    let anti = owned_zeroizing_utf8(cursor.take_slice(anti_length)?)?;
    let mnemonic = owned_zeroizing_utf8(cursor.take_slice(phrase_length)?)?;
    RecoveryDisplayRequest::new(&ceremony_id, anti, word_count, first_address, mnemonic)
        .map(RecoveryRequest::Display)
}

fn decode_confirm_payload(cursor: &mut Cursor<'_>) -> Result<RecoveryRequest, SecretInputError> {
    let anti_length = usize::from(cursor.read_u8()?);
    let word_count = RecoveryWordCount::try_from(cursor.read_u8()?)?;
    validate_fixed_profile(cursor)?;
    let ceremony_id = RecoveryCeremonyId::from_bytes(cursor.take::<RECOVERY_CEREMONY_ID_BYTES>()?)?;
    let positions = cursor.take::<CHALLENGE_WORDS>()?;
    if anti_length == 0
        || anti_length > MAX_ANTI_PHISHING_BYTES
        || cursor.remaining() != anti_length
    {
        return Err(SecretInputError::Malformed);
    }
    let anti = owned_zeroizing_utf8(cursor.take_slice(anti_length)?)?;
    RecoveryConfirmRequest::new(&ceremony_id, anti, word_count, positions)
        .map(RecoveryRequest::Confirm)
}

fn validate_fixed_profile(cursor: &mut Cursor<'_>) -> Result<(), SecretInputError> {
    if cursor.read_u8()? != WORDLIST_ENGLISH
        || cursor.read_u8()? != DERIVATION_EVM_BIP44_INDEX_ZERO
        || cursor.read_u8()? != PASSPHRASE_NOT_REQUIRED
        || cursor.read_u8()? != 0
    {
        return Err(SecretInputError::Malformed);
    }
    Ok(())
}

fn decode_confirmation(cursor: &mut Cursor<'_>) -> Result<RecoveryOutcome, SecretInputError> {
    if cursor.remaining() < CONFIRMED_FIXED_BYTES {
        return Err(SecretInputError::Malformed);
    }
    let lengths = cursor.take::<CHALLENGE_WORDS>()?;
    let first_address = cursor.take::<20>()?;
    let words_length = lengths.iter().try_fold(0_usize, |total, length| {
        let length = usize::from(*length);
        if !(1..=MAX_BIP39_WORD_BYTES).contains(&length) {
            return Err(SecretInputError::Malformed);
        }
        total.checked_add(length).ok_or(SecretInputError::Malformed)
    })?;
    if cursor.remaining() != words_length {
        return Err(SecretInputError::Malformed);
    }
    let mut words = Vec::with_capacity(CHALLENGE_WORDS);
    for length in lengths {
        words.push(owned_zeroizing_utf8(
            cursor.take_slice(usize::from(length))?,
        )?);
    }
    let words: [Zeroizing<String>; CHALLENGE_WORDS] =
        words.try_into().map_err(|_| SecretInputError::Malformed)?;
    RecoveryConfirmationInput::new(words, first_address).map(RecoveryOutcome::Confirmed)
}

fn validate_display(request: &RecoveryDisplayRequest) -> Result<(), SecretInputError> {
    if !is_safe_anti_phishing_phrase(&request.anti_phishing_phrase)
        || request.anti_phishing_phrase.len() > MAX_ANTI_PHISHING_BYTES
        || request.mnemonic.is_empty()
        || request.mnemonic.len() > MAX_MNEMONIC_BYTES
        || !is_canonical_mnemonic(&request.mnemonic, request.word_count)
    {
        return Err(SecretInputError::Malformed);
    }
    Ok(())
}

fn validate_confirm(request: &RecoveryConfirmRequest) -> Result<(), SecretInputError> {
    if !is_safe_anti_phishing_phrase(&request.anti_phishing_phrase)
        || request.anti_phishing_phrase.len() > MAX_ANTI_PHISHING_BYTES
    {
        return Err(SecretInputError::Malformed);
    }
    let mut previous = 0_u8;
    for position in request.positions {
        if position <= previous || position > request.word_count.get() {
            return Err(SecretInputError::Malformed);
        }
        previous = position;
    }
    Ok(())
}

fn is_canonical_mnemonic(value: &str, word_count: RecoveryWordCount) -> bool {
    let mut count = 0_usize;
    for word in value.split(' ') {
        if !is_canonical_word(word) {
            return false;
        }
        count = count.saturating_add(1);
    }
    count == usize::from(word_count.get())
}

fn is_canonical_word(value: &str) -> bool {
    (1..=MAX_BIP39_WORD_BYTES).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_lowercase())
}

fn owned_zeroizing_utf8(bytes: &[u8]) -> Result<Zeroizing<String>, SecretInputError> {
    let value = core::str::from_utf8(bytes).map_err(|_| SecretInputError::Malformed)?;
    let mut owned = Zeroizing::new(String::with_capacity(value.len()));
    owned.push_str(value);
    if owned.len() != value.len() || owned.capacity() != value.len() {
        return Err(SecretInputError::Malformed);
    }
    Ok(owned)
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    const fn remaining(&self) -> usize {
        self.remaining.len()
    }

    fn take_slice(&mut self, length: usize) -> Result<&'a [u8], SecretInputError> {
        if self.remaining.len() < length {
            return Err(SecretInputError::Malformed);
        }
        let (value, rest) = self.remaining.split_at(length);
        self.remaining = rest;
        Ok(value)
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], SecretInputError> {
        self.take_slice(N)?
            .try_into()
            .map_err(|_| SecretInputError::Malformed)
    }

    fn read_u8(&mut self) -> Result<u8, SecretInputError> {
        self.take::<1>().map(|value| value[0])
    }

    fn read_u16(&mut self) -> Result<u16, SecretInputError> {
        self.take::<2>().map(u16::from_be_bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor as IoCursor;

    use zeroize::Zeroizing;

    use super::{
        MAX_RECOVERY_REQUEST_BYTES, MAX_RECOVERY_RESPONSE_BYTES, RECOVERY_CEREMONY_ID_BYTES,
        REQUEST_HEADER_BYTES, RecoveryCeremonyId, RecoveryConfirmRequest,
        RecoveryConfirmationInput, RecoveryDisplayRequest, RecoveryOutcome, RecoveryRequest,
        RecoveryWordCount, decode_outcome, decode_request, encode_outcome, encode_request,
        read_outcome, read_request,
    };

    const TEST_CEREMONY_BYTE: u8 = 0x21;

    fn anti() -> Zeroizing<String> {
        Zeroizing::new("amber cedar moon river sage".to_owned())
    }

    fn mnemonic(count: RecoveryWordCount) -> Zeroizing<String> {
        let words = match count {
            RecoveryWordCount::Twelve => 12,
            RecoveryWordCount::TwentyFour => 24,
        };
        Zeroizing::new(
            (0..words)
                .map(|index| if index % 2 == 0 { "apple" } else { "breeze" })
                .collect::<Vec<_>>()
                .join(" "),
        )
    }

    fn ceremony(byte: u8) -> RecoveryCeremonyId {
        RecoveryCeremonyId::from_bytes([byte; RECOVERY_CEREMONY_ID_BYTES])
            .unwrap_or_else(|_| unreachable!("valid ceremony fixture"))
    }

    fn display(count: RecoveryWordCount) -> RecoveryRequest {
        let ceremony_id = ceremony(TEST_CEREMONY_BYTE);
        RecoveryRequest::Display(
            RecoveryDisplayRequest::new(&ceremony_id, anti(), count, [0x31; 20], mnemonic(count))
                .unwrap_or_else(|_| unreachable!("valid display fixture")),
        )
    }

    fn confirm() -> RecoveryRequest {
        let ceremony_id = ceremony(TEST_CEREMONY_BYTE);
        RecoveryRequest::Confirm(
            RecoveryConfirmRequest::new(
                &ceremony_id,
                anti(),
                RecoveryWordCount::Twelve,
                [1, 4, 8, 12],
            )
            .unwrap_or_else(|_| unreachable!("valid confirmation fixture")),
        )
    }

    fn confirmation() -> RecoveryOutcome {
        let words =
            ["apple", "breeze", "cedar", "dune"].map(|word| Zeroizing::new(word.to_owned()));
        RecoveryOutcome::Confirmed(
            RecoveryConfirmationInput::new(words, [0x42; 20])
                .unwrap_or_else(|_| unreachable!("valid response fixture")),
        )
    }

    #[test]
    fn twelve_and_twenty_four_word_display_requests_round_trip() {
        let expected = ceremony(TEST_CEREMONY_BYTE);
        for count in [RecoveryWordCount::Twelve, RecoveryWordCount::TwentyFour] {
            let request = display(count);
            let encoded = encode_request(&request).unwrap_or_else(|_| unreachable!("encode"));
            assert!(encoded.len() <= MAX_RECOVERY_REQUEST_BYTES);
            let decoded = decode_request(encoded).unwrap_or_else(|_| unreachable!("decode"));
            let RecoveryRequest::Display(decoded) = decoded else {
                unreachable!("display changed stage")
            };
            assert!(decoded.matches_ceremony(&expected));
        }
    }

    #[test]
    fn ceremony_id_is_nonzero_opaque_and_constant_time_comparable() {
        assert!(RecoveryCeremonyId::from_bytes([0; RECOVERY_CEREMONY_ID_BYTES]).is_err());
        let first = ceremony(0x41);
        let same = ceremony(0x41);
        let different = ceremony(0x42);
        assert!(first.matches(&same));
        assert!(!first.matches(&different));
        let rendered = format!("{first:?}");
        assert_eq!(rendered, "RecoveryCeremonyId([REDACTED])");
        assert!(!rendered.contains("65"));
    }

    #[test]
    fn ceremony_id_bits_are_canonical_request_data_and_zero_is_rejected() {
        let expected = ceremony(TEST_CEREMONY_BYTE);
        for request in [display(RecoveryWordCount::Twelve), confirm()] {
            let encoded = encode_request(&request).unwrap_or_else(|_| unreachable!("encode"));
            let ceremony_start = REQUEST_HEADER_BYTES + 6;
            let ceremony_end = ceremony_start + RECOVERY_CEREMONY_ID_BYTES;

            let mut mutated = encoded.to_vec();
            mutated[ceremony_start] ^= 1;
            let decoded = decode_request(Zeroizing::new(mutated))
                .unwrap_or_else(|_| unreachable!("nonzero ceremony mutation remains canonical"));
            let matches = match decoded {
                RecoveryRequest::Display(request) => request.matches_ceremony(&expected),
                RecoveryRequest::Confirm(request) => request.matches_ceremony(&expected),
            };
            assert!(!matches);

            let mut zero = encoded.to_vec();
            zero[ceremony_start..ceremony_end].fill(0);
            assert!(decode_request(Zeroizing::new(zero)).is_err());
        }
    }

    #[test]
    fn confirmation_request_contains_no_expected_words_or_address() {
        let request = confirm();
        let encoded = encode_request(&request).unwrap_or_else(|_| unreachable!("encode"));
        assert!(!encoded.windows(5).any(|window| window == b"apple"));
        assert!(!encoded.windows(20).any(|window| window == [0x42; 20]));
        let decoded = decode_request(encoded).unwrap_or_else(|_| unreachable!("decode"));
        assert!(matches!(decoded, RecoveryRequest::Confirm(_)));
    }

    #[test]
    fn exact_confirmation_response_round_trips_and_consumes_secrets() {
        let request = confirm();
        let encoded =
            encode_outcome(&request, &confirmation()).unwrap_or_else(|_| unreachable!("encode"));
        assert!(encoded.len() <= MAX_RECOVERY_RESPONSE_BYTES);
        let decoded = decode_outcome(&request, encoded).unwrap_or_else(|_| unreachable!("decode"));
        let RecoveryOutcome::Confirmed(input) = decoded else {
            unreachable!("confirmed outcome")
        };
        let (words, address) = input.into_parts();
        assert_eq!(words[0].as_str(), "apple");
        assert_eq!(words[3].as_str(), "dune");
        assert_eq!(address, [0x42; 20]);
    }

    #[test]
    fn cancellation_and_acknowledgement_are_stage_specific() {
        let display = display(RecoveryWordCount::Twelve);
        let confirm = confirm();
        for outcome in [
            RecoveryOutcome::DisplayAcknowledged,
            RecoveryOutcome::DisplayCancelled,
        ] {
            let encoded = encode_outcome(&display, &outcome)
                .unwrap_or_else(|_| unreachable!("display outcome"));
            assert!(decode_outcome(&display, encoded).is_ok());
        }
        let encoded = encode_outcome(&confirm, &RecoveryOutcome::ConfirmCancelled)
            .unwrap_or_else(|_| unreachable!("confirm cancel"));
        assert!(decode_outcome(&confirm, encoded).is_ok());
        assert!(encode_outcome(&confirm, &RecoveryOutcome::DisplayAcknowledged).is_err());
        assert!(encode_outcome(&display, &confirmation()).is_err());
    }

    #[test]
    fn every_request_truncation_and_trailing_byte_is_rejected() {
        for request in [display(RecoveryWordCount::Twelve), confirm()] {
            let encoded = encode_request(&request).unwrap_or_else(|_| unreachable!("encode"));
            for length in 0..encoded.len() {
                assert!(decode_request(Zeroizing::new(encoded[..length].to_vec())).is_err());
            }
            let mut trailing = encoded.to_vec();
            trailing.push(0);
            assert!(decode_request(Zeroizing::new(trailing)).is_err());
        }
    }

    #[test]
    fn every_response_truncation_and_trailing_byte_is_rejected() {
        let request = confirm();
        let encoded =
            encode_outcome(&request, &confirmation()).unwrap_or_else(|_| unreachable!("encode"));
        for length in 0..encoded.len() {
            assert!(decode_outcome(&request, Zeroizing::new(encoded[..length].to_vec())).is_err());
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(decode_outcome(&request, Zeroizing::new(trailing)).is_err());
    }

    #[test]
    fn invalid_profiles_positions_and_words_fail_closed() {
        let ceremony_id = ceremony(TEST_CEREMONY_BYTE);
        assert!(
            RecoveryConfirmRequest::new(
                &ceremony_id,
                anti(),
                RecoveryWordCount::Twelve,
                [1, 1, 8, 12]
            )
            .is_err()
        );
        assert!(
            RecoveryConfirmRequest::new(
                &ceremony_id,
                anti(),
                RecoveryWordCount::Twelve,
                [1, 4, 13, 12]
            )
            .is_err()
        );
        assert!(
            RecoveryDisplayRequest::new(
                &ceremony_id,
                anti(),
                RecoveryWordCount::Twelve,
                [0x31; 20],
                Zeroizing::new("Apple breeze".to_owned()),
            )
            .is_err()
        );
        assert!(
            RecoveryConfirmationInput::new(
                ["apple", "Breeze", "cedar", "dune"]
                    .map(|word| { Zeroizing::new(word.to_owned()) }),
                [0x42; 20],
            )
            .is_err()
        );
    }

    #[test]
    fn reserved_profile_and_kind_mutations_are_rejected() {
        let request = display(RecoveryWordCount::Twelve);
        let encoded = encode_request(&request).unwrap_or_else(|_| unreachable!("encode"));
        for index in [10_usize, 11, 16, 17, 18, 19] {
            let mut mutated = encoded.to_vec();
            mutated[index] ^= 0x7f;
            assert!(decode_request(Zeroizing::new(mutated)).is_err());
        }
    }

    #[test]
    fn bounded_readers_require_exact_eof() {
        let request = confirm();
        let encoded = encode_request(&request).unwrap_or_else(|_| unreachable!("encode"));
        assert!(read_request(&mut IoCursor::new(encoded.to_vec())).is_ok());
        let outcome = encode_outcome(&request, &RecoveryOutcome::ConfirmCancelled)
            .unwrap_or_else(|_| unreachable!("encode"));
        assert!(read_outcome(&mut IoCursor::new(outcome.to_vec()), &request).is_ok());
        assert!(
            read_request(&mut IoCursor::new(vec![
                0_u8;
                MAX_RECOVERY_REQUEST_BYTES + 1
            ]))
            .is_err()
        );
        assert!(
            read_outcome(
                &mut IoCursor::new(vec![0_u8; MAX_RECOVERY_RESPONSE_BYTES + 1]),
                &request,
            )
            .is_err()
        );
    }

    #[test]
    fn debug_output_is_redacted() {
        let display = display(RecoveryWordCount::Twelve);
        let confirmation = confirmation();
        let rendered = format!("{display:?} {confirmation:?}");
        assert!(rendered.contains("REDACTED"));
        assert!(rendered.contains("ceremony_id: \"[REDACTED]\""));
        assert!(!rendered.contains("apple"));
        assert!(!rendered.contains("amber"));
    }
}
