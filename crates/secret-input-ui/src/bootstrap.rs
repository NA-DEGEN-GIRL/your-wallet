//! Child-side authentication for the one-shot Secret Input process.
//!
//! The native prompt is unreachable until this module has verified the helper's
//! own sandbox, both inherited pipe endpoints, a live held parent process, and
//! an independently compiled Key Agent artifact policy. The compiled policy is
//! deliberately absent in development builds, so even an opt-in runtime binary
//! fails before presenting UI.

use core::fmt;
use std::io::Write;

use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use super::{
    MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, SecretInputError, SecretOutcome, SecretPrompt,
    decode_outcome, decode_prompt, encode_prompt, write_outcome,
};
use crate::recovery::{
    MAX_RECOVERY_REQUEST_BYTES, MAX_RECOVERY_RESPONSE_BYTES, RecoveryOutcome, RecoveryRequest,
    decode_outcome as decode_recovery_outcome, decode_request as decode_recovery_request,
    encode_outcome as encode_recovery_outcome, encode_request as encode_recovery_request,
};

const VERSION: u16 = 1;
const PARENT_HELLO_MAGIC: &[u8; 8] = b"YWSBPH01";
const CHILD_HELLO_MAGIC: &[u8; 8] = b"YWSBCH01";
const PARENT_FINISH_MAGIC: &[u8; 8] = b"YWSBPF01";
const OUTCOME_MAGIC: &[u8; 8] = b"YWSBOR01";
const RECOVERY_DISPLAY_PARENT_HELLO_MAGIC: &[u8; 8] = b"YWRDPH01";
const RECOVERY_CONFIRM_PARENT_HELLO_MAGIC: &[u8; 8] = b"YWRCPH01";
const RECOVERY_DISPLAY_CHILD_HELLO_MAGIC: &[u8; 8] = b"YWRDCH01";
const RECOVERY_CONFIRM_CHILD_HELLO_MAGIC: &[u8; 8] = b"YWRCCH01";
const RECOVERY_DISPLAY_PARENT_FINISH_MAGIC: &[u8; 8] = b"YWRDPF01";
const RECOVERY_CONFIRM_PARENT_FINISH_MAGIC: &[u8; 8] = b"YWRCPF01";
const RECOVERY_DISPLAY_OUTCOME_MAGIC: &[u8; 8] = b"YWRDOR01";
const RECOVERY_CONFIRM_OUTCOME_MAGIC: &[u8; 8] = b"YWRCOR01";
const CHILD_TRANSCRIPT_DOMAIN: &[u8] = b"your-wallet/secret-input-bootstrap-child/v1\0";
const RECOVERY_DISPLAY_CHILD_TRANSCRIPT_DOMAIN: &[u8] =
    b"your-wallet/recovery-display-bootstrap-child/v1\0";
const RECOVERY_CONFIRM_CHILD_TRANSCRIPT_DOMAIN: &[u8] =
    b"your-wallet/recovery-confirm-bootstrap-child/v1\0";
const PROMPT_DOMAIN: &[u8] = b"your-wallet/secret-input-bootstrap-prompt/v1\0";
const RECOVERY_DISPLAY_REQUEST_DOMAIN: &[u8] =
    b"your-wallet/recovery-display-bootstrap-request/v1\0";
const RECOVERY_CONFIRM_REQUEST_DOMAIN: &[u8] =
    b"your-wallet/recovery-confirm-bootstrap-request/v1\0";

/// Size of each fresh bootstrap nonce.
pub const NONCE_BYTES: usize = 32;
/// Exact byte length of a parent hello.
pub const PARENT_HELLO_BYTES: usize = 8 + 2 + 4 + 8 + 8 + NONCE_BYTES;
/// Exact byte length of a child hello.
pub const CHILD_HELLO_BYTES: usize = 8 + 2 + NONCE_BYTES + NONCE_BYTES + 32;
const PARENT_FINISH_HEADER_BYTES: usize = 8 + 2 + NONCE_BYTES + NONCE_BYTES + 32 + 2;
const OUTCOME_HEADER_BYTES: usize = 8 + 2 + NONCE_BYTES + NONCE_BYTES + 32 + 4;
/// Maximum authenticated response, including its non-secret binding envelope.
pub const MAX_AUTHENTICATED_RESPONSE_BYTES: usize = OUTCOME_HEADER_BYTES + MAX_RESPONSE_BYTES;
/// Maximum authenticated recovery response, including its binding envelope.
pub const MAX_AUTHENTICATED_RECOVERY_RESPONSE_BYTES: usize =
    OUTCOME_HEADER_BYTES + MAX_RECOVERY_RESPONSE_BYTES;

/// Exact recovery ceremony carried by one fresh authenticated child process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoverySessionKind {
    /// Show the generated phrase and first address without challenge positions.
    Display,
    /// Collect four challenged words and the independently retained address.
    Confirm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BootstrapKind {
    SecretInput,
    Recovery(RecoverySessionKind),
}

/// The first fixed-width frame sent by the Key Agent.
///
/// Handle values refer only to handles explicitly inherited into this child.
/// The values are never accepted as identity without kernel-object, pipe-peer,
/// and compiled artifact-policy verification in the child.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ParentHello {
    process_id: u32,
    process_handle: u64,
    image_handle: u64,
    parent_nonce: [u8; NONCE_BYTES],
}

impl ParentHello {
    /// Creates a bounded parent hello for the restricted launcher.
    pub fn new(
        process_id: u32,
        process_handle: u64,
        image_handle: u64,
        parent_nonce: [u8; NONCE_BYTES],
    ) -> Result<Self, SecretInputError> {
        if process_id == 0
            || process_handle == 0
            || image_handle == 0
            || process_handle == image_handle
            || is_all_zero(&parent_nonce)
        {
            return Err(SecretInputError::Malformed);
        }
        Ok(Self {
            process_id,
            process_handle,
            image_handle,
            parent_nonce,
        })
    }

    /// Returns the fresh parent nonce.
    #[must_use]
    pub const fn parent_nonce(&self) -> [u8; NONCE_BYTES] {
        self.parent_nonce
    }
}

impl fmt::Debug for ParentHello {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ParentHello([REDACTED HANDLES AND NONCE])")
    }
}

/// Verified child-half of the bootstrap exchange.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ChildHello {
    child_nonce: [u8; NONCE_BYTES],
}

impl ChildHello {
    /// Returns the fresh child nonce after transcript verification.
    #[must_use]
    pub const fn child_nonce(&self) -> [u8; NONCE_BYTES] {
        self.child_nonce
    }
}

impl fmt::Debug for ChildHello {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChildHello([VERIFIED REDACTED NONCE])")
    }
}

/// Non-cloneable proof that child-side parent authentication finished before UI.
pub struct AuthenticatedSession {
    prompt: SecretPrompt,
    prompt_hash: [u8; 32],
    parent_nonce: Zeroizing<[u8; NONCE_BYTES]>,
    child_nonce: Zeroizing<[u8; NONCE_BYTES]>,
}

/// Non-cloneable proof that a typed recovery request came from the verified parent.
pub struct AuthenticatedRecoverySession {
    request: RecoveryRequest,
    request_hash: [u8; 32],
    parent_nonce: Zeroizing<[u8; NONCE_BYTES]>,
    child_nonce: Zeroizing<[u8; NONCE_BYTES]>,
}

impl AuthenticatedRecoverySession {
    pub(crate) const fn request(&self) -> &RecoveryRequest {
        &self.request
    }

    const fn kind(&self) -> RecoverySessionKind {
        recovery_session_kind(&self.request)
    }
}

impl fmt::Debug for AuthenticatedRecoverySession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedRecoverySession([REDACTED ONE-SHOT CAPABILITY])")
    }
}

impl AuthenticatedSession {
    pub(crate) const fn prompt(&self) -> &SecretPrompt {
        &self.prompt
    }
}

impl fmt::Debug for AuthenticatedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedSession([REDACTED ONE-SHOT CAPABILITY])")
    }
}

/// The only request capability that the helper runtime may dispatch.
///
/// Values can be constructed only after child-side parent, channel, artifact,
/// nonce, and exact request verification has completed.
pub enum AuthenticatedRequestSession {
    /// A normal password, passphrase, mnemonic-import, or raw-key prompt.
    Secret(AuthenticatedSession),
    /// One isolated display or confirmation stage of wallet recovery.
    Recovery(AuthenticatedRecoverySession),
}

impl fmt::Debug for AuthenticatedRequestSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Secret(_) => "AuthenticatedRequestSession::Secret([REDACTED CAPABILITY])",
            Self::Recovery(_) => "AuthenticatedRequestSession::Recovery([REDACTED CAPABILITY])",
        })
    }
}

/// Encodes a fixed-width parent hello.
#[must_use]
pub fn encode_parent_hello(hello: &ParentHello) -> Zeroizing<Vec<u8>> {
    encode_parent_hello_for(BootstrapKind::SecretInput, hello)
}

/// Encodes the stage-specific parent hello for one recovery child process.
#[must_use]
pub fn encode_recovery_parent_hello(
    kind: RecoverySessionKind,
    hello: &ParentHello,
) -> Zeroizing<Vec<u8>> {
    encode_parent_hello_for(BootstrapKind::Recovery(kind), hello)
}

fn encode_parent_hello_for(kind: BootstrapKind, hello: &ParentHello) -> Zeroizing<Vec<u8>> {
    let mut output = Zeroizing::new(Vec::with_capacity(PARENT_HELLO_BYTES));
    output.extend_from_slice(parent_hello_magic(kind));
    output.extend_from_slice(&VERSION.to_be_bytes());
    output.extend_from_slice(&hello.process_id.to_be_bytes());
    output.extend_from_slice(&hello.process_handle.to_be_bytes());
    output.extend_from_slice(&hello.image_handle.to_be_bytes());
    output.extend_from_slice(&hello.parent_nonce);
    output
}

fn decode_parent_hello(bytes: &[u8]) -> Result<(BootstrapKind, ParentHello), SecretInputError> {
    if bytes.len() != PARENT_HELLO_BYTES || u16::from_be_bytes(array(&bytes[8..10])?) != VERSION {
        return Err(SecretInputError::Malformed);
    }
    let kind = bootstrap_kind_from_parent_magic(array(&bytes[..8])?)?;
    let hello = ParentHello::new(
        u32::from_be_bytes(array(&bytes[10..14])?),
        u64::from_be_bytes(array(&bytes[14..22])?),
        u64::from_be_bytes(array(&bytes[22..30])?),
        array(&bytes[30..62])?,
    )?;
    Ok((kind, hello))
}

fn child_transcript(
    kind: BootstrapKind,
    parent_hello: &[u8],
    child_nonce: &[u8; NONCE_BYTES],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(child_transcript_domain(kind));
    hash.update(parent_hello);
    hash.update(child_nonce);
    hash.finalize().into()
}

fn encode_child_hello(
    kind: BootstrapKind,
    parent_hello: &[u8],
    parent_nonce: &[u8; NONCE_BYTES],
    child_nonce: &[u8; NONCE_BYTES],
) -> Zeroizing<Vec<u8>> {
    let mut output = Zeroizing::new(Vec::with_capacity(CHILD_HELLO_BYTES));
    output.extend_from_slice(child_hello_magic(kind));
    output.extend_from_slice(&VERSION.to_be_bytes());
    output.extend_from_slice(parent_nonce);
    output.extend_from_slice(child_nonce);
    output.extend_from_slice(&child_transcript(kind, parent_hello, child_nonce));
    output
}

/// Decodes and verifies the child's exact response to one parent hello.
pub fn decode_child_hello(
    parent_hello: &ParentHello,
    bytes: &[u8],
) -> Result<ChildHello, SecretInputError> {
    decode_child_hello_for(BootstrapKind::SecretInput, parent_hello, bytes)
}

/// Decodes a child hello only for the exact recovery stage that was launched.
pub fn decode_recovery_child_hello(
    kind: RecoverySessionKind,
    parent_hello: &ParentHello,
    bytes: &[u8],
) -> Result<ChildHello, SecretInputError> {
    decode_child_hello_for(BootstrapKind::Recovery(kind), parent_hello, bytes)
}

fn decode_child_hello_for(
    kind: BootstrapKind,
    parent_hello: &ParentHello,
    bytes: &[u8],
) -> Result<ChildHello, SecretInputError> {
    if bytes.len() != CHILD_HELLO_BYTES
        || bytes.get(..8) != Some(child_hello_magic(kind).as_slice())
        || u16::from_be_bytes(array(&bytes[8..10])?) != VERSION
        || !bool::from(bytes[10..42].ct_eq(&parent_hello.parent_nonce))
    {
        return Err(SecretInputError::Malformed);
    }
    let child_nonce: [u8; NONCE_BYTES] = array(&bytes[42..74])?;
    if is_all_zero(&child_nonce) {
        return Err(SecretInputError::Malformed);
    }
    let encoded_parent = encode_parent_hello_for(kind, parent_hello);
    let expected = child_transcript(kind, &encoded_parent, &child_nonce);
    if !bool::from(bytes[74..106].ct_eq(&expected)) {
        return Err(SecretInputError::Malformed);
    }
    Ok(ChildHello { child_nonce })
}

const fn parent_hello_magic(kind: BootstrapKind) -> &'static [u8; 8] {
    match kind {
        BootstrapKind::SecretInput => PARENT_HELLO_MAGIC,
        BootstrapKind::Recovery(RecoverySessionKind::Display) => {
            RECOVERY_DISPLAY_PARENT_HELLO_MAGIC
        }
        BootstrapKind::Recovery(RecoverySessionKind::Confirm) => {
            RECOVERY_CONFIRM_PARENT_HELLO_MAGIC
        }
    }
}

const fn child_hello_magic(kind: BootstrapKind) -> &'static [u8; 8] {
    match kind {
        BootstrapKind::SecretInput => CHILD_HELLO_MAGIC,
        BootstrapKind::Recovery(RecoverySessionKind::Display) => RECOVERY_DISPLAY_CHILD_HELLO_MAGIC,
        BootstrapKind::Recovery(RecoverySessionKind::Confirm) => RECOVERY_CONFIRM_CHILD_HELLO_MAGIC,
    }
}

const fn child_transcript_domain(kind: BootstrapKind) -> &'static [u8] {
    match kind {
        BootstrapKind::SecretInput => CHILD_TRANSCRIPT_DOMAIN,
        BootstrapKind::Recovery(RecoverySessionKind::Display) => {
            RECOVERY_DISPLAY_CHILD_TRANSCRIPT_DOMAIN
        }
        BootstrapKind::Recovery(RecoverySessionKind::Confirm) => {
            RECOVERY_CONFIRM_CHILD_TRANSCRIPT_DOMAIN
        }
    }
}

fn bootstrap_kind_from_parent_magic(magic: [u8; 8]) -> Result<BootstrapKind, SecretInputError> {
    if magic == *PARENT_HELLO_MAGIC {
        Ok(BootstrapKind::SecretInput)
    } else if magic == *RECOVERY_DISPLAY_PARENT_HELLO_MAGIC {
        Ok(BootstrapKind::Recovery(RecoverySessionKind::Display))
    } else if magic == *RECOVERY_CONFIRM_PARENT_HELLO_MAGIC {
        Ok(BootstrapKind::Recovery(RecoverySessionKind::Confirm))
    } else {
        Err(SecretInputError::Malformed)
    }
}

fn prompt_hash(prompt_bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(PROMPT_DOMAIN);
    hash.update(
        u32::try_from(prompt_bytes.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    hash.update(prompt_bytes);
    hash.finalize().into()
}

fn recovery_request_hash(kind: RecoverySessionKind, request_bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(recovery_request_domain(kind));
    hash.update(
        u32::try_from(request_bytes.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    hash.update(request_bytes);
    hash.finalize().into()
}

const fn recovery_session_kind(request: &RecoveryRequest) -> RecoverySessionKind {
    match request {
        RecoveryRequest::Display(_) => RecoverySessionKind::Display,
        RecoveryRequest::Confirm(_) => RecoverySessionKind::Confirm,
    }
}

const fn recovery_request_domain(kind: RecoverySessionKind) -> &'static [u8] {
    match kind {
        RecoverySessionKind::Display => RECOVERY_DISPLAY_REQUEST_DOMAIN,
        RecoverySessionKind::Confirm => RECOVERY_CONFIRM_REQUEST_DOMAIN,
    }
}

const fn recovery_parent_finish_magic(kind: RecoverySessionKind) -> &'static [u8; 8] {
    match kind {
        RecoverySessionKind::Display => RECOVERY_DISPLAY_PARENT_FINISH_MAGIC,
        RecoverySessionKind::Confirm => RECOVERY_CONFIRM_PARENT_FINISH_MAGIC,
    }
}

const fn recovery_outcome_magic(kind: RecoverySessionKind) -> &'static [u8; 8] {
    match kind {
        RecoverySessionKind::Display => RECOVERY_DISPLAY_OUTCOME_MAGIC,
        RecoverySessionKind::Confirm => RECOVERY_CONFIRM_OUTCOME_MAGIC,
    }
}

/// Encodes the exact prompt only after both bootstrap nonces exist.
pub fn encode_parent_finish(
    prompt: &SecretPrompt,
    parent_nonce: &[u8; NONCE_BYTES],
    child_nonce: &[u8; NONCE_BYTES],
) -> Result<Zeroizing<Vec<u8>>, SecretInputError> {
    if is_all_zero(parent_nonce) || is_all_zero(child_nonce) {
        return Err(SecretInputError::Malformed);
    }
    let prompt_bytes = Zeroizing::new(encode_prompt(prompt)?);
    let prompt_length =
        u16::try_from(prompt_bytes.len()).map_err(|_| SecretInputError::Malformed)?;
    let mut output = Zeroizing::new(Vec::with_capacity(
        PARENT_FINISH_HEADER_BYTES.saturating_add(prompt_bytes.len()),
    ));
    output.extend_from_slice(PARENT_FINISH_MAGIC);
    output.extend_from_slice(&VERSION.to_be_bytes());
    output.extend_from_slice(parent_nonce);
    output.extend_from_slice(child_nonce);
    output.extend_from_slice(&prompt_hash(&prompt_bytes));
    output.extend_from_slice(&prompt_length.to_be_bytes());
    output.extend_from_slice(&prompt_bytes);
    Ok(output)
}

fn decode_parent_finish(
    bytes: &[u8],
    expected_parent_nonce: &[u8; NONCE_BYTES],
    expected_child_nonce: &[u8; NONCE_BYTES],
) -> Result<(SecretPrompt, [u8; 32]), SecretInputError> {
    if bytes.len() < PARENT_FINISH_HEADER_BYTES
        || &bytes[..8] != PARENT_FINISH_MAGIC
        || u16::from_be_bytes(array(&bytes[8..10])?) != VERSION
        || !bool::from(bytes[10..42].ct_eq(expected_parent_nonce))
        || !bool::from(bytes[42..74].ct_eq(expected_child_nonce))
    {
        return Err(SecretInputError::Malformed);
    }
    let expected_hash: [u8; 32] = array(&bytes[74..106])?;
    let prompt_length = usize::from(u16::from_be_bytes(array(&bytes[106..108])?));
    if prompt_length
        > usize::try_from(MAX_REQUEST_BYTES).map_err(|_| SecretInputError::Malformed)?
        || bytes.len() != PARENT_FINISH_HEADER_BYTES.saturating_add(prompt_length)
    {
        return Err(SecretInputError::Malformed);
    }
    let actual_hash = prompt_hash(&bytes[PARENT_FINISH_HEADER_BYTES..]);
    if is_all_zero(&expected_hash) || !bool::from(actual_hash.ct_eq(&expected_hash)) {
        return Err(SecretInputError::Malformed);
    }
    let prompt = decode_prompt(&bytes[PARENT_FINISH_HEADER_BYTES..])?;
    Ok((prompt, actual_hash))
}

/// Encodes one exact recovery request after both bootstrap nonces exist.
pub fn encode_recovery_parent_finish(
    request: &RecoveryRequest,
    parent_nonce: &[u8; NONCE_BYTES],
    child_nonce: &[u8; NONCE_BYTES],
) -> Result<Zeroizing<Vec<u8>>, SecretInputError> {
    if is_all_zero(parent_nonce) || is_all_zero(child_nonce) {
        return Err(SecretInputError::Malformed);
    }
    let kind = recovery_session_kind(request);
    let request_bytes = encode_recovery_request(request)?;
    let request_length =
        u16::try_from(request_bytes.len()).map_err(|_| SecretInputError::Malformed)?;
    let total = PARENT_FINISH_HEADER_BYTES
        .checked_add(request_bytes.len())
        .ok_or(SecretInputError::Malformed)?;
    let mut output = Zeroizing::new(Vec::with_capacity(total));
    output.extend_from_slice(recovery_parent_finish_magic(kind));
    output.extend_from_slice(&VERSION.to_be_bytes());
    output.extend_from_slice(parent_nonce);
    output.extend_from_slice(child_nonce);
    output.extend_from_slice(&recovery_request_hash(kind, &request_bytes));
    output.extend_from_slice(&request_length.to_be_bytes());
    output.extend_from_slice(&request_bytes);
    if output.len() != total || output.capacity() != total {
        return Err(SecretInputError::Malformed);
    }
    Ok(output)
}

#[allow(clippy::needless_pass_by_value)] // Ownership zeroizes the complete recovery frame.
fn decode_recovery_parent_finish(
    bytes: Zeroizing<Vec<u8>>,
    expected_kind: RecoverySessionKind,
    expected_parent_nonce: &[u8; NONCE_BYTES],
    expected_child_nonce: &[u8; NONCE_BYTES],
) -> Result<(RecoveryRequest, [u8; 32]), SecretInputError> {
    if bytes.len() < PARENT_FINISH_HEADER_BYTES
        || bytes.len()
            > PARENT_FINISH_HEADER_BYTES
                .checked_add(MAX_RECOVERY_REQUEST_BYTES)
                .ok_or(SecretInputError::Malformed)?
        || bytes.get(..8) != Some(recovery_parent_finish_magic(expected_kind).as_slice())
        || u16::from_be_bytes(array(&bytes[8..10])?) != VERSION
        || !bool::from(bytes[10..42].ct_eq(expected_parent_nonce))
        || !bool::from(bytes[42..74].ct_eq(expected_child_nonce))
    {
        return Err(SecretInputError::Malformed);
    }
    let expected_hash: [u8; 32] = array(&bytes[74..106])?;
    let request_length = usize::from(u16::from_be_bytes(array(&bytes[106..108])?));
    if request_length > MAX_RECOVERY_REQUEST_BYTES
        || bytes.len()
            != PARENT_FINISH_HEADER_BYTES
                .checked_add(request_length)
                .ok_or(SecretInputError::Malformed)?
    {
        return Err(SecretInputError::Malformed);
    }
    let request_bytes = &bytes[PARENT_FINISH_HEADER_BYTES..];
    let actual_hash = recovery_request_hash(expected_kind, request_bytes);
    if is_all_zero(&expected_hash) || !bool::from(actual_hash.ct_eq(&expected_hash)) {
        return Err(SecretInputError::Malformed);
    }
    let request = decode_recovery_request(Zeroizing::new(request_bytes.to_vec()))?;
    if recovery_session_kind(&request) != expected_kind {
        return Err(SecretInputError::Malformed);
    }
    Ok((request, actual_hash))
}

/// Writes the final outcome bound to both fresh nonces and the exact prompt.
#[allow(clippy::needless_pass_by_value)] // Consuming the capability enforces one-shot use.
pub fn write_authenticated_outcome(
    writer: &mut impl Write,
    session: AuthenticatedSession,
    outcome: SecretOutcome,
) -> Result<(), SecretInputError> {
    let mut inner = Zeroizing::new(Vec::with_capacity(MAX_RESPONSE_BYTES));
    write_outcome(&mut *inner, outcome)?;
    let inner_length = u32::try_from(inner.len()).map_err(|_| SecretInputError::Malformed)?;
    let mut envelope = Zeroizing::new(Vec::with_capacity(
        OUTCOME_HEADER_BYTES.saturating_add(inner.len()),
    ));
    envelope.extend_from_slice(OUTCOME_MAGIC);
    envelope.extend_from_slice(&VERSION.to_be_bytes());
    envelope.extend_from_slice(&*session.parent_nonce);
    envelope.extend_from_slice(&*session.child_nonce);
    envelope.extend_from_slice(&session.prompt_hash);
    envelope.extend_from_slice(&inner_length.to_be_bytes());
    envelope.extend_from_slice(&inner);
    writer.write_all(&envelope)?;
    writer.flush().map_err(Into::into)
}

/// Decodes a final outcome only when both nonces and the exact prompt match.
#[allow(clippy::needless_pass_by_value)] // Ownership keeps the complete frame zeroizing.
pub fn decode_authenticated_outcome(
    prompt: &SecretPrompt,
    expected_parent_nonce: &[u8; NONCE_BYTES],
    expected_child_nonce: &[u8; NONCE_BYTES],
    bytes: Zeroizing<Vec<u8>>,
) -> Result<SecretOutcome, SecretInputError> {
    if bytes.len() < OUTCOME_HEADER_BYTES
        || bytes.len() > MAX_AUTHENTICATED_RESPONSE_BYTES
        || &bytes[..8] != OUTCOME_MAGIC
        || u16::from_be_bytes(array(&bytes[8..10])?) != VERSION
        || !bool::from(bytes[10..42].ct_eq(expected_parent_nonce))
        || !bool::from(bytes[42..74].ct_eq(expected_child_nonce))
    {
        return Err(SecretInputError::Malformed);
    }
    let prompt_bytes = Zeroizing::new(encode_prompt(prompt)?);
    let expected_prompt_hash = prompt_hash(&prompt_bytes);
    if !bool::from(bytes[74..106].ct_eq(&expected_prompt_hash)) {
        return Err(SecretInputError::Malformed);
    }
    let inner_length = usize::try_from(u32::from_be_bytes(array(&bytes[106..110])?))
        .map_err(|_| SecretInputError::Malformed)?;
    if inner_length > MAX_RESPONSE_BYTES
        || bytes.len() != OUTCOME_HEADER_BYTES.saturating_add(inner_length)
    {
        return Err(SecretInputError::Malformed);
    }
    let inner = Zeroizing::new(bytes[OUTCOME_HEADER_BYTES..].to_vec());
    decode_outcome(prompt, inner)
}

/// Writes one recovery outcome bound to both nonces and the exact typed request.
#[allow(clippy::needless_pass_by_value)] // Consuming the capability enforces one-shot use.
pub fn write_authenticated_recovery_outcome(
    writer: &mut impl Write,
    session: AuthenticatedRecoverySession,
    outcome: RecoveryOutcome,
) -> Result<(), SecretInputError> {
    let kind = session.kind();
    let inner = encode_recovery_outcome(&session.request, &outcome)?;
    let inner_length = u32::try_from(inner.len()).map_err(|_| SecretInputError::Malformed)?;
    let total = OUTCOME_HEADER_BYTES
        .checked_add(inner.len())
        .ok_or(SecretInputError::Malformed)?;
    let mut envelope = Zeroizing::new(Vec::with_capacity(total));
    envelope.extend_from_slice(recovery_outcome_magic(kind));
    envelope.extend_from_slice(&VERSION.to_be_bytes());
    envelope.extend_from_slice(&*session.parent_nonce);
    envelope.extend_from_slice(&*session.child_nonce);
    envelope.extend_from_slice(&session.request_hash);
    envelope.extend_from_slice(&inner_length.to_be_bytes());
    envelope.extend_from_slice(&inner);
    if envelope.len() != total || envelope.capacity() != total {
        return Err(SecretInputError::Malformed);
    }
    writer.write_all(&envelope)?;
    writer.flush().map_err(Into::into)
}

/// Decodes a recovery outcome only for the exact request and nonce pair.
#[allow(clippy::needless_pass_by_value)] // Ownership keeps the complete frame zeroizing.
pub fn decode_authenticated_recovery_outcome(
    request: &RecoveryRequest,
    expected_parent_nonce: &[u8; NONCE_BYTES],
    expected_child_nonce: &[u8; NONCE_BYTES],
    bytes: Zeroizing<Vec<u8>>,
) -> Result<RecoveryOutcome, SecretInputError> {
    let kind = recovery_session_kind(request);
    if bytes.len() < OUTCOME_HEADER_BYTES
        || bytes.len() > MAX_AUTHENTICATED_RECOVERY_RESPONSE_BYTES
        || bytes.get(..8) != Some(recovery_outcome_magic(kind).as_slice())
        || u16::from_be_bytes(array(&bytes[8..10])?) != VERSION
        || !bool::from(bytes[10..42].ct_eq(expected_parent_nonce))
        || !bool::from(bytes[42..74].ct_eq(expected_child_nonce))
    {
        return Err(SecretInputError::Malformed);
    }
    let request_bytes = encode_recovery_request(request)?;
    let expected_request_hash = recovery_request_hash(kind, &request_bytes);
    if !bool::from(bytes[74..106].ct_eq(&expected_request_hash)) {
        return Err(SecretInputError::Malformed);
    }
    let inner_length = usize::try_from(u32::from_be_bytes(array(&bytes[106..110])?))
        .map_err(|_| SecretInputError::Malformed)?;
    if inner_length > MAX_RECOVERY_RESPONSE_BYTES
        || bytes.len()
            != OUTCOME_HEADER_BYTES
                .checked_add(inner_length)
                .ok_or(SecretInputError::Malformed)?
    {
        return Err(SecretInputError::Malformed);
    }
    let inner = Zeroizing::new(bytes[OUTCOME_HEADER_BYTES..].to_vec());
    decode_recovery_outcome(request, inner)
}

/// Authenticates the inherited Windows parent and performs the nonce exchange.
///
/// Development builds have no compiled parent artifact policy and therefore
/// return before reading a prompt or presenting any UI.
pub fn authenticate_inherited_parent() -> Result<AuthenticatedSession, SecretInputError> {
    match authenticate_inherited_request()? {
        AuthenticatedRequestSession::Secret(session) => Ok(session),
        AuthenticatedRequestSession::Recovery(_) => Err(SecretInputError::Malformed),
    }
}

/// Authenticates and decodes exactly one typed helper request capability.
///
/// Recovery display and confirmation require different hello, transcript,
/// finish, hash, and outcome domains. Each invocation also requires two fresh
/// nonces, so neither stage can be replayed into the other helper process.
///
/// # Errors
///
/// Fails before UI dispatch unless the child sandbox, inherited pipe peers,
/// held parent process, signed parent artifact, stage domain, nonces, and exact
/// bounded request are all verified.
pub fn authenticate_inherited_request() -> Result<AuthenticatedRequestSession, SecretInputError> {
    #[cfg(windows)]
    {
        windows::authenticate_request()
    }
    #[cfg(not(windows))]
    {
        Err(SecretInputError::NativeFailure)
    }
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], SecretInputError> {
    bytes.try_into().map_err(|_| SecretInputError::Malformed)
}

fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(windows)]
mod windows;

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::{
        AuthenticatedRecoverySession, BootstrapKind, CHILD_HELLO_BYTES, ChildHello, ParentHello,
        RecoverySessionKind, decode_authenticated_outcome, decode_authenticated_recovery_outcome,
        decode_child_hello, decode_parent_finish, decode_recovery_child_hello,
        decode_recovery_parent_finish, encode_child_hello, encode_parent_finish,
        encode_parent_hello, encode_recovery_parent_finish, encode_recovery_parent_hello,
    };
    use crate::recovery::{
        RecoveryCeremonyId, RecoveryConfirmRequest, RecoveryDisplayRequest, RecoveryOutcome,
        RecoveryRequest, RecoveryWordCount, encode_request as encode_recovery_request,
    };
    use crate::{PromptKind, SecretOutcome, SecretPrompt};

    fn prompt() -> Result<SecretPrompt, crate::SecretInputError> {
        SecretPrompt::new(PromptKind::UnlockPassword, "blue comet".to_owned())
    }

    fn hello() -> Result<ParentHello, crate::SecretInputError> {
        ParentHello::new(42, 0x100, 0x104, [7; 32])
    }

    fn recovery_display() -> Result<RecoveryRequest, crate::SecretInputError> {
        let ceremony_id = RecoveryCeremonyId::generate()?;
        RecoveryDisplayRequest::new(
            &ceremony_id,
            Zeroizing::new("amber cedar moon river sage".to_owned()),
            RecoveryWordCount::Twelve,
            [0x31; 20],
            Zeroizing::new(["abandon"; 12].into_iter().collect::<Vec<_>>().join(" ")),
        )
        .map(RecoveryRequest::Display)
    }

    fn recovery_confirm() -> Result<RecoveryRequest, crate::SecretInputError> {
        let ceremony_id = RecoveryCeremonyId::generate()?;
        RecoveryConfirmRequest::new(
            &ceremony_id,
            Zeroizing::new("amber cedar moon river sage".to_owned()),
            RecoveryWordCount::Twelve,
            [1, 4, 8, 12],
        )
        .map(RecoveryRequest::Confirm)
    }

    #[test]
    fn hello_round_trip_binds_both_nonces_and_transcript() -> Result<(), crate::SecretInputError> {
        let parent = hello()?;
        let encoded_parent = encode_parent_hello(&parent);
        let encoded_child = encode_child_hello(
            BootstrapKind::SecretInput,
            &encoded_parent,
            &[7; 32],
            &[9; 32],
        );
        assert_eq!(encoded_child.len(), CHILD_HELLO_BYTES);
        let child = decode_child_hello(&parent, &encoded_child)?;
        assert_eq!(
            child,
            ChildHello {
                child_nonce: [9; 32]
            }
        );

        for index in [10_usize, 42, 74] {
            let mut corrupted = encoded_child.to_vec();
            corrupted[index] ^= 1;
            assert!(decode_child_hello(&parent, &corrupted).is_err());
        }
        Ok(())
    }

    #[test]
    fn recovery_hello_domains_are_stage_specific() -> Result<(), crate::SecretInputError> {
        let parent = hello()?;
        for kind in [RecoverySessionKind::Display, RecoverySessionKind::Confirm] {
            let encoded_parent = encode_recovery_parent_hello(kind, &parent);
            let encoded_child = encode_child_hello(
                BootstrapKind::Recovery(kind),
                &encoded_parent,
                &[7; 32],
                &[9; 32],
            );
            assert!(decode_recovery_child_hello(kind, &parent, &encoded_child).is_ok());
            let other = match kind {
                RecoverySessionKind::Display => RecoverySessionKind::Confirm,
                RecoverySessionKind::Confirm => RecoverySessionKind::Display,
            };
            assert!(decode_recovery_child_hello(other, &parent, &encoded_child).is_err());
            assert!(decode_child_hello(&parent, &encoded_child).is_err());
            for length in 0..encoded_child.len() {
                assert!(
                    decode_recovery_child_hello(kind, &parent, &encoded_child[..length]).is_err()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn finish_binds_exact_prompt_and_rejects_trailing_data() -> Result<(), crate::SecretInputError>
    {
        let encoded = encode_parent_finish(&prompt()?, &[7; 32], &[9; 32])?;
        let (decoded, hash) = decode_parent_finish(&encoded, &[7; 32], &[9; 32])?;
        assert_eq!(decoded, prompt()?);
        assert_ne!(hash, [0; 32]);

        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(decode_parent_finish(&trailing, &[7; 32], &[9; 32]).is_err());
        assert!(decode_parent_finish(&encoded, &[8; 32], &[9; 32]).is_err());
        Ok(())
    }

    #[test]
    fn authenticated_outcome_rejects_nonce_prompt_and_trailing_swaps()
    -> Result<(), crate::SecretInputError> {
        let prompt = prompt()?;
        let session = super::AuthenticatedSession {
            prompt: prompt.clone(),
            prompt_hash: super::prompt_hash(&crate::encode_prompt(&prompt)?),
            parent_nonce: Zeroizing::new([7; 32]),
            child_nonce: Zeroizing::new([9; 32]),
        };
        let mut bytes = Vec::new();
        super::write_authenticated_outcome(&mut bytes, session, SecretOutcome::Cancelled)?;
        assert!(matches!(
            decode_authenticated_outcome(
                &prompt,
                &[7; 32],
                &[9; 32],
                Zeroizing::new(bytes.clone())
            )?,
            SecretOutcome::Cancelled
        ));
        assert!(
            decode_authenticated_outcome(
                &prompt,
                &[8; 32],
                &[9; 32],
                Zeroizing::new(bytes.clone())
            )
            .is_err()
        );
        bytes.push(0);
        assert!(
            decode_authenticated_outcome(&prompt, &[7; 32], &[9; 32], Zeroizing::new(bytes))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn recovery_finish_is_domain_separated_and_exactly_bound() -> Result<(), crate::SecretInputError>
    {
        let request = recovery_display()?;
        let encoded = encode_recovery_parent_finish(&request, &[7; 32], &[9; 32])?;
        let (decoded, hash) = decode_recovery_parent_finish(
            Zeroizing::new(encoded.to_vec()),
            RecoverySessionKind::Display,
            &[7; 32],
            &[9; 32],
        )?;
        assert_eq!(
            encode_recovery_request(&decoded)?,
            encode_recovery_request(&request)?
        );
        assert_ne!(hash, [0; 32]);

        assert!(decode_parent_finish(&encoded, &[7; 32], &[9; 32]).is_err());
        let secret_finish = encode_parent_finish(&prompt()?, &[7; 32], &[9; 32])?;
        assert!(
            decode_recovery_parent_finish(
                Zeroizing::new(secret_finish.to_vec()),
                RecoverySessionKind::Display,
                &[7; 32],
                &[9; 32]
            )
            .is_err()
        );
        for index in [10_usize, 42, 74, encoded.len() - 1] {
            let mut corrupted = encoded.to_vec();
            corrupted[index] ^= 1;
            assert!(
                decode_recovery_parent_finish(
                    Zeroizing::new(corrupted),
                    RecoverySessionKind::Display,
                    &[7; 32],
                    &[9; 32]
                )
                .is_err()
            );
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(
            decode_recovery_parent_finish(
                Zeroizing::new(trailing),
                RecoverySessionKind::Display,
                &[7; 32],
                &[9; 32]
            )
            .is_err()
        );
        assert!(
            decode_recovery_parent_finish(
                Zeroizing::new(encoded.to_vec()),
                RecoverySessionKind::Confirm,
                &[7; 32],
                &[9; 32]
            )
            .is_err()
        );
        for length in 0..encoded.len() {
            assert!(
                decode_recovery_parent_finish(
                    Zeroizing::new(encoded[..length].to_vec()),
                    RecoverySessionKind::Display,
                    &[7; 32],
                    &[9; 32]
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn recovery_confirmation_finish_cannot_replay_as_display() -> Result<(), crate::SecretInputError>
    {
        let request = recovery_confirm()?;
        let encoded = encode_recovery_parent_finish(&request, &[17; 32], &[19; 32])?;
        assert!(
            decode_recovery_parent_finish(
                Zeroizing::new(encoded.to_vec()),
                RecoverySessionKind::Confirm,
                &[17; 32],
                &[19; 32]
            )
            .is_ok()
        );
        assert!(
            decode_recovery_parent_finish(
                Zeroizing::new(encoded.to_vec()),
                RecoverySessionKind::Display,
                &[17; 32],
                &[19; 32]
            )
            .is_err()
        );
        assert!(
            decode_recovery_parent_finish(
                Zeroizing::new(encoded.to_vec()),
                RecoverySessionKind::Confirm,
                &[17; 32],
                &[20; 32]
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn authenticated_recovery_outcome_rejects_cross_protocol_and_replay()
    -> Result<(), crate::SecretInputError> {
        let request = recovery_display()?;
        let request_hash = super::recovery_request_hash(
            RecoverySessionKind::Display,
            &encode_recovery_request(&request)?,
        );
        let session = AuthenticatedRecoverySession {
            request: recovery_display()?,
            request_hash,
            parent_nonce: Zeroizing::new([7; 32]),
            child_nonce: Zeroizing::new([9; 32]),
        };
        let mut bytes = Vec::new();
        super::write_authenticated_recovery_outcome(
            &mut bytes,
            session,
            RecoveryOutcome::DisplayAcknowledged,
        )?;
        assert!(matches!(
            decode_authenticated_recovery_outcome(
                &request,
                &[7; 32],
                &[9; 32],
                Zeroizing::new(bytes.clone())
            )?,
            RecoveryOutcome::DisplayAcknowledged
        ));
        assert!(
            decode_authenticated_recovery_outcome(
                &request,
                &[8; 32],
                &[9; 32],
                Zeroizing::new(bytes.clone())
            )
            .is_err()
        );
        assert!(
            decode_authenticated_outcome(
                &prompt()?,
                &[7; 32],
                &[9; 32],
                Zeroizing::new(bytes.clone())
            )
            .is_err()
        );
        assert!(
            decode_authenticated_recovery_outcome(
                &recovery_confirm()?,
                &[7; 32],
                &[9; 32],
                Zeroizing::new(bytes.clone())
            )
            .is_err()
        );
        for length in 0..bytes.len() {
            assert!(
                decode_authenticated_recovery_outcome(
                    &request,
                    &[7; 32],
                    &[9; 32],
                    Zeroizing::new(bytes[..length].to_vec())
                )
                .is_err()
            );
        }
        bytes.push(0);
        assert!(
            decode_authenticated_recovery_outcome(
                &request,
                &[7; 32],
                &[9; 32],
                Zeroizing::new(bytes)
            )
            .is_err()
        );
        Ok(())
    }
}
