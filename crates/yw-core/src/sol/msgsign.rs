//! Solana message signatures for dApp ownership proof (spec/07 §19): `sol_signMessage` (Ed25519
//! over the exact bytes) and Sign-In-With-Solana (`sol_signIn`, the message the app builds from
//! validated fields in the `@solana/wallet-standard-util` `createSignInMessageText` layout).
//!
//! Never a transaction: bytes that are or begin with a legacy or v0 message or a signed
//! transaction, or that start with a version prefix `0x80`–`0xfe` and are not UTF-8 text (a
//! message version this wallet cannot parse), are blocked (M01); bytes with the off-chain signing domain `\xffsolana offchain`
//! must parse as an off-chain message version 0 (either the `solana-sdk` layout or the proposal
//! layout with application domain and signers) or are blocked (M02).
#![deny(clippy::indexing_slicing)]

use core::fmt;

use ed25519_dalek::Signer as _;

use super::address::{SolAddress, SolCluster};
use super::keys::{signing_key, verify_strict};
use super::shortvec;
use super::text as t;
use crate::approval::message::{inline_value, push_message_body};
use crate::approval::{
    AccountRef, ApprovalDisplay, ApprovalDraft, ApprovalId, ApprovalKind, ApprovalOrigin, Approved,
    ChainRef, DisplayError, DisplayField, FieldKey, MAX_TITLE_BYTES, Signer, SigningPayload,
    SimulationBinding, SolMessagePayload, Warning,
};
use crate::evm::risk::{self, M01, M02, M04, M05, W01, W02, W03, W04, W05, W06, W07, W08};
use crate::evm::siwe::parse_date_time;
use crate::lang::Lang;
use crate::policy::BrowserOrigin;
use crate::slip10::SolKeySource;
use crate::vault::Vault;

/// Largest message.
pub const MAX_SOL_MESSAGE_BYTES: usize = 65_536;
/// Off-chain message signing domain.
pub const OFFCHAIN_DOMAIN: &[u8; 16] = b"\xffsolana offchain";
/// The SIWS first-line marker.
pub const SIWS_MARKER: &str = " wants you to sign in with your Solana account:";
/// `Issued At` further than this from now is high risk (W06).
pub const SIWS_ISSUED_AT_SKEW_MS: i128 = 600_000;
/// Most `Resources` entries accepted from a dApp.
pub const MAX_SIWS_RESOURCES: usize = 32;
/// Largest SIWS field (bytes).
pub const MAX_SIWS_FIELD_BYTES: usize = 1_024;

// ----- transaction and off-chain detection ------------------------------------------------

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> Option<u8> {
        let value = *self.bytes.get(self.at)?;
        self.at += 1;
        Some(value)
    }

    fn short(&mut self) -> Option<usize> {
        let (value, used) = shortvec::decode(self.bytes.get(self.at..)?).ok()?;
        self.at += used;
        Some(usize::from(value))
    }

    fn skip(&mut self, count: usize) -> Option<&[u8]> {
        let end = self.at.checked_add(count)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    const fn done(&self) -> bool {
        self.at == self.bytes.len()
    }
}

/// Parses a legacy or v0 message structurally from `reader`; returns its required signer count.
/// Later versions (prefix `0x81`–`0xff`) are not parsed here: [`looks_like_versioned_message`]
/// blocks them by their prefix alone.
fn parse_message(reader: &mut Reader<'_>) -> Option<usize> {
    let first = *reader.bytes.get(reader.at)?;
    let versioned = first & 0x80 != 0;
    if versioned {
        if first & 0x7f != 0 {
            return None;
        }
        reader.at += 1;
    }
    let required = usize::from(reader.byte()?);
    let readonly_signed = usize::from(reader.byte()?);
    let readonly_unsigned = usize::from(reader.byte()?);
    let keys = reader.short()?;
    if required == 0
        || readonly_signed >= required
        || keys < required
        || readonly_unsigned > keys - required
    {
        return None;
    }
    reader.skip(keys.checked_mul(32)?)?;
    reader.skip(32)?;
    let instructions = reader.short()?;
    let mut indices = Vec::new();
    for _ in 0..instructions {
        indices.push(usize::from(reader.byte()?));
        let accounts = reader.short()?;
        indices.extend(
            reader
                .skip(accounts)?
                .iter()
                .map(|index| usize::from(*index)),
        );
        let data = reader.short()?;
        reader.skip(data)?;
    }
    let mut total = keys;
    if versioned {
        let lookups = reader.short()?;
        for _ in 0..lookups {
            reader.skip(32)?;
            let writable = reader.short()?;
            reader.skip(writable)?;
            let readonly = reader.short()?;
            reader.skip(readonly)?;
            total = total.checked_add(writable)?.checked_add(readonly)?;
        }
    }
    indices
        .iter()
        .all(|index| *index < total)
        .then_some(required)
}

/// Whether `bytes` start like a versioned Solana message of any version, including versions this
/// wallet cannot parse yet: a first byte `0x80`–`0xfe` (the version flag; `0xff` begins the
/// off-chain domain) — unless the whole buffer is valid UTF-8 text (M01).
#[must_use]
pub fn looks_like_versioned_message(bytes: &[u8]) -> bool {
    bytes
        .first()
        .is_some_and(|first| (0x80..=0xfe).contains(first))
        && !bytes.starts_with(OFFCHAIN_DOMAIN)
        && core::str::from_utf8(bytes).is_err()
}

/// Whether `bytes` are, or begin with, a legacy/v0 Solana message or a signed transaction, or
/// start like a versioned message of a later version (M01). Trailing bytes after a parsable
/// message do not make the bytes safe to sign.
#[must_use]
pub fn looks_like_transaction(bytes: &[u8]) -> bool {
    if looks_like_versioned_message(bytes) {
        return true;
    }
    let mut message = Reader { bytes, at: 0 };
    if parse_message(&mut message).is_some() {
        return true;
    }
    let mut transaction = Reader { bytes, at: 0 };
    let Some(signatures) = transaction.short() else {
        return false;
    };
    signatures >= 1
        && signatures
            .checked_mul(64)
            .and_then(|length| transaction.skip(length))
            .is_some()
        && parse_message(&mut transaction) == Some(signatures)
}

/// A parsed off-chain message (version 0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OffchainMessage {
    /// Message format: 0 restricted ASCII, 1 limited UTF-8, 2 extended UTF-8.
    pub format: u8,
    /// Signers of the proposal layout (empty for the `solana-sdk` layout).
    pub signers: Vec<[u8; 32]>,
    /// The inner message bytes.
    pub message: Vec<u8>,
}

fn offchain_body_ok(format: u8, message: &[u8]) -> bool {
    match format {
        0 => message.len() <= 1_212 && message.iter().all(|byte| (0x20..=0x7e).contains(byte)),
        1 => message.len() <= 1_212 && core::str::from_utf8(message).is_ok(),
        2 => core::str::from_utf8(message).is_ok(),
        _ => false,
    }
}

/// Parses an off-chain message version 0 (`None` when the bytes lack the domain or break both
/// layouts).
#[must_use]
pub fn parse_offchain(bytes: &[u8]) -> Option<OffchainMessage> {
    let rest = bytes.strip_prefix(OFFCHAIN_DOMAIN.as_slice())?;
    let (version, body) = rest.split_first()?;
    if *version != 0 {
        return None;
    }
    // solana-sdk: format u8 ‖ length u16 LE ‖ message.
    if let Some((format, tail)) = body.split_first()
        && let Some((length, message)) = tail.split_first_chunk::<2>()
        && usize::from(u16::from_le_bytes(*length)) == message.len()
        && !message.is_empty()
        && offchain_body_ok(*format, message)
    {
        return Some(OffchainMessage {
            format: *format,
            signers: Vec::new(),
            message: message.to_vec(),
        });
    }
    // Proposal: application domain 32 ‖ format ‖ signer count ‖ signers ‖ length u16 LE ‖ message.
    let mut reader = Reader { bytes: body, at: 0 };
    reader.skip(32)?;
    let format = reader.byte()?;
    let count = usize::from(reader.byte()?);
    if count == 0 {
        return None;
    }
    let mut signers = Vec::with_capacity(count);
    for _ in 0..count {
        signers.push(<[u8; 32]>::try_from(reader.skip(32)?).ok()?);
    }
    let length = usize::from(u16::from_le_bytes(
        <[u8; 2]>::try_from(reader.skip(2)?).ok()?,
    ));
    let message = reader.skip(length)?.to_vec();
    (reader.done() && !message.is_empty() && offchain_body_ok(format, &message)).then_some(
        OffchainMessage {
            format,
            signers,
            message,
        },
    )
}

// ----- SIWS ----------------------------------------------------------------------------------

/// A Sign-In-With-Solana message (`SolanaSignInInput` with the required `domain` and `address`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SiwsMessage {
    /// RFC 4501 authority (`host[:port]`).
    pub domain: String,
    /// Base58 account.
    pub address: String,
    /// Statement (one line).
    pub statement: Option<String>,
    /// `URI`.
    pub uri: Option<String>,
    /// `Version` (must be `1` when present).
    pub version: Option<String>,
    /// `Chain ID` (`mainnet`, `devnet`, `solana:mainnet`, …).
    pub chain_id: Option<String>,
    /// `Nonce`.
    pub nonce: Option<String>,
    /// `Issued At` (RFC 3339).
    pub issued_at: Option<String>,
    /// `Expiration Time` (RFC 3339).
    pub expiration_time: Option<String>,
    /// `Not Before` (RFC 3339).
    pub not_before: Option<String>,
    /// `Request ID`.
    pub request_id: Option<String>,
    /// `Resources`.
    pub resources: Option<Vec<String>>,
}

const FIELD_TAGS: [&str; 8] = [
    "URI: ",
    "Version: ",
    "Chain ID: ",
    "Nonce: ",
    "Issued At: ",
    "Expiration Time: ",
    "Not Before: ",
    "Request ID: ",
];

impl SiwsMessage {
    fn optional_fields(&self) -> [&Option<String>; 8] {
        [
            &self.uri,
            &self.version,
            &self.chain_id,
            &self.nonce,
            &self.issued_at,
            &self.expiration_time,
            &self.not_before,
            &self.request_id,
        ]
    }

    /// The message text exactly as `createSignInMessageText` writes it (empty values are
    /// omitted like the JavaScript falsy checks).
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut message = format!("{}{SIWS_MARKER}\n{}", self.domain, self.address);
        if let Some(statement) = self.statement.as_deref().filter(|text| !text.is_empty()) {
            message.push_str("\n\n");
            message.push_str(statement);
        }
        let mut fields: Vec<String> = Vec::new();
        for (tag, value) in FIELD_TAGS.iter().zip(self.optional_fields()) {
            if let Some(value) = value.as_deref().filter(|text| !text.is_empty()) {
                fields.push(format!("{tag}{value}"));
            }
        }
        if let Some(resources) = &self.resources {
            fields.push("Resources:".to_owned());
            fields.extend(resources.iter().map(|resource| format!("- {resource}")));
        }
        if !fields.is_empty() {
            message.push_str("\n\n");
            message.push_str(&fields.join("\n"));
        }
        message
    }

    /// Parses SIWS text (single-line statement; trailing line feeds allowed). `None` when the
    /// marker line or the grammar does not match.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim_end_matches('\n');
        let mut lines = text.split('\n').peekable();
        let domain = lines.next()?.strip_suffix(SIWS_MARKER)?;
        let address = lines.next()?;
        if domain.is_empty() || address.is_empty() {
            return None;
        }
        let mut message = Self {
            domain: domain.to_owned(),
            address: address.to_owned(),
            ..Self::default()
        };
        let is_field =
            |line: &str| line == "Resources:" || FIELD_TAGS.iter().any(|tag| line.starts_with(tag));
        if lines.peek().is_some() {
            if !lines.next()?.is_empty() {
                return None;
            }
            let next = *lines.peek()?;
            if !is_field(next) {
                message.statement = Some(next.to_owned());
                lines.next();
                if lines.peek().is_some() && !lines.next()?.is_empty() {
                    return None;
                }
            }
        }
        let mut position = 0_usize;
        while let Some(line) = lines.next() {
            if line == "Resources:" {
                let mut resources = Vec::new();
                for item in lines.by_ref() {
                    resources.push(item.strip_prefix("- ")?.to_owned());
                }
                message.resources = Some(resources);
                break;
            }
            let (index, value) = FIELD_TAGS
                .iter()
                .enumerate()
                .skip(position)
                .find_map(|(index, tag)| line.strip_prefix(tag).map(|value| (index, value)))?;
            if value.is_empty() {
                return None;
            }
            let slot = match index {
                0 => &mut message.uri,
                1 => &mut message.version,
                2 => &mut message.chain_id,
                3 => &mut message.nonce,
                4 => &mut message.issued_at,
                5 => &mut message.expiration_time,
                6 => &mut message.not_before,
                _ => &mut message.request_id,
            };
            *slot = Some(value.to_owned());
            position = index + 1;
        }
        (message.to_text() == text).then_some(message)
    }
}

/// Whether text carries the SIWS marker on its first line (after leading whitespace).
#[must_use]
pub fn has_siws_marker(text: &str) -> bool {
    text.trim_start()
        .split('\n')
        .next()
        .is_some_and(|line| line.contains(SIWS_MARKER))
}

/// What the SIWS checks compare against.
#[derive(Clone, Copy, Debug)]
pub struct SiwsContext<'a> {
    /// Requesting site.
    pub origin: &'a BrowserOrigin,
    /// Signing account (base58).
    pub account: &'a str,
    /// The wallet's Solana cluster.
    pub cluster: SolCluster,
    /// Wall clock.
    pub now_unix_ms: u64,
}

/// Whether a SIWS `Chain ID` names `cluster`.
#[must_use]
pub fn chain_matches(chain_id: &str, cluster: SolCluster) -> bool {
    let name = chain_id.strip_prefix("solana:").unwrap_or(chain_id);
    match cluster {
        SolCluster::Mainnet => name == "mainnet" || name == "mainnet-beta",
        SolCluster::Devnet => name == "devnet",
    }
}

/// `domain` (`host[:port]`, no scheme, userinfo or path) names the requesting site: same host,
/// and an explicit port equal to the site's effective port, or no port only when the site uses
/// its scheme's default port (a site on `:5173` must say `host:5173`).
#[must_use]
pub fn domain_matches(domain: &str, origin: &BrowserOrigin) -> bool {
    if domain.contains(['/', '@', '?', '#', '[', ']', ' ']) {
        return false;
    }
    let (host, port) = match domain.rsplit_once(':') {
        Some((host, port)) => {
            let valid = !port.is_empty()
                && port.len() <= 5
                && !port.starts_with('0')
                && port.bytes().all(|byte| byte.is_ascii_digit());
            match port.parse::<u16>() {
                Ok(port) if valid => (host, Some(port)),
                _ => return false,
            }
        }
        None => (domain, None),
    };
    host.eq_ignore_ascii_case(origin.host())
        && match port {
            Some(port) => port == origin.effective_port(),
            None => origin.port().is_none(),
        }
}

fn ms_of(seconds: i64) -> i128 {
    i128::from(seconds) * 1_000
}

/// The W01–W08 warnings of a SIWS message (spec/07 §19.4), in `lang`.
#[must_use]
pub fn check_siws(lang: Lang, message: &SiwsMessage, context: &SiwsContext<'_>) -> Vec<Warning> {
    let now = i128::from(context.now_unix_ms);
    let mut warnings = Vec::new();
    if !domain_matches(&message.domain, context.origin) {
        warnings.push(risk::warning(lang, W01, None));
    }
    if message.address != context.account {
        warnings.push(risk::warning(lang, W02, None));
    }
    if let Some(chain) = &message.chain_id
        && !chain_matches(chain, context.cluster)
    {
        warnings.push(risk::warning(lang, W03, None));
    }
    if message
        .version
        .as_deref()
        .is_some_and(|version| version != "1")
    {
        warnings.push(risk::warning(lang, W07, Some(t::W07_VERSION.get(lang))));
    }
    let time = |text: &Option<String>| text.as_deref().map(parse_date_time);
    match time(&message.issued_at) {
        Some(None) => warnings.push(risk::warning(lang, W07, Some(t::W07_ISSUED_AT.get(lang)))),
        Some(Some(seconds)) if (ms_of(seconds) - now).abs() > SIWS_ISSUED_AT_SKEW_MS => {
            warnings.push(risk::warning(lang, W06, None));
        }
        _ => {}
    }
    match time(&message.expiration_time) {
        Some(None) => warnings.push(risk::warning(lang, W07, Some(t::W07_EXPIRATION.get(lang)))),
        Some(Some(seconds)) if ms_of(seconds) <= now => {
            warnings.push(risk::warning(lang, W04, None));
        }
        _ => {}
    }
    match time(&message.not_before) {
        Some(None) => warnings.push(risk::warning(lang, W07, Some(t::W07_NOT_BEFORE.get(lang)))),
        Some(Some(seconds)) if ms_of(seconds) > now => {
            warnings.push(risk::warning(lang, W05, None));
        }
        _ => {}
    }
    if warnings.is_empty() {
        warnings.push(risk::warning(lang, W08, None));
    }
    warnings
}

fn siws_fields(
    lang: Lang,
    fields: &mut Vec<DisplayField>,
    message: &SiwsMessage,
) -> Result<(), DisplayError> {
    let mut push = |label: &str, value: &str| -> Result<(), DisplayError> {
        fields.push(DisplayField::new(
            FieldKey::SIWS_FIELD,
            label,
            inline_value(lang, value),
        )?);
        Ok(())
    };
    push(t::SIWS_DOMAIN.get(lang), &message.domain)?;
    push(t::SIWS_ADDRESS.get(lang), &message.address)?;
    for (label, value) in [
        (t::SIWS_STATEMENT.get(lang), &message.statement),
        ("URI", &message.uri),
        (t::SIWS_VERSION.get(lang), &message.version),
        ("Chain ID", &message.chain_id),
        ("Nonce", &message.nonce),
        (t::SIWS_ISSUED_AT.get(lang), &message.issued_at),
        (t::SIWS_EXPIRATION.get(lang), &message.expiration_time),
        (t::SIWS_NOT_BEFORE.get(lang), &message.not_before),
        (t::SIWS_REQUEST_ID.get(lang), &message.request_id),
    ] {
        if let Some(value) = value.as_deref().filter(|text| !text.is_empty()) {
            push(label, value)?;
        }
    }
    if let Some(resources) = &message.resources {
        let value = if resources.is_empty() {
            t::NONE.get(lang).to_owned()
        } else {
            resources
                .iter()
                .map(|resource| inline_value(lang, resource))
                .collect::<Vec<_>>()
                .join("\n")
        };
        fields.push(DisplayField::new(
            FieldKey::SIWS_FIELD,
            t::SIWS_RESOURCES.get(lang),
            value,
        )?);
    }
    Ok(())
}

// ----- approval --------------------------------------------------------------------------------

/// What a Solana message approval shows besides the bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolMessageRequest {
    /// Approval id.
    pub id: ApprovalId,
    /// Requesting site.
    pub origin: BrowserOrigin,
    /// The wallet's cluster (the pinned genesis is bound).
    pub cluster: SolCluster,
    /// Key source.
    pub source: SolKeySource,
    /// Public key.
    pub public: [u8; 32],
    /// The account label (user text, escaped here).
    pub label: String,
    /// The message bytes.
    pub message: Vec<u8>,
    /// `sol_signIn` (the app built the SIWS text).
    pub sign_in: bool,
}

fn title(lang: Lang, cluster: SolCluster, action: &str) -> String {
    let network = cluster.display_name_in(lang);
    let full = format!("[{network}] {action}");
    if full.len() <= MAX_TITLE_BYTES {
        full
    } else {
        format!("[{network}] {}", t::MESSAGE_TITLE_SHORT.get(lang))
    }
}

/// M01 when the bytes are or begin like a transaction message (a later message version gets
/// its own detail line).
fn transaction_warning(lang: Lang, bytes: &[u8]) -> Option<Warning> {
    if looks_like_versioned_message(bytes) {
        Some(risk::warning(lang, M01, Some(t::M01_VERSIONED.get(lang))))
    } else {
        looks_like_transaction(bytes).then(|| risk::warning(lang, M01, None))
    }
}

/// Builds the approval draft of a Solana message or sign-in request (spec/07 §19.3) with every
/// fixed text in `lang`.
///
/// # Errors
///
/// [`DisplayError`] (defensive).
pub fn build_sol_message_request(
    lang: Lang,
    request: &SolMessageRequest,
    now_unix_ms: u64,
) -> Result<ApprovalDraft, DisplayError> {
    let address = SolAddress::from_bytes(request.public).to_base58();
    let mut fields = vec![
        DisplayField::new(FieldKey::ORIGIN, "", request.origin.as_str())?,
        DisplayField::new(
            FieldKey::NETWORK,
            "",
            request.cluster.display_name_in(lang).to_owned(),
        )?,
        DisplayField::new(
            FieldKey::ACCOUNT,
            "",
            format!(
                "{}\n{}\n{address}",
                inline_value(lang, &request.label),
                request.source.path_text_in(lang)
            ),
        )?,
    ];
    let mut warnings = vec![risk::warning(lang, M04, None)];
    let bytes = &request.message;
    let mut body: &[u8] = bytes;
    if bytes.len() > MAX_SOL_MESSAGE_BYTES {
        warnings.push(risk::warning(lang, M01, Some(t::M01_TOO_LONG.get(lang))));
    }
    warnings.extend(transaction_warning(lang, bytes));
    let offchain = parse_offchain(bytes);
    if bytes.starts_with(OFFCHAIN_DOMAIN) {
        match &offchain {
            Some(parsed) => {
                warnings.push(risk::warning(lang, M05, None));
                if !parsed.signers.is_empty() && !parsed.signers.contains(&request.public) {
                    warnings.push(risk::warning(lang, M02, Some(t::M02_NOT_SIGNER.get(lang))));
                }
                fields.push(DisplayField::new(
                    FieldKey::MESSAGE_FORMAT,
                    "",
                    t::OFFCHAIN_FORMAT.fill(lang, [&parsed.format.to_string()]),
                )?);
                body = &parsed.message;
            }
            None => warnings.push(risk::warning(lang, M02, None)),
        }
    }
    push_message_body(lang, &mut fields, &mut warnings, body)?;
    let siws = core::str::from_utf8(body)
        .ok()
        .filter(|text| has_siws_marker(text));
    let action = match siws {
        Some(text) => {
            match SiwsMessage::parse(text) {
                Some(message) => {
                    siws_fields(lang, &mut fields, &message)?;
                    warnings.extend(check_siws(
                        lang,
                        &message,
                        &SiwsContext {
                            origin: &request.origin,
                            account: &address,
                            cluster: request.cluster,
                            now_unix_ms,
                        },
                    ));
                }
                None => warnings.push(risk::warning(lang, W07, None)),
            }
            t::ACTION_SIWS
        }
        None => t::ACTION_MESSAGE,
    };
    let display = ApprovalDisplay::new(
        lang,
        title(lang, request.cluster, action.get(lang)),
        fields,
        warnings,
    )?;
    Ok(ApprovalDraft {
        id: request.id,
        origin: ApprovalOrigin::Site(request.origin.clone()),
        chain: ChainRef::Solana {
            cluster: request.cluster,
            genesis: request.cluster.genesis(),
        },
        account: AccountRef::Sol(request.public),
        signer: Signer::FromPayload,
        kind: if request.sign_in {
            ApprovalKind::SolSignIn
        } else {
            ApprovalKind::SolMessage
        },
        payload: SigningPayload::SolMessage(Box::new(SolMessagePayload {
            source: request.source,
            public: request.public,
            message: request.message.clone(),
        })),
        display,
        simulation: SimulationBinding::NotApplicable,
    })
}

// ----- signing ---------------------------------------------------------------------------------

/// Message signing failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolMessageError {
    /// Not a Solana message approval of this payload.
    KindMismatch,
    /// The bytes are a transaction, a malformed off-chain message or too long.
    Refused,
    /// The key does not give the approved public key.
    KeyMismatch,
    /// Vault refusal or failed post-sign verification.
    Signing,
}

impl SolMessageError {
    /// The fixed text in `lang` (`Display` is the Korean one).
    #[must_use]
    pub const fn text_in(self, lang: Lang) -> &'static str {
        match self {
            Self::KindMismatch | Self::Refused | Self::KeyMismatch => t::MESSAGE_ERR_INTERNAL,
            Self::Signing => t::MESSAGE_ERR_SIGNING,
        }
        .get(lang)
    }
}

impl fmt::Display for SolMessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.text_in(Lang::Ko))
    }
}

impl std::error::Error for SolMessageError {}

/// Whether the bytes may be signed at all (the M01/M02 rules once more before key use).
#[must_use]
pub fn signable(bytes: &[u8]) -> bool {
    bytes.len() <= MAX_SOL_MESSAGE_BYTES
        && !looks_like_transaction(bytes)
        && (!bytes.starts_with(OFFCHAIN_DOMAIN) || parse_offchain(bytes).is_some())
}

/// Signs an approved Solana message; returns the 64-byte Ed25519 signature (spec/07 §19.5).
///
/// # Errors
///
/// [`SolMessageError`]; nothing is returned on error.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the one-time approval token is consumed by signing (spec/03 §11.5)"
)]
pub fn sign_message(vault: &Vault, approved: Approved) -> Result<[u8; 64], SolMessageError> {
    let payload = approved_message(&approved)?;
    let sign = |secret: &[u8; 32]| Ok(sign_with_seed(secret, &payload.public, &payload.message));
    let signed = if payload.source.is_imported() {
        vault.with_imported_ed25519_seed(&payload.public, sign)
    } else {
        vault.with_ed25519_seed(payload.source, sign)
    };
    signed.map_err(|_| SolMessageError::Signing)?
}

/// The approval checks of a message signature before any key use: kind, account and cluster,
/// then the M01/M02 rules ([`signable`]).
fn approved_message(approved: &Approved) -> Result<&SolMessagePayload, SolMessageError> {
    let SigningPayload::SolMessage(payload) = approved.payload() else {
        return Err(SolMessageError::KindMismatch);
    };
    let chain_ok = matches!(
        approved.chain(),
        ChainRef::Solana { cluster, genesis } if genesis == cluster.genesis()
    );
    if !matches!(
        approved.kind(),
        ApprovalKind::SolMessage | ApprovalKind::SolSignIn
    ) || approved.account() != AccountRef::Sol(payload.public)
        || !chain_ok
    {
        return Err(SolMessageError::KindMismatch);
    }
    if !signable(&payload.message) {
        return Err(SolMessageError::Refused);
    }
    Ok(payload)
}

/// Failure of a card (`YubiKey`) Solana message signature (spec/10 §6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolMessageCardError {
    /// The approval or the post-sign verification failed (as for vault signing:
    /// `KindMismatch` also for a source other than `SolKeySource::Hardware`, `Refused` for
    /// transaction-like or malformed off-chain bytes, `Signing` when `verify_strict` fails).
    Sign(SolMessageError),
    /// The card operation failed.
    Card(crate::yubikey::CardError),
}

impl fmt::Display for SolMessageCardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sign(error) => error.fmt(formatter),
            Self::Card(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SolMessageCardError {}

impl From<SolMessageError> for SolMessageCardError {
    fn from(error: SolMessageError) -> Self {
        Self::Sign(error)
    }
}

impl From<crate::yubikey::CardError> for SolMessageCardError {
    fn from(error: crate::yubikey::CardError) -> Self {
        Self::Card(error)
    }
}

/// [`sign_message`] on a card (spec/10 §6.4): the same approval checks and the same refusal of
/// transaction-like bytes and malformed off-chain messages (M01/M02) before the card is asked,
/// the card signs the exact message bytes, then `verify_strict` against the approved public key.
///
/// # Errors
///
/// [`SolMessageCardError::Sign`], [`SolMessageCardError::Card`]; nothing is returned on error.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the one-time approval token is consumed by signing (spec/03 §11.5)"
)]
pub fn sign_message_card(
    approved: Approved,
    card: super::sign::SolCardSigner<'_>,
) -> Result<[u8; 64], SolMessageCardError> {
    let payload = approved_message(&approved)?;
    if !payload.source.is_hardware() {
        return Err(SolMessageError::KindMismatch.into());
    }
    let signature = card(&payload.message)?;
    if !verify_strict(&payload.public, &payload.message, &signature) {
        return Err(SolMessageError::Signing.into());
    }
    Ok(signature)
}

/// Signs with a seed whose public key must be `public`, then `verify_strict`.
pub(crate) fn sign_with_seed(
    secret: &[u8; 32],
    public: &[u8; 32],
    message: &[u8],
) -> Result<[u8; 64], SolMessageError> {
    let key = signing_key(secret);
    if key.verifying_key().to_bytes() != *public {
        return Err(SolMessageError::KeyMismatch);
    }
    let signature = key.sign(message).to_bytes();
    if !verify_strict(public, message, &signature) {
        return Err(SolMessageError::Signing);
    }
    Ok(signature)
}

#[cfg(test)]
mod tests;
