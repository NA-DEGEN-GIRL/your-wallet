//! Sign-In with Ethereum (ERC-4361) parser and checks (spec/03 §9.3–§9.4, D18).
//!
//! The parser accepts exactly the §9.3 grammar with LF line breaks (any CR fails) and at most one
//! trailing LF. A message whose first line carries the SIWE marker but fails the grammar is
//! reported as `marker only` (S08); its first-line authority is still checked (S01/S02, blocked
//! when it cannot be read, [`check_marker_only`]). Parsed messages keep their raw tokens so that
//! [`SiweMessage::to_text`] reproduces the source exactly (fuzz invariant, spec/09 §2.4).

use super::address::{Address, AddressError, parse_address};
use super::display::time::{days_from_civil, valid_date};
use super::risk::{self, S01, S02, S03, S04, S05, S06, S07, S08, S09};
use crate::approval::Warning;
use crate::policy::BrowserOrigin;

const MARKER: &str = " wants you to sign in with your Ethereum account:";
const MARKER_PHRASE: &str = " wants you to sign in with your Ethereum account";
const MAX_URI_BYTES: usize = 2_048;
const MAX_RESOURCES: usize = 64;

/// A parsed SIWE message (spec/03 §9.3) plus the raw tokens needed for exact reassembly.
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag records one optional source token for exact reassembly"
)]
pub struct SiweMessage {
    /// `https` or `http` (`https` when absent).
    pub scheme: String,
    /// Whether the scheme was written explicitly.
    pub scheme_explicit: bool,
    /// The raw authority (`[userinfo@]host[:port]`).
    pub domain: String,
    /// Lowercased host.
    pub domain_host: String,
    /// Explicit port.
    pub domain_port: Option<u16>,
    /// Whether the authority has userinfo (S02).
    pub has_userinfo: bool,
    /// The address bytes (grammar is case-insensitive; checksum is checked by S03).
    pub address: Address,
    /// The raw address text.
    pub address_text: String,
    /// Statement.
    pub statement: Option<String>,
    /// URI.
    pub uri: String,
    /// Chain id.
    pub chain_id: u64,
    /// Raw chain-id digits.
    pub chain_id_text: String,
    /// Nonce.
    pub nonce: String,
    /// Issued At (unix seconds).
    pub issued_at: i64,
    /// Raw Issued At.
    pub issued_at_text: String,
    /// Expiration Time (unix seconds).
    pub expiration_time: Option<i64>,
    /// Raw Expiration Time.
    pub expiration_time_text: Option<String>,
    /// Not Before (unix seconds).
    pub not_before: Option<i64>,
    /// Raw Not Before.
    pub not_before_text: Option<String>,
    /// Request ID.
    pub request_id: Option<String>,
    /// Resources.
    pub resources: Vec<String>,
    /// Whether the "Resources:" line is present (it may list no entries).
    pub resources_present: bool,
    /// Whether the text ended with one LF.
    pub trailing_lf: bool,
}

/// Result of looking for SIWE in a UTF-8 message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SiweParse {
    /// Not a SIWE message.
    NotSiwe,
    /// The first line has the marker but the grammar failed (S08).
    MarkerOnly,
    /// A well-formed message.
    Message(Box<SiweMessage>),
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn is_sub_delim(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}

fn is_reserved(byte: u8) -> bool {
    matches!(byte, b':' | b'/' | b'?' | b'#' | b'[' | b']' | b'@') || is_sub_delim(byte)
}

fn is_pchar(byte: u8) -> bool {
    is_unreserved(byte) || is_sub_delim(byte) || matches!(byte, b':' | b'@' | b'%')
}

fn valid_uri(text: &str) -> bool {
    if text.is_empty() || text.len() > MAX_URI_BYTES {
        return false;
    }
    if !text.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return false;
    }
    let Some((scheme, _)) = text.split_once(':') else {
        return false;
    };
    let mut bytes = scheme.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

/// Parses an authority: `[userinfo@]host[:port]`.
fn parse_authority(text: &str) -> Option<(String, Option<u16>, bool)> {
    if text.is_empty() {
        return None;
    }
    let (userinfo, host_port) = match text.rsplit_once('@') {
        Some((userinfo, rest)) => (Some(userinfo), rest),
        None => (None, text),
    };
    if let Some(userinfo) = userinfo
        && !userinfo
            .bytes()
            .all(|byte| is_unreserved(byte) || is_sub_delim(byte) || matches!(byte, b':' | b'%'))
    {
        return None;
    }
    let (host, port) = if host_port.starts_with('[') {
        let close = host_port.find(']')?;
        let (host, rest) = host_port.split_at(close.checked_add(1)?);
        let port = match rest.strip_prefix(':') {
            Some(port) => Some(port),
            None if rest.is_empty() => None,
            None => return None,
        };
        let inner = host.get(1..host.len().checked_sub(1)?)?;
        if inner.is_empty()
            || !inner
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b':' | b'.'))
        {
            return None;
        }
        (host, port)
    } else {
        match host_port.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (host_port, None),
        }
    };
    if !host.starts_with('[')
        && (host.is_empty()
            || !host
                .bytes()
                .all(|byte| is_unreserved(byte) || is_sub_delim(byte) || byte == b'%'))
    {
        return None;
    }
    let port = match port {
        Some(digits) => {
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            Some(digits.parse::<u16>().ok()?)
        }
        None => None,
    };
    Some((host.to_ascii_lowercase(), port, userinfo.is_some()))
}

fn two_digits(text: &str) -> Option<u32> {
    if text.len() != 2 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Parses an RFC 3339 date-time to unix seconds (fraction ignored).
#[must_use]
pub fn parse_date_time(text: &str) -> Option<i64> {
    let (date, rest) = text.split_once(['T', 't'])?;
    let mut date_parts = date.split('-');
    let year_text = date_parts.next()?;
    if year_text.len() != 4 || !year_text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let year: i64 = year_text.parse().ok()?;
    let month = two_digits(date_parts.next()?)?;
    let day = two_digits(date_parts.next()?)?;
    if date_parts.next().is_some() || !valid_date(year, month, day) {
        return None;
    }
    let (time, offset_seconds) = if let Some(time) = rest.strip_suffix(['Z', 'z']) {
        (time, 0_i64)
    } else {
        let split = rest.rfind(['+', '-'])?;
        let (time, offset) = rest.split_at(split);
        let sign = if offset.starts_with('-') { -1 } else { 1 };
        let (hours, minutes) = offset.get(1..)?.split_once(':')?;
        let (hours, minutes) = (two_digits(hours)?, two_digits(minutes)?);
        if hours > 23 || minutes > 59 {
            return None;
        }
        (time, sign * i64::from(hours * 3_600 + minutes * 60))
    };
    let (clock, fraction) = match time.split_once('.') {
        Some((clock, fraction)) => (clock, Some(fraction)),
        None => (time, None),
    };
    if let Some(fraction) = fraction
        && (fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    let mut clock_parts = clock.split(':');
    let hour = two_digits(clock_parts.next()?)?;
    let minute = two_digits(clock_parts.next()?)?;
    let second = two_digits(clock_parts.next()?)?;
    if clock_parts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + i64::from(hour * 3_600 + minute * 60 + second) - offset_seconds)
}

struct Lines<'a> {
    lines: Vec<&'a str>,
    index: usize,
}

impl<'a> Lines<'a> {
    fn next(&mut self) -> Option<&'a str> {
        let line = self.lines.get(self.index).copied();
        self.index = self.index.saturating_add(1);
        line
    }

    fn peek(&self) -> Option<&'a str> {
        self.lines.get(self.index).copied()
    }

    fn tagged(&mut self, tag: &str) -> Option<&'a str> {
        let value = self.peek()?.strip_prefix(tag)?;
        self.index = self.index.saturating_add(1);
        Some(value)
    }
}

/// Looks for a SIWE message in UTF-8 text.
#[must_use]
pub fn parse_siwe(text: &str) -> SiweParse {
    let first_line = text.split('\n').next().unwrap_or("");
    if !first_line.contains("wants you to sign in with your Ethereum account") {
        return SiweParse::NotSiwe;
    }
    parse_strict(text).map_or(SiweParse::MarkerOnly, |message| {
        SiweParse::Message(Box::new(message))
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "one linear pass over the ERC-4361 grammar"
)]
fn parse_strict(text: &str) -> Option<SiweMessage> {
    if text.contains('\r') {
        return None;
    }
    let (body, trailing_lf) = match text.strip_suffix('\n') {
        Some(body) => (body, true),
        None => (text, false),
    };
    let mut lines = Lines {
        lines: body.split('\n').collect(),
        index: 0,
    };
    let head = lines.next()?.strip_suffix(MARKER)?;
    let (scheme, scheme_explicit, domain) = match head.split_once("://") {
        Some((scheme, domain)) if scheme == "https" || scheme == "http" => {
            (scheme.to_owned(), true, domain)
        }
        Some(_) => return None,
        None => ("https".to_owned(), false, head),
    };
    let (domain_host, domain_port, has_userinfo) = parse_authority(domain)?;
    let address_text = lines.next()?;
    let digits = address_text.strip_prefix("0x")?;
    if digits.len() != 40 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let address = parse_address(&format!("0x{}", digits.to_ascii_lowercase())).ok()?;
    if !lines.next()?.is_empty() {
        return None;
    }
    let statement = if lines.peek()?.is_empty() {
        lines.next();
        None
    } else {
        let statement = lines.next()?;
        if !statement
            .bytes()
            .all(|byte| byte == b' ' || is_reserved(byte) || is_unreserved(byte))
        {
            return None;
        }
        if !lines.next()?.is_empty() {
            return None;
        }
        Some(statement.to_owned())
    };
    let uri = lines.tagged("URI: ")?;
    if !valid_uri(uri) {
        return None;
    }
    if lines.tagged("Version: ")? != "1" {
        return None;
    }
    let chain_id_text = lines.tagged("Chain ID: ")?;
    if chain_id_text.is_empty() || !chain_id_text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let chain_id: u64 = chain_id_text.parse().ok()?;
    let nonce = lines.tagged("Nonce: ")?;
    if nonce.len() < 8 || !nonce.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return None;
    }
    let issued_at_text = lines.tagged("Issued At: ")?;
    let issued_at = parse_date_time(issued_at_text)?;
    let expiration_time_text = lines.tagged("Expiration Time: ");
    let expiration_time = match expiration_time_text {
        Some(text) => Some(parse_date_time(text)?),
        None => None,
    };
    let not_before_text = lines.tagged("Not Before: ");
    let not_before = match not_before_text {
        Some(text) => Some(parse_date_time(text)?),
        None => None,
    };
    let request_id = lines.tagged("Request ID: ");
    if let Some(request_id) = request_id
        && !request_id.bytes().all(is_pchar)
    {
        return None;
    }
    let mut resources = Vec::new();
    let resources_present = lines.peek() == Some("Resources:");
    if resources_present {
        lines.next();
        while let Some(resource) = lines.tagged("- ") {
            if !valid_uri(resource) || resources.len() >= MAX_RESOURCES {
                return None;
            }
            resources.push(resource.to_owned());
        }
    }
    if lines.peek().is_some() {
        return None;
    }
    Some(SiweMessage {
        scheme,
        scheme_explicit,
        domain: domain.to_owned(),
        domain_host,
        domain_port,
        has_userinfo,
        address,
        address_text: address_text.to_owned(),
        statement,
        uri: uri.to_owned(),
        chain_id,
        chain_id_text: chain_id_text.to_owned(),
        nonce: nonce.to_owned(),
        issued_at,
        issued_at_text: issued_at_text.to_owned(),
        expiration_time,
        expiration_time_text: expiration_time_text.map(str::to_owned),
        not_before,
        not_before_text: not_before_text.map(str::to_owned),
        request_id: request_id.map(str::to_owned),
        resources,
        resources_present,
        trailing_lf,
    })
}

impl SiweMessage {
    /// Reassembles the exact source text.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        if self.scheme_explicit {
            out.push_str(&self.scheme);
            out.push_str("://");
        }
        out.push_str(&self.domain);
        out.push_str(MARKER);
        out.push('\n');
        out.push_str(&self.address_text);
        out.push_str("\n\n");
        if let Some(statement) = &self.statement {
            out.push_str(statement);
            out.push('\n');
        }
        out.push('\n');
        out.push_str("URI: ");
        out.push_str(&self.uri);
        out.push_str("\nVersion: 1\nChain ID: ");
        out.push_str(&self.chain_id_text);
        out.push_str("\nNonce: ");
        out.push_str(&self.nonce);
        out.push_str("\nIssued At: ");
        out.push_str(&self.issued_at_text);
        for (tag, value) in [
            ("Expiration Time: ", &self.expiration_time_text),
            ("Not Before: ", &self.not_before_text),
            ("Request ID: ", &self.request_id),
        ] {
            if let Some(value) = value {
                out.push('\n');
                out.push_str(tag);
                out.push_str(value);
            }
        }
        if self.resources_present {
            out.push_str("\nResources:");
            for resource in &self.resources {
                out.push_str("\n- ");
                out.push_str(resource);
            }
        }
        if self.trailing_lf {
            out.push('\n');
        }
        out
    }
}

/// Inputs of the §9.4 checks.
#[derive(Clone, Copy, Debug)]
pub struct SiweContext<'a> {
    /// Requesting site; `None` for the app itself (domain checks then fail closed).
    pub origin: Option<&'a BrowserOrigin>,
    /// Signing account.
    pub account: &'a Address,
    /// Active chain.
    pub active_chain_id: u64,
    /// Wall clock.
    pub now_unix_ms: u64,
}

fn now_ms_i128(now_unix_ms: u64) -> i128 {
    i128::from(now_unix_ms)
}

fn seconds_ms(seconds: i64) -> i128 {
    i128::from(seconds) * 1_000
}

/// The authority of a first line carrying the SIWE marker, read even when the rest of the
/// grammar fails (spec/03 §9.4: S01/S02 still apply to marker-only messages).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiweAuthority {
    /// `https` or `http` (`https` when absent).
    pub scheme: String,
    /// Lowercased host.
    pub host: String,
    /// Explicit port.
    pub port: Option<u16>,
    /// Whether the authority has userinfo (S02).
    pub has_userinfo: bool,
}

/// The authority before ` wants you to sign in with your Ethereum account` on the first line;
/// `None` without the marker or when the text before it is not a valid `[scheme "://"]`
/// authority (the caller then blocks with S01).
#[must_use]
pub fn marker_authority(text: &str) -> Option<SiweAuthority> {
    let first_line = text.split('\n').next()?;
    let (head, _) = first_line.split_once(MARKER_PHRASE)?;
    let (scheme, domain) = match head.split_once("://") {
        Some((scheme, domain)) if scheme == "https" || scheme == "http" => (scheme, domain),
        Some(_) => return None,
        None => ("https", head),
    };
    let (host, port, has_userinfo) = parse_authority(domain)?;
    Some(SiweAuthority {
        scheme: scheme.to_owned(),
        host,
        port,
        has_userinfo,
    })
}

/// S01, S02 and S05 of an authority against the requesting site (`None` = the app: S01).
fn domain_warnings(authority: &SiweAuthority, origin: Option<&BrowserOrigin>) -> Vec<Warning> {
    let mut warnings = Vec::new();
    match origin {
        Some(origin) => {
            if authority.host != origin.host() {
                warnings.push(risk::warning(S01, None));
            }
            if authority.scheme != origin.scheme() || authority.has_userinfo {
                warnings.push(risk::warning(S02, None));
            }
            if let Some(port) = authority.port
                && port != origin.effective_port()
            {
                warnings.push(risk::warning(S05, None));
            }
        }
        None => warnings.push(risk::warning(S01, None)),
    }
    warnings
}

/// The warnings of a marker-only message (`siwe_marker_only`): S08, plus the domain checks of
/// its first-line authority, or S01 (blocked) when no authority can be read.
#[must_use]
pub fn check_marker_only(text: &str, context: &SiweContext<'_>) -> Vec<Warning> {
    let mut warnings = vec![marker_only_warning()];
    match marker_authority(text) {
        Some(authority) => warnings.extend(domain_warnings(&authority, context.origin)),
        None => warnings.push(risk::warning(
            S01,
            Some("SIWE 형식의 첫 줄에서 도메인을 읽을 수 없습니다"),
        )),
    }
    warnings
}

/// The §9.4 warnings (S01–S07, S09) of a parsed message.
#[must_use]
pub fn check_siwe(message: &SiweMessage, context: &SiweContext<'_>) -> Vec<Warning> {
    let now = now_ms_i128(context.now_unix_ms);
    let mut warnings = domain_warnings(
        &SiweAuthority {
            scheme: message.scheme.clone(),
            host: message.domain_host.clone(),
            port: message.domain_port,
            has_userinfo: message.has_userinfo,
        },
        context.origin,
    );
    let checksum = parse_address(&message.address_text);
    if checksum == Err(AddressError::BadChecksum) || message.address != *context.account {
        warnings.push(risk::warning(S03, None));
    }
    if let Some(expiration) = message.expiration_time
        && seconds_ms(expiration) <= now
    {
        warnings.push(risk::warning(S04, None));
    }
    if message.chain_id != context.active_chain_id {
        warnings.push(risk::warning(S06, None));
    }
    if let Some(not_before) = message.not_before
        && seconds_ms(not_before) > now
    {
        warnings.push(risk::warning(S07, None));
    }
    if warnings.is_empty() {
        warnings.push(risk::warning(S09, None));
    }
    warnings
}

/// The S08 warning for marker-only messages.
#[must_use]
pub fn marker_only_warning() -> Warning {
    risk::warning(S08, None)
}
