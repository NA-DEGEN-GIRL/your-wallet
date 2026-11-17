//! HTTP client types (spec/01 §7.4, D13, D21): URLs, timeouts, the response, the error, the
//! request limits and the RPC [`Transport`] seam. The client itself is per platform (Windows:
//! `yw_win::http::Client`, which implements [`Transport`]).
//!
//! Errors never contain the URL or host; `HttpsUrl` formats as `https://[redacted]` because a
//! whole RPC URL is a secret.
//!
//! 2026-11-17: moved out of yw-win `http` unchanged, except that [`HttpError::Os`] now carries
//! only the OS error code (before: the Win32 API name and code) and the WebSocket non-101 answer
//! has its own [`HttpError::UpgradeRefused`] (before: `Os` with the API name
//! `WinHttpReceiveResponse` and the HTTP status as the code).

use core::fmt;

/// Longest URL (bytes).
pub const MAX_URL_BYTES: usize = 2_048;
/// Largest request body.
pub const MAX_REQUEST_BODY: usize = 1_048_576;
/// Largest `max_response` honoured.
pub const MAX_RESPONSE_CAP: usize = 16 * 1_048_576;
/// Longest header value (bytes).
pub const MAX_HEADER_VALUE: usize = 4_096;
/// Longest `Content-Type` kept in a [`Response`] (bytes).
pub const MAX_CONTENT_TYPE_BYTES: usize = 256;

/// HTTP failure. Contains no URL, host or response text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpError {
    /// The URL breaks the rules, or its kind does not match the client.
    InvalidUrl,
    /// A header name or value breaks the rules.
    InvalidHeader,
    /// The OS HTTP stack timed out (Windows: `ERROR_WINHTTP_TIMEOUT`).
    Timeout,
    /// TLS failed (Windows: `ERROR_WINHTTP_SECURE_FAILURE`).
    Tls,
    /// Request or response exceeds its bound.
    TooLarge,
    /// WebSocket only (`yw_win::ws`): the server answered the upgrade with this HTTP status
    /// instead of 101 (e.g. 401/403 for a refused `WalletConnect` project id or auth token). A plain
    /// HTTP request never produces it; its status is in [`Response::status`].
    UpgradeRefused(u16),
    /// Another OS failure: the OS error code only (no API name, URL or text).
    Os(u32),
}

impl fmt::Display for HttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl => formatter.write_str("invalid URL"),
            Self::InvalidHeader => formatter.write_str("invalid header"),
            Self::Timeout => formatter.write_str("HTTP timeout"),
            Self::Tls => formatter.write_str("TLS failure"),
            Self::TooLarge => formatter.write_str("HTTP payload too large"),
            Self::UpgradeRefused(status) => {
                write!(formatter, "WebSocket upgrade refused: HTTP {status}")
            }
            Self::Os(code) => write!(formatter, "OS error 0x{code:08X}"),
        }
    }
}

impl std::error::Error for HttpError {}

#[derive(Clone, PartialEq, Eq)]
struct Parts {
    text: String,
    host: String,
    port: Option<u16>,
    path: String,
}

fn valid_https_host(host: &str) -> bool {
    if let Some(literal) = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return valid_ipv6_literal(literal);
    }
    (1..=253).contains(&host.len())
        && host.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-'
        })
}

/// A bracketed IPv6 literal's inside (already lowercased): hex groups and `:` (one `::`), an
/// optional dotted IPv4 tail, no zone id (`%`), 2–45 bytes. The OS connect call gets it without
/// the brackets, like the loopback `[::1]`.
fn valid_ipv6_literal(literal: &str) -> bool {
    (2..=45).contains(&literal.len())
        && literal.contains(':')
        && literal.matches("::").count() <= 1
        && !literal.contains(":::")
        && literal
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b':' || byte == b'.')
        && literal
            .split(':')
            .all(|group| group.len() <= 4 || (group.contains('.') && group.split('.').count() == 4))
}

/// `input` without its `scheme` prefix, the scheme compared case-insensitively (RFC 3986 §3.1;
/// the normalized text is lowercase).
fn strip_scheme<'a>(input: &'a str, scheme: &str) -> Option<&'a str> {
    let head = input.get(..scheme.len())?;
    head.eq_ignore_ascii_case(scheme)
        .then(|| input.get(scheme.len()..))
        .flatten()
}

fn parse_parts(input: &str, scheme: &str) -> Result<Parts, HttpError> {
    if input.len() > MAX_URL_BYTES || !input.bytes().all(|byte| (0x21..=0x7E).contains(&byte)) {
        return Err(HttpError::InvalidUrl);
    }
    let rest = strip_scheme(input, scheme).ok_or(HttpError::InvalidUrl)?;
    if rest.contains('#') {
        return Err(HttpError::InvalidUrl);
    }
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(split);
    if authority.is_empty() || authority.contains('@') {
        return Err(HttpError::InvalidUrl);
    }
    let path = if tail.is_empty() {
        "/".to_owned()
    } else if tail.starts_with('/') {
        tail.to_owned()
    } else {
        format!("/{tail}")
    };
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let close = inner.find(']').ok_or(HttpError::InvalidUrl)?;
        let (literal, after) = inner.split_at(close);
        let after = after.get(1..).unwrap_or("");
        if !after.is_empty() && !after.starts_with(':') {
            return Err(HttpError::InvalidUrl);
        }
        (format!("[{}]", literal.to_ascii_lowercase()), after)
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host.to_ascii_lowercase(), port),
            None => (authority.to_ascii_lowercase(), ""),
        }
    };
    let port = if port.is_empty() {
        if authority.ends_with(':') {
            return Err(HttpError::InvalidUrl);
        }
        None
    } else {
        let digits = port.strip_prefix(':').unwrap_or(port);
        if digits.is_empty()
            || digits.len() > 5
            || digits.starts_with('0')
            || !digits.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(HttpError::InvalidUrl);
        }
        let value: u16 = digits.parse().map_err(|_| HttpError::InvalidUrl)?;
        Some(value)
    };
    let mut text = String::with_capacity(input.len());
    text.push_str(scheme);
    text.push_str(&host);
    if let Some(port) = port {
        text.push(':');
        text.push_str(&port.to_string());
    }
    text.push_str(if tail.is_empty() { "" } else { &path });
    Ok(Parts {
        text,
        host,
        port,
        path,
    })
}

/// An `https://` URL (rules of spec/01 §7.4). The whole URL is treated as secret: `Debug` and
/// `Display` show only `https://[redacted]`.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpsUrl(Parts);

impl HttpsUrl {
    /// Parses and normalizes (lowercase host) an HTTPS URL: `https://` only, host
    /// `[a-z0-9.-]{1,253}`, optional port 1–65535, printable-ASCII path without spaces, ≤ 2048
    /// bytes, no userinfo or fragment.
    ///
    /// # Errors
    ///
    /// [`HttpError::InvalidUrl`].
    pub fn parse(text: &str) -> Result<Self, HttpError> {
        let parts = parse_parts(text, "https://")?;
        if !valid_https_host(&parts.host) {
            return Err(HttpError::InvalidUrl);
        }
        Ok(Self(parts))
    }

    /// The host, lowercase; an IPv6 literal keeps its brackets. For the transport's use; never
    /// log it for an RPC endpoint (spec/01 §5.4).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.0.host
    }

    /// The normalized URL text. Secret: store it encrypted, never log or display it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0.text
    }

    /// The path (with query), starting with `/`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.0.path
    }

    /// The explicit port, if any.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.0.port
    }
}

impl fmt::Debug for HttpsUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("https://[redacted]")
    }
}

impl fmt::Display for HttpsUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("https://[redacted]")
    }
}

/// An `http://` loopback URL (`127.0.0.1`, `localhost`, `[::1]`).
#[derive(Clone, PartialEq, Eq)]
pub struct LoopbackUrl(Parts);

impl LoopbackUrl {
    /// Parses a loopback URL with the same port/path/length rules as [`HttpsUrl`].
    ///
    /// # Errors
    ///
    /// [`HttpError::InvalidUrl`].
    pub fn parse(text: &str) -> Result<Self, HttpError> {
        let parts = parse_parts(text, "http://")?;
        if !matches!(parts.host.as_str(), "127.0.0.1" | "localhost" | "[::1]") {
            return Err(HttpError::InvalidUrl);
        }
        Ok(Self(parts))
    }

    /// The host: `127.0.0.1`, `localhost` or `[::1]` (with brackets).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.0.host
    }

    /// The path (with query), starting with `/`. For the transport's use only: `Display` hides
    /// it and it is never logged (D28, spec/01 §5.4).
    #[must_use]
    pub fn path(&self) -> &str {
        &self.0.path
    }

    /// The explicit port, if any.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.0.port
    }
}

impl fmt::Debug for LoopbackUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for LoopbackUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.port {
            Some(port) => write!(formatter, "http://{}:{port}/…", self.0.host),
            None => write!(formatter, "http://{}/…", self.0.host),
        }
    }
}

/// An LLM endpoint (D21). RPC endpoints are [`HttpsUrl`] only (D13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndpointUrl {
    /// HTTPS.
    Https(HttpsUrl),
    /// Loopback HTTP.
    Loopback(LoopbackUrl),
}

impl EndpointUrl {
    /// Dispatches on the scheme.
    ///
    /// # Errors
    ///
    /// [`HttpError::InvalidUrl`].
    pub fn parse(text: &str) -> Result<Self, HttpError> {
        if strip_scheme(text, "https://").is_some() {
            HttpsUrl::parse(text).map(Self::Https)
        } else if strip_scheme(text, "http://").is_some() {
            LoopbackUrl::parse(text).map(Self::Loopback)
        } else {
            Err(HttpError::InvalidUrl)
        }
    }
}

/// Per-phase HTTP timeouts in milliseconds (no default; callers choose, spec/01 §7.4). A
/// request's total deadline is [`Timeouts::total_ms`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_field_names,
    reason = "field names are fixed by spec/01 §7.4"
)]
pub struct Timeouts {
    /// Name resolution.
    pub resolve_ms: u32,
    /// Connect.
    pub connect_ms: u32,
    /// Send.
    pub send_ms: u32,
    /// Receive.
    pub receive_ms: u32,
}

impl Timeouts {
    /// The total deadline of one request: the sum of the four phase timeouts (saturating).
    #[must_use]
    pub fn total_ms(&self) -> u64 {
        u64::from(self.resolve_ms)
            .saturating_add(u64::from(self.connect_ms))
            .saturating_add(u64::from(self.send_ms))
            .saturating_add(u64::from(self.receive_ms))
    }
}

/// An HTTP response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// `Content-Type` when present, ASCII and ≤ 256 bytes.
    pub content_type: Option<String>,
    /// Body.
    pub body: Vec<u8>,
}

/// The header rule: name `[A-Za-z0-9-]{1,64}`, value printable ASCII (0x20–0x7E) of at most
/// [`MAX_HEADER_VALUE`] bytes (no CR/LF, so no header injection).
#[must_use]
pub fn valid_header(name: &str, value: &[u8]) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && value.len() <= MAX_HEADER_VALUE
        && value.iter().all(|byte| (0x20..=0x7E).contains(byte))
}

/// A raw HTTP reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpReply {
    /// Status.
    pub status: u16,
    /// Body.
    pub body: Vec<u8>,
}

/// The transport seam of the RPC pipelines (spec/01 §2.3a): the platform HTTP client (Windows:
/// `yw_win::http::Client`, `WinHTTP`) or a fake in tests. 2026-11-17 S2: moved unchanged from
/// yw-app `rpc` (which re-exports it).
pub trait Transport: Send + Sync {
    /// POSTs a JSON body.
    ///
    /// # Errors
    ///
    /// [`HttpError`].
    fn post_json(
        &self,
        url: &HttpsUrl,
        body: &[u8],
        max_response: usize,
    ) -> Result<HttpReply, HttpError>;

    /// GETs `url` with `Accept: application/json` and returns status, `Content-Type` and body
    /// (Bitcoin `esplora`/`bb-rest` indexers, spec/08 §4.1). Transports that only speak JSON-RPC
    /// keep the default, which sends nothing and fails with [`HttpError::InvalidUrl`].
    ///
    /// # Errors
    ///
    /// [`HttpError`].
    fn http_get(&self, _url: &HttpsUrl, _max_response: usize) -> Result<Response, HttpError> {
        Err(HttpError::InvalidUrl)
    }

    /// POSTs `body` with exactly `Content-Type: text/plain` (only the user-confirmed Esplora
    /// `POST /tx`, spec/08 §11.3). The default sends nothing and fails with
    /// [`HttpError::InvalidUrl`].
    ///
    /// # Errors
    ///
    /// [`HttpError`].
    fn http_post_text(
        &self,
        _url: &HttpsUrl,
        _body: &[u8],
        _max_response: usize,
    ) -> Result<Response, HttpError> {
        Err(HttpError::InvalidUrl)
    }
}
