#![allow(unsafe_code)]
//! Synchronous `WinHTTP` client (spec/01 §7.4, D13, D21): HTTPS with TLS 1.2/1.3 only, or loopback
//! `http` for local LLM endpoints. No redirects, cookies, automatic authentication, Origin or
//! Referer. Errors never contain the URL or host; `HttpsUrl` formats as `https://[redacted]`
//! because a whole RPC URL is a secret.
//!
//! The `WinHTTP` timeouts are per phase and per receive, so a server that trickles its body could
//! keep a request alive indefinitely; every request therefore also has a total deadline (the sum
//! of the four phase timeouts) that bounds the body read loop.
//!
//! Certificate revocation checking (`WINHTTP_ENABLE_SSL_REVOCATION`) is deliberately left off:
//! with it, an unreachable CRL/OCSP responder (captive portal, filtered network, offline
//! revocation infrastructure of a provider) fails the whole TLS handshake, which would make RPC
//! and LLM endpoints unusable in such networks. Chain validation itself is never weakened
//! (`SECURITY_FLAG_IGNORE_*` is not used).

use core::fmt;
use std::time::{Duration, Instant};

use windows_sys::Win32::Networking::WinHttp::{
    ERROR_WINHTTP_SECURE_FAILURE, ERROR_WINHTTP_TIMEOUT, INTERNET_DEFAULT_HTTP_PORT,
    INTERNET_DEFAULT_HTTPS_PORT, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_ACCESS_TYPE_NO_PROXY,
    WINHTTP_DISABLE_AUTHENTICATION, WINHTTP_DISABLE_COOKIES, WINHTTP_DISABLE_REDIRECTS,
    WINHTTP_FLAG_SECURE, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3,
    WINHTTP_OPTION_DISABLE_FEATURE, WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE,
    WINHTTP_OPTION_RECEIVE_TIMEOUT, WINHTTP_OPTION_REDIRECT_POLICY,
    WINHTTP_OPTION_REDIRECT_POLICY_NEVER, WINHTTP_OPTION_SECURE_PROTOCOLS,
    WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_QUERY_CONTENT_TYPE, WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_QUERY_FLAG_NUMBER64, WINHTTP_QUERY_STATUS_CODE, WinHttpCloseHandle, WinHttpConnect,
    WinHttpOpen, WinHttpOpenRequest, WinHttpQueryDataAvailable, WinHttpQueryHeaders,
    WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetOption,
    WinHttpSetTimeouts,
};

use crate::error::WinError;
use crate::mem::WipeBuf;
use crate::wide::to_wide;

/// Longest URL (bytes).
pub const MAX_URL_BYTES: usize = 2_048;
/// Largest request body.
pub const MAX_REQUEST_BODY: usize = 1_048_576;
/// Largest `max_response` honoured.
pub const MAX_RESPONSE_CAP: usize = 16 * 1_048_576;
const MAX_HEADER_VALUE: usize = 4_096;
const MAX_CONTENT_TYPE_BYTES: usize = 256;

/// HTTP failure. Contains no URL, host or response text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpError {
    /// The URL breaks the rules, or its kind does not match the client.
    InvalidUrl,
    /// A header name or value breaks the rules.
    InvalidHeader,
    /// `ERROR_WINHTTP_TIMEOUT`.
    Timeout,
    /// `ERROR_WINHTTP_SECURE_FAILURE`.
    Tls,
    /// Request or response exceeds its bound.
    TooLarge,
    /// Another `WinHTTP` failure.
    Os(WinError),
}

impl fmt::Display for HttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl => formatter.write_str("invalid URL"),
            Self::InvalidHeader => formatter.write_str("invalid header"),
            Self::Timeout => formatter.write_str("HTTP timeout"),
            Self::Tls => formatter.write_str("TLS failure"),
            Self::TooLarge => formatter.write_str("HTTP payload too large"),
            Self::Os(error) => write!(formatter, "{error}"),
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
    (1..=253).contains(&host.len())
        && host.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-'
        })
}

fn parse_parts(input: &str, scheme: &str) -> Result<Parts, HttpError> {
    if input.len() > MAX_URL_BYTES || !input.bytes().all(|byte| (0x21..=0x7E).contains(&byte)) {
        return Err(HttpError::InvalidUrl);
    }
    let rest = input.strip_prefix(scheme).ok_or(HttpError::InvalidUrl)?;
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
        (format!("[{literal}]"), after)
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

    /// The host (LLM endpoint display/log only; never for RPC endpoints, spec/01 §5.4).
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
        if text.starts_with("https://") {
            HttpsUrl::parse(text).map(Self::Https)
        } else if text.starts_with("http://") {
            LoopbackUrl::parse(text).map(Self::Loopback)
        } else {
            Err(HttpError::InvalidUrl)
        }
    }
}

/// Per-phase `WinHTTP` timeouts in milliseconds (no default; callers choose, spec/01 §7.4).
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

fn valid_header(name: &str, value: &[u8]) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && value.len() <= MAX_HEADER_VALUE
        && value.iter().all(|byte| (0x20..=0x7E).contains(byte))
}

/// Builds `Name: value\r\n…` as UTF-16 in a wiping buffer.
fn header_block(headers: &[(&str, &[u8])]) -> Result<WipeBuf<u16>, HttpError> {
    let mut total = 0_usize;
    for (name, value) in headers {
        if !valid_header(name, value) {
            return Err(HttpError::InvalidHeader);
        }
        total = total
            .saturating_add(name.len())
            .saturating_add(value.len())
            .saturating_add(4);
    }
    let mut block = WipeBuf::with_capacity(total);
    for (name, value) in headers {
        for unit in name
            .bytes()
            .chain(*b": ")
            .chain(value.iter().copied())
            .chain(*b"\r\n")
        {
            block
                .push(u16::from(unit))
                .map_err(|_| HttpError::InvalidHeader)?;
        }
    }
    Ok(block)
}

struct Handle(*mut core::ffi::c_void);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Closes a WinHTTP handle we opened, exactly once.
            unsafe { WinHttpCloseHandle(self.0) };
        }
    }
}

fn os_error(api: &'static str) -> HttpError {
    let error = WinError::last(api);
    match error.code {
        ERROR_WINHTTP_TIMEOUT => HttpError::Timeout,
        ERROR_WINHTTP_SECURE_FAILURE => HttpError::Tls,
        _ => HttpError::Os(error),
    }
}

fn set_u32_option(handle: &Handle, option: u32, value: u32) -> Result<(), HttpError> {
    // SAFETY: `value` is a live u32 whose size is passed; the handle is ours.
    let ok = unsafe {
        WinHttpSetOption(
            handle.0,
            option,
            (&raw const value).cast(),
            u32::try_from(core::mem::size_of::<u32>()).unwrap_or(4),
        )
    };
    if ok == 0 {
        return Err(os_error("WinHttpSetOption"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientKind {
    Https,
    Loopback,
}

/// A `WinHTTP` session (`Send + Sync`; each request opens its own connection handles).
pub struct Client {
    session: Handle,
    kind: ClientKind,
    timeouts: Timeouts,
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

/// The receive timeout for the next body read: what is left of the total deadline, at most
/// `receive_ms`, at least 1 ms; `None` once the deadline has passed.
fn next_receive_timeout(total: Duration, elapsed: Duration, receive_ms: u32) -> Option<u32> {
    let remaining = total.checked_sub(elapsed).filter(|left| !left.is_zero())?;
    let remaining_ms = u32::try_from(remaining.as_millis()).unwrap_or(u32::MAX);
    Some(remaining_ms.clamp(1, receive_ms.max(1)))
}

impl fmt::Debug for Client {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Client")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

// SAFETY: A WinHTTP session handle may be used from several threads for synchronous requests;
// all per-request state lives in handles created and closed inside `request`.
unsafe impl Send for Client {}
// SAFETY: As above; `&Client` only opens new connection/request handles under the session.
unsafe impl Sync for Client {}

impl Client {
    fn open(timeouts: Timeouts, kind: ClientKind) -> Result<Self, HttpError> {
        let agent = to_wide("YourWallet/3", "WinHttpOpen").map_err(HttpError::Os)?;
        let access = match kind {
            ClientKind::Https => WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            ClientKind::Loopback => WINHTTP_ACCESS_TYPE_NO_PROXY,
        };
        // SAFETY: `agent` is NUL-terminated and live; no proxy strings; synchronous mode.
        let session = Handle(unsafe {
            WinHttpOpen(
                agent.as_ptr(),
                access,
                core::ptr::null(),
                core::ptr::null(),
                0,
            )
        });
        if session.0.is_null() {
            return Err(os_error("WinHttpOpen"));
        }
        if kind == ClientKind::Https {
            set_u32_option(
                &session,
                WINHTTP_OPTION_SECURE_PROTOCOLS,
                WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3,
            )?;
        }
        set_u32_option(
            &session,
            WINHTTP_OPTION_REDIRECT_POLICY,
            WINHTTP_OPTION_REDIRECT_POLICY_NEVER,
        )?;
        set_u32_option(&session, WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE, 16_384)?;
        let to_i32 = |ms: u32| i32::try_from(ms).unwrap_or(i32::MAX);
        // SAFETY: Sets the four timeouts on our session handle.
        let ok = unsafe {
            WinHttpSetTimeouts(
                session.0,
                to_i32(timeouts.resolve_ms),
                to_i32(timeouts.connect_ms),
                to_i32(timeouts.send_ms),
                to_i32(timeouts.receive_ms),
            )
        };
        if ok == 0 {
            return Err(os_error("WinHttpSetTimeouts"));
        }
        Ok(Self {
            session,
            kind,
            timeouts,
        })
    }

    /// An HTTPS-only session (TLS 1.2 | 1.3; fails if that cannot be set).
    ///
    /// # Errors
    ///
    /// [`HttpError`].
    pub fn new(timeouts: Timeouts) -> Result<Self, HttpError> {
        Self::open(timeouts, ClientKind::Https)
    }

    /// A loopback-HTTP-only session (no proxy).
    ///
    /// # Errors
    ///
    /// [`HttpError`].
    pub fn new_loopback(timeouts: Timeouts) -> Result<Self, HttpError> {
        Self::open(timeouts, ClientKind::Loopback)
    }

    /// POSTs `body` with exactly the caller's headers.
    ///
    /// # Errors
    ///
    /// [`HttpError`]; `InvalidUrl` when the URL kind does not match the client.
    pub fn post(
        &self,
        url: &EndpointUrl,
        headers: &[(&str, &str)],
        body: &[u8],
        max_response: usize,
    ) -> Result<Response, HttpError> {
        let parts = match (url, self.kind) {
            (EndpointUrl::Https(url), ClientKind::Https) => &url.0,
            (EndpointUrl::Loopback(url), ClientKind::Loopback) => &url.0,
            _ => return Err(HttpError::InvalidUrl),
        };
        let headers: Vec<(&str, &[u8])> = headers
            .iter()
            .map(|(name, value)| (*name, value.as_bytes()))
            .collect();
        self.request("POST", parts, &headers, Some(body), max_response)
    }

    /// POSTs JSON with `Accept`/`Content-Type: application/json` and an optional bearer token.
    ///
    /// # Errors
    ///
    /// [`HttpError`].
    pub fn post_json(
        &self,
        url: &HttpsUrl,
        bearer: Option<&[u8]>,
        body: &[u8],
        max_response: usize,
    ) -> Result<Response, HttpError> {
        if self.kind != ClientKind::Https {
            return Err(HttpError::InvalidUrl);
        }
        let mut authorization =
            WipeBuf::<u8>::with_capacity(bearer.map_or(0, |token| token.len().saturating_add(7)));
        let mut headers: Vec<(&str, &[u8])> = vec![
            ("Accept", b"application/json".as_slice()),
            ("Content-Type", b"application/json".as_slice()),
        ];
        if let Some(token) = bearer {
            authorization
                .extend_from_slice(b"Bearer ")
                .and_then(|()| authorization.extend_from_slice(token))
                .map_err(|_| HttpError::InvalidHeader)?;
            headers.push(("Authorization", authorization.as_slice()));
        }
        self.request("POST", &url.0, &headers, Some(body), max_response)
    }

    /// GETs with `Accept: application/json`.
    ///
    /// # Errors
    ///
    /// [`HttpError`].
    pub fn get(&self, url: &HttpsUrl, max_response: usize) -> Result<Response, HttpError> {
        if self.kind != ClientKind::Https {
            return Err(HttpError::InvalidUrl);
        }
        self.request(
            "GET",
            &url.0,
            &[("Accept", b"application/json".as_slice())],
            None,
            max_response,
        )
    }

    #[expect(clippy::too_many_lines, reason = "one linear WinHTTP request sequence")]
    fn request(
        &self,
        verb: &str,
        parts: &Parts,
        headers: &[(&str, &[u8])],
        body: Option<&[u8]>,
        max_response: usize,
    ) -> Result<Response, HttpError> {
        let started = Instant::now();
        let total = Duration::from_millis(self.timeouts.total_ms());
        let body = body.unwrap_or(&[]);
        if body.len() > MAX_REQUEST_BODY {
            return Err(HttpError::TooLarge);
        }
        let max_response = max_response.min(MAX_RESPONSE_CAP);
        let block = header_block(headers)?;
        let secure = self.kind == ClientKind::Https;
        let host = parts
            .host
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(&parts.host);
        let host = to_wide(host, "WinHttpConnect").map_err(|_| HttpError::InvalidUrl)?;
        let port = parts.port.unwrap_or(if secure {
            INTERNET_DEFAULT_HTTPS_PORT
        } else {
            INTERNET_DEFAULT_HTTP_PORT
        });
        // SAFETY: Opens a connection handle under our session; `host` is NUL-terminated.
        let connect = Handle(unsafe { WinHttpConnect(self.session.0, host.as_ptr(), port, 0) });
        if connect.0.is_null() {
            return Err(os_error("WinHttpConnect"));
        }
        let verb = to_wide(verb, "WinHttpOpenRequest").map_err(|_| HttpError::InvalidUrl)?;
        let path = to_wide(&parts.path, "WinHttpOpenRequest").map_err(|_| HttpError::InvalidUrl)?;
        // SAFETY: Strings are NUL-terminated and live; default version, no referrer, no accept
        // type list.
        let request = Handle(unsafe {
            WinHttpOpenRequest(
                connect.0,
                verb.as_ptr(),
                path.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
                if secure { WINHTTP_FLAG_SECURE } else { 0 },
            )
        });
        if request.0.is_null() {
            return Err(os_error("WinHttpOpenRequest"));
        }
        set_u32_option(
            &request,
            WINHTTP_OPTION_DISABLE_FEATURE,
            WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_AUTHENTICATION,
        )?;
        let header_len = u32::try_from(block.len()).map_err(|_| HttpError::InvalidHeader)?;
        let body_len = u32::try_from(body.len()).map_err(|_| HttpError::TooLarge)?;
        let header_ptr = if block.is_empty() {
            core::ptr::null()
        } else {
            block.as_slice().as_ptr()
        };
        // SAFETY: The header block and body are live for this synchronous call and their exact
        // lengths are passed.
        let sent = unsafe {
            WinHttpSendRequest(
                request.0,
                header_ptr,
                header_len,
                body.as_ptr().cast(),
                body_len,
                body_len,
                0,
            )
        };
        if sent == 0 {
            return Err(os_error("WinHttpSendRequest"));
        }
        // SAFETY: Waits for the response on our request handle.
        if unsafe { WinHttpReceiveResponse(request.0, core::ptr::null_mut()) } == 0 {
            return Err(os_error("WinHttpReceiveResponse"));
        }
        let mut status = 0_u32;
        let mut status_len = u32::try_from(core::mem::size_of::<u32>()).unwrap_or(4);
        // SAFETY: `status` is writable for `status_len` bytes.
        let ok = unsafe {
            WinHttpQueryHeaders(
                request.0,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                core::ptr::null(),
                (&raw mut status).cast(),
                &raw mut status_len,
                core::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(os_error("WinHttpQueryHeaders"));
        }
        let status = u16::try_from(status)
            .map_err(|_| HttpError::Os(WinError::new("WinHttpQueryHeaders", 0)))?;
        let mut type_buffer = [0_u16; MAX_CONTENT_TYPE_BYTES / 2 + 1];
        let mut type_len = u32::try_from(core::mem::size_of_val(&type_buffer)).unwrap_or(0);
        // SAFETY: `type_buffer` is writable for `type_len` bytes.
        let type_ok = unsafe {
            WinHttpQueryHeaders(
                request.0,
                WINHTTP_QUERY_CONTENT_TYPE,
                core::ptr::null(),
                type_buffer.as_mut_ptr().cast(),
                &raw mut type_len,
                core::ptr::null_mut(),
            )
        };
        let content_type = (type_ok != 0)
            .then(|| {
                let units = usize::try_from(type_len).unwrap_or(0) / 2;
                type_buffer.get(..units).and_then(|units| {
                    (units.len() <= MAX_CONTENT_TYPE_BYTES
                        && units.iter().all(|unit| (0x20..=0x7E).contains(unit)))
                    .then(|| String::from_utf16_lossy(units))
                })
            })
            .flatten();
        let mut length = 0_u64;
        let mut length_len = u32::try_from(core::mem::size_of::<u64>()).unwrap_or(8);
        // SAFETY: `length` is writable for `length_len` bytes.
        let length_ok = unsafe {
            WinHttpQueryHeaders(
                request.0,
                WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER64,
                core::ptr::null(),
                (&raw mut length).cast(),
                &raw mut length_len,
                core::ptr::null_mut(),
            )
        };
        if length_ok != 0 && u64::try_from(max_response).is_ok_and(|max| length > max) {
            return Err(HttpError::TooLarge);
        }
        let mut body_out = Vec::new();
        loop {
            // Total deadline: a trickling body cannot outlive the sum of the phase timeouts. The
            // next wait is shortened to what is left (best effort; the check above each read
            // bounds the loop even if the option cannot be set).
            let wait_ms = next_receive_timeout(total, started.elapsed(), self.timeouts.receive_ms)
                .ok_or(HttpError::Timeout)?;
            if wait_ms < self.timeouts.receive_ms {
                let _ = set_u32_option(&request, WINHTTP_OPTION_RECEIVE_TIMEOUT, wait_ms);
            }
            let mut available = 0_u32;
            // SAFETY: `available` is writable.
            if unsafe { WinHttpQueryDataAvailable(request.0, &raw mut available) } == 0 {
                return Err(os_error("WinHttpQueryDataAvailable"));
            }
            if available == 0 {
                break;
            }
            let chunk = usize::try_from(available).map_err(|_| HttpError::TooLarge)?;
            let total = body_out
                .len()
                .checked_add(chunk)
                .ok_or(HttpError::TooLarge)?;
            if total > max_response {
                return Err(HttpError::TooLarge);
            }
            let start = body_out.len();
            body_out.resize(total, 0);
            let mut read = 0_u32;
            let target = body_out.get_mut(start..).ok_or(HttpError::TooLarge)?;
            // SAFETY: `target` is writable for `available` bytes; `read` is writable.
            if unsafe {
                WinHttpReadData(
                    request.0,
                    target.as_mut_ptr().cast(),
                    available,
                    &raw mut read,
                )
            } == 0
            {
                return Err(os_error("WinHttpReadData"));
            }
            body_out.truncate(start.saturating_add(usize::try_from(read).unwrap_or(0)));
            if read == 0 {
                break;
            }
        }
        Ok(Response {
            status,
            content_type,
            body: body_out,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EndpointUrl, HttpError, HttpsUrl, LoopbackUrl, Timeouts, header_block,
        next_receive_timeout, valid_header,
    };
    use std::time::Duration;

    #[test]
    fn total_deadline_bounds_each_receive() {
        let timeouts = Timeouts {
            resolve_ms: 5_000,
            connect_ms: 5_000,
            send_ms: 10_000,
            receive_ms: 10_000,
        };
        assert_eq!(timeouts.total_ms(), 30_000);
        let total = Duration::from_millis(timeouts.total_ms());
        let at = Duration::from_millis;
        assert_eq!(next_receive_timeout(total, at(0), 10_000), Some(10_000));
        assert_eq!(next_receive_timeout(total, at(25_000), 10_000), Some(5_000));
        assert_eq!(next_receive_timeout(total, at(29_999), 10_000), Some(1));
        assert_eq!(next_receive_timeout(total, at(30_000), 10_000), None);
        assert_eq!(next_receive_timeout(total, at(90_000), 10_000), None);
        let huge = Timeouts {
            resolve_ms: u32::MAX,
            connect_ms: u32::MAX,
            send_ms: u32::MAX,
            receive_ms: u32::MAX,
        };
        assert_eq!(huge.total_ms(), 4 * u64::from(u32::MAX));
    }

    #[test]
    fn https_url_accepts_and_normalizes() {
        let url =
            HttpsUrl::parse("https://Name.Ethereum-Sepolia.QuikNode.pro/tok_EN-123/").unwrap();
        assert_eq!(url.host(), "name.ethereum-sepolia.quiknode.pro");
        assert_eq!(url.path(), "/tok_EN-123/");
        assert_eq!(
            url.expose(),
            "https://name.ethereum-sepolia.quiknode.pro/tok_EN-123/"
        );
        assert_eq!(HttpsUrl::parse("https://h.example").unwrap().path(), "/");
        assert_eq!(
            HttpsUrl::parse("https://h.example:8443/x?y=1")
                .unwrap()
                .port(),
            Some(8443)
        );
        assert!(HttpsUrl::parse(&format!("https://h.example/{}", "a".repeat(2_028))).is_ok());
    }

    #[test]
    fn https_url_rejections() {
        for bad in [
            "http://example.com",
            "https://",
            "https://user@example.com/",
            "https://example.com/#frag",
            "https://example.com/a b",
            "https://exa_mple.com/",
            "https://example.com:0/",
            "https://example.com:65536/",
            "https://example.com:/",
            "https://example.com:08/",
            "https://[::1]/",
            "ftp://example.com/",
            "HTTPS://example.com/",
            "https://example.com/\u{e9}",
        ] {
            assert_eq!(HttpsUrl::parse(bad), Err(HttpError::InvalidUrl), "{bad}");
        }
        assert!(HttpsUrl::parse(&format!("https://h.example/{}", "a".repeat(2_040))).is_err());
    }

    #[test]
    fn https_url_formatting_never_shows_host_or_path() {
        let url = HttpsUrl::parse("https://secret-name.rpc.example/token-path/").unwrap();
        for shown in [format!("{url}"), format!("{url:?}")] {
            assert_eq!(shown, "https://[redacted]");
            assert!(!shown.contains("secret-name"));
            assert!(!shown.contains("token"));
        }
    }

    #[test]
    fn loopback_and_endpoint_dispatch() {
        assert!(LoopbackUrl::parse("http://127.0.0.1:11434/v1/chat/completions").is_ok());
        assert!(LoopbackUrl::parse("http://LOCALHOST/v1/chat/completions").is_ok());
        assert!(matches!(
            EndpointUrl::parse("http://[::1]:11434/v1/chat/completions"),
            Ok(EndpointUrl::Loopback(_))
        ));
        assert_eq!(
            EndpointUrl::parse("http://example.com/"),
            Err(HttpError::InvalidUrl)
        );
        assert_eq!(
            EndpointUrl::parse("http://127.0.0.2/"),
            Err(HttpError::InvalidUrl)
        );
        assert!(matches!(
            EndpointUrl::parse("https://api.example/v1/chat/completions"),
            Ok(EndpointUrl::Https(_))
        ));
        let shown = format!(
            "{}",
            LoopbackUrl::parse("http://localhost:8080/secret/path").unwrap()
        );
        assert_eq!(shown, "http://localhost:8080/…");
    }

    #[test]
    fn header_rules() {
        assert!(valid_header("Content-Type", b"application/json"));
        assert!(!valid_header("", b"x"));
        assert!(!valid_header("Bad Name", b"x"));
        assert!(!valid_header(&"a".repeat(65), b"x"));
        assert!(!valid_header("X", b"line\r\nbreak"));
        assert!(!valid_header("X", &[0x80]));
        assert!(!valid_header("X", &vec![b'a'; 4_097]));
        assert_eq!(
            header_block(&[("Bad Name", b"x".as_slice())]).map(|_| ()),
            Err(HttpError::InvalidHeader)
        );
        let block = header_block(&[("A", b"b".as_slice())]).unwrap();
        assert_eq!(String::from_utf16_lossy(block.as_slice()), "A: b\r\n");
    }
}
