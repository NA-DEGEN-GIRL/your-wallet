#![allow(unsafe_code)]
//! Synchronous `WinHTTP` client (spec/01 §7.4, D13, D21): HTTPS with TLS 1.2/1.3 only, or loopback
//! `http` for local LLM endpoints. No redirects, cookies, automatic authentication, Origin or
//! Referer. Errors never contain the URL or host.
//!
//! The URL, timeout, response and error types and the request limits live in
//! `yw_platform::http` (2026-11-17: moved there so platform-neutral code does not name yw-win);
//! this module holds only the `WinHTTP` [`Client`]. A `WinHTTP` failure other than a timeout or a
//! TLS failure is `HttpError::Os` with the `GetLastError` code (before 2026-11-17 it also carried
//! the API name).
//!
//! The `WinHTTP` timeouts are per phase and per receive, so a server that trickles its body could
//! keep a request alive indefinitely; every request therefore also has a total deadline (the sum
//! of the four phase timeouts). Before each phase the request handle gets that phase's timeout
//! capped by what is left of the total (`WinHttpSetTimeouts` before the send, plus
//! `WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT` before the response headers, whose 90 s default
//! `WinHttpSetTimeouts` does not change), and the body read loop shortens each receive the same
//! way.
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
    WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT, WINHTTP_OPTION_RECEIVE_TIMEOUT,
    WINHTTP_OPTION_REDIRECT_POLICY, WINHTTP_OPTION_REDIRECT_POLICY_NEVER,
    WINHTTP_OPTION_SECURE_PROTOCOLS, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_QUERY_CONTENT_TYPE,
    WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_FLAG_NUMBER64, WINHTTP_QUERY_STATUS_CODE,
    WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryDataAvailable,
    WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest,
    WinHttpSetOption, WinHttpSetTimeouts,
};

use yw_platform::http::{
    EndpointUrl, HttpError, HttpsUrl, MAX_CONTENT_TYPE_BYTES, MAX_REQUEST_BODY, MAX_RESPONSE_CAP,
    Response, Timeouts, valid_header,
};

use crate::error::WinError;
use crate::mem::WipeBuf;
use crate::wide::to_wide;

/// The host as `WinHttpConnect` takes it: an IPv6 literal without its brackets (`[::1]` →
/// `::1`), any other host unchanged. Shared with [`crate::ws`].
pub(crate) fn connect_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host)
}

/// The request target, read from an `HttpsUrl` or a `LoopbackUrl`.
struct Target<'a> {
    host: &'a str,
    port: Option<u16>,
    path: &'a str,
}

impl<'a> Target<'a> {
    fn https(url: &'a HttpsUrl) -> Self {
        Self {
            host: url.host(),
            port: url.port(),
            path: url.path(),
        }
    }
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
    match WinError::last(api).code {
        ERROR_WINHTTP_TIMEOUT => HttpError::Timeout,
        ERROR_WINHTTP_SECURE_FAILURE => HttpError::Tls,
        code => HttpError::Os(code),
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

/// `WinHttpSetTimeouts` on a request handle (resolve, connect, send, receive).
fn set_timeouts(handle: &Handle, phases: &PhaseTimeouts) -> Result<(), HttpError> {
    let to_i32 = |ms: u32| i32::try_from(ms).unwrap_or(i32::MAX);
    // SAFETY: Sets the four timeouts on our live request handle.
    let ok = unsafe {
        WinHttpSetTimeouts(
            handle.0,
            to_i32(phases.resolve),
            to_i32(phases.connect),
            to_i32(phases.send),
            to_i32(phases.receive),
        )
    };
    if ok == 0 {
        return Err(os_error("WinHttpSetTimeouts"));
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

/// The receive timeout for the next body read: what is left of the total deadline, at most
/// `receive_ms`, at least 1 ms; `None` once the deadline has passed.
fn next_receive_timeout(total: Duration, elapsed: Duration, receive_ms: u32) -> Option<u32> {
    let remaining = total.checked_sub(elapsed).filter(|left| !left.is_zero())?;
    let remaining_ms = u32::try_from(remaining.as_millis()).unwrap_or(u32::MAX);
    Some(remaining_ms.clamp(1, receive_ms.max(1)))
}

/// Per-request `WinHTTP` phase timeouts, each the configured phase timeout capped by what is
/// left of the total deadline (at least 1 ms), set on the request handle before the phase runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PhaseTimeouts {
    resolve: u32,
    connect: u32,
    send: u32,
    /// Also used for `WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT` (the response headers).
    receive: u32,
}

impl PhaseTimeouts {
    /// `None` once the total deadline has passed.
    fn remaining(timeouts: &Timeouts, total: Duration, elapsed: Duration) -> Option<Self> {
        let cap = |phase_ms: u32| next_receive_timeout(total, elapsed, phase_ms);
        Some(Self {
            resolve: cap(timeouts.resolve_ms)?,
            connect: cap(timeouts.connect_ms)?,
            send: cap(timeouts.send_ms)?,
            receive: cap(timeouts.receive_ms)?,
        })
    }
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
        let agent =
            to_wide("YourWallet/3", "WinHttpOpen").map_err(|error| HttpError::Os(error.code))?;
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
        let target = match (url, self.kind) {
            (EndpointUrl::Https(url), ClientKind::Https) => Target::https(url),
            (EndpointUrl::Loopback(url), ClientKind::Loopback) => Target {
                host: url.host(),
                port: url.port(),
                path: url.path(),
            },
            _ => return Err(HttpError::InvalidUrl),
        };
        let headers: Vec<(&str, &[u8])> = headers
            .iter()
            .map(|(name, value)| (*name, value.as_bytes()))
            .collect();
        self.request("POST", &target, &headers, Some(body), max_response)
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
        self.request(
            "POST",
            &Target::https(url),
            &headers,
            Some(body),
            max_response,
        )
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
            &Target::https(url),
            &[("Accept", b"application/json".as_slice())],
            None,
            max_response,
        )
    }

    #[expect(clippy::too_many_lines, reason = "one linear WinHTTP request sequence")]
    fn request(
        &self,
        verb: &str,
        target: &Target<'_>,
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
        let host = to_wide(connect_host(target.host), "WinHttpConnect")
            .map_err(|_| HttpError::InvalidUrl)?;
        let port = target.port.unwrap_or(if secure {
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
        let path = to_wide(target.path, "WinHttpOpenRequest").map_err(|_| HttpError::InvalidUrl)?;
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
        // Total deadline, connection phases: resolve, connect and send happen inside
        // `WinHttpSendRequest`; each is capped by what is left of the total.
        let phases = PhaseTimeouts::remaining(&self.timeouts, total, started.elapsed())
            .ok_or(HttpError::Timeout)?;
        set_timeouts(&request, &phases)?;
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
        // Total deadline, response headers: `WinHttpReceiveResponse` is bounded by
        // RECEIVE_RESPONSE_TIMEOUT (default 90 s, not set by `WinHttpSetTimeouts`) and each
        // receive by RECEIVE_TIMEOUT; both get what is left of the total.
        let phases = PhaseTimeouts::remaining(&self.timeouts, total, started.elapsed())
            .ok_or(HttpError::Timeout)?;
        set_timeouts(&request, &phases)?;
        set_u32_option(
            &request,
            WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT,
            phases.receive,
        )?;
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
        let status = u16::try_from(status).map_err(|_| HttpError::Os(0))?;
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
            // next wait is shortened to what is left (and the check above each read bounds the
            // loop).
            let wait_ms = next_receive_timeout(total, started.elapsed(), self.timeouts.receive_ms)
                .ok_or(HttpError::Timeout)?;
            if wait_ms < self.timeouts.receive_ms {
                set_u32_option(&request, WINHTTP_OPTION_RECEIVE_TIMEOUT, wait_ms)?;
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
        HttpError, PhaseTimeouts, Timeouts, connect_host, header_block, next_receive_timeout,
    };
    use std::time::Duration;

    #[test]
    fn phase_timeouts_are_capped_by_the_rest_of_the_total() {
        let timeouts = Timeouts {
            resolve_ms: 5_000,
            connect_ms: 5_000,
            send_ms: 10_000,
            receive_ms: 10_000,
        };
        let total = Duration::from_millis(timeouts.total_ms());
        let at = Duration::from_millis;
        assert_eq!(
            PhaseTimeouts::remaining(&timeouts, total, at(0)),
            Some(PhaseTimeouts {
                resolve: 5_000,
                connect: 5_000,
                send: 10_000,
                receive: 10_000,
            })
        );
        // 27 s spent in resolve/connect/send: the response headers get the last 3 s, not 90 s.
        assert_eq!(
            PhaseTimeouts::remaining(&timeouts, total, at(27_000)),
            Some(PhaseTimeouts {
                resolve: 3_000,
                connect: 3_000,
                send: 3_000,
                receive: 3_000,
            })
        );
        assert_eq!(PhaseTimeouts::remaining(&timeouts, total, at(30_000)), None);
    }

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

    /// `WinHttpConnect` gets an IPv6 literal without brackets (2026-11-17: shared with `ws`,
    /// which before passed the bracketed host).
    #[test]
    fn connect_host_strips_ipv6_brackets_only() {
        assert_eq!(connect_host("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(connect_host("[::1]"), "::1");
        assert_eq!(connect_host("relay.example"), "relay.example");
        assert_eq!(connect_host("127.0.0.1"), "127.0.0.1");
        assert_eq!(connect_host("[::1"), "[::1");
    }

    /// The header rule itself is tested in yw-platform (`tests/http.rs`).
    #[test]
    fn header_rules() {
        assert_eq!(
            header_block(&[("Bad Name", b"x".as_slice())]).map(|_| ()),
            Err(HttpError::InvalidHeader)
        );
        let block = header_block(&[("A", b"b".as_slice())]).unwrap();
        assert_eq!(String::from_utf16_lossy(block.as_slice()), "A: b\r\n");
    }
}
