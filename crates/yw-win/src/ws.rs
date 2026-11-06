#![allow(unsafe_code)]
//! Synchronous `WinHTTP` WebSocket client (spec/13 §4): `wss://` only (TLS 1.2/1.3, the same
//! session rules as [`crate::http`]: no redirects, cookies or automatic authentication), text
//! messages only. Used by the `WalletConnect` relay connection.
//!
//! Sequence (`WinHTTP` WebSocket API): `WinHttpOpen` → `WinHttpConnect` → `WinHttpOpenRequest
//! ("GET")` → `WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET` → `WinHttpSendRequest` →
//! `WinHttpReceiveResponse` (status must be 101) → `WinHttpWebSocketCompleteUpgrade`. One thread
//! may block in [`WebSocket::receive`] while another calls [`WebSocket::send_text`] (sends are
//! serialized by a lock); [`WebSocket::abort`] (`WinHttpWebSocketClose` with a 2 s close timeout)
//! makes a pending receive return. Handles close on drop. Errors carry no URL (the relay URL
//! holds the auth token and the project id).

use std::sync::Mutex;

use windows_sys::Win32::Networking::WinHttp::{
    ERROR_WINHTTP_SECURE_FAILURE, ERROR_WINHTTP_TIMEOUT, INTERNET_DEFAULT_HTTPS_PORT,
    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_DISABLE_AUTHENTICATION, WINHTTP_DISABLE_COOKIES,
    WINHTTP_DISABLE_REDIRECTS, WINHTTP_FLAG_SECURE, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2,
    WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3, WINHTTP_OPTION_DISABLE_FEATURE,
    WINHTTP_OPTION_REDIRECT_POLICY, WINHTTP_OPTION_REDIRECT_POLICY_NEVER,
    WINHTTP_OPTION_SECURE_PROTOCOLS, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET,
    WINHTTP_OPTION_WEB_SOCKET_CLOSE_TIMEOUT, WINHTTP_OPTION_WEB_SOCKET_KEEPALIVE_INTERVAL,
    WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE, WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE,
    WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE, WINHTTP_WEB_SOCKET_BUFFER_TYPE,
    WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS,
    WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
    WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders,
    WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetOption, WinHttpSetTimeouts,
    WinHttpWebSocketClose, WinHttpWebSocketCompleteUpgrade, WinHttpWebSocketReceive,
    WinHttpWebSocketSend,
};

use crate::error::WinError;
use crate::http::{HttpError, HttpsUrl};
use crate::wide::to_wide;

/// Largest text message accepted (relay frames are small; a bigger one is a protocol error).
pub const MAX_MESSAGE_BYTES: usize = 4 * 1_048_576;

/// A received frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WsMessage {
    /// A complete UTF-8 text message.
    Text(String),
    /// The peer closed the connection.
    Closed,
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

fn code_error(api: &'static str, code: u32) -> HttpError {
    match code {
        ERROR_WINHTTP_TIMEOUT => HttpError::Timeout,
        ERROR_WINHTTP_SECURE_FAILURE => HttpError::Tls,
        _ => HttpError::Os(WinError::new(api, code)),
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

/// An open WebSocket.
pub struct WebSocket {
    socket: Handle,
    // The session and connection handles outlive the WebSocket handle (closed after it: struct
    // fields drop in declaration order).
    _connect: Handle,
    _session: Handle,
    send_lock: Mutex<()>,
    receive_lock: Mutex<()>,
}

impl core::fmt::Debug for WebSocket {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("WebSocket")
    }
}

// SAFETY: WinHTTP WebSocket handles may be used from several threads; one send and one receive
// may be outstanding at a time, which the two locks enforce.
unsafe impl Send for WebSocket {}
// SAFETY: As above.
unsafe impl Sync for WebSocket {}

impl WebSocket {
    /// Opens `wss://host[:port]/path?query` (given as the equivalent `https://` URL) and
    /// completes the upgrade. `timeout_ms` bounds resolve, connect, send and the 101 response.
    ///
    /// # Errors
    ///
    /// [`HttpError`]; `Os(WinHttpReceiveResponse, status)` when the server answers without 101
    /// (e.g. 401 for a bad project id or auth token: the code is the HTTP status).
    #[expect(clippy::too_many_lines, reason = "one linear WinHTTP upgrade sequence")]
    pub fn connect(url: &HttpsUrl, timeout_ms: u32) -> Result<Self, HttpError> {
        let agent = to_wide("YourWallet/3", "WinHttpOpen").map_err(HttpError::Os)?;
        // SAFETY: `agent` is NUL-terminated and live; no proxy strings; synchronous mode.
        let session = Handle(unsafe {
            WinHttpOpen(
                agent.as_ptr(),
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                core::ptr::null(),
                core::ptr::null(),
                0,
            )
        });
        if session.0.is_null() {
            return Err(os_error("WinHttpOpen"));
        }
        set_u32_option(
            &session,
            WINHTTP_OPTION_SECURE_PROTOCOLS,
            WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3,
        )?;
        set_u32_option(
            &session,
            WINHTTP_OPTION_REDIRECT_POLICY,
            WINHTTP_OPTION_REDIRECT_POLICY_NEVER,
        )?;
        let timeout = i32::try_from(timeout_ms).unwrap_or(i32::MAX);
        // SAFETY: Sets resolve, connect, send and receive timeouts on our session handle.
        if unsafe { WinHttpSetTimeouts(session.0, timeout, timeout, timeout, timeout) } == 0 {
            return Err(os_error("WinHttpSetTimeouts"));
        }
        let host = to_wide(url.host(), "WinHttpConnect").map_err(|_| HttpError::InvalidUrl)?;
        let port = url.port().unwrap_or(INTERNET_DEFAULT_HTTPS_PORT);
        // SAFETY: Opens a connection handle under our session; `host` is NUL-terminated.
        let connect = Handle(unsafe { WinHttpConnect(session.0, host.as_ptr(), port, 0) });
        if connect.0.is_null() {
            return Err(os_error("WinHttpConnect"));
        }
        let verb = to_wide("GET", "WinHttpOpenRequest").map_err(|_| HttpError::InvalidUrl)?;
        let path = to_wide(url.path(), "WinHttpOpenRequest").map_err(|_| HttpError::InvalidUrl)?;
        // SAFETY: Strings are NUL-terminated and live; default version, no referrer or accept list.
        let request = Handle(unsafe {
            WinHttpOpenRequest(
                connect.0,
                verb.as_ptr(),
                path.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
                WINHTTP_FLAG_SECURE,
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
        // Keep-alive pings every 15 s (the minimum) so a dead connection fails the receive; set on
        // the request before the upgrade (best effort: older systems keep the 30 s default).
        let _ = set_u32_option(&request, WINHTTP_OPTION_WEB_SOCKET_KEEPALIVE_INTERVAL, 15_000);
        // SAFETY: The upgrade option takes no buffer (NULL, 0) on our request handle.
        if unsafe {
            WinHttpSetOption(
                request.0,
                WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET,
                core::ptr::null(),
                0,
            )
        } == 0
        {
            return Err(os_error("WinHttpSetOption"));
        }
        // SAFETY: No extra headers and no body for this synchronous call.
        let sent = unsafe {
            WinHttpSendRequest(
                request.0,
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                0,
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
        if status != 101 {
            return Err(HttpError::Os(WinError::new("WinHttpReceiveResponse", status)));
        }
        // SAFETY: Completes the upgrade of our request handle (no context).
        let socket = Handle(unsafe { WinHttpWebSocketCompleteUpgrade(request.0, 0) });
        if socket.0.is_null() {
            return Err(os_error("WinHttpWebSocketCompleteUpgrade"));
        }
        drop(request);
        set_u32_option(&socket, WINHTTP_OPTION_WEB_SOCKET_CLOSE_TIMEOUT, 2_000)?;
        Ok(Self {
            socket,
            _connect: connect,
            _session: session,
            send_lock: Mutex::new(()),
            receive_lock: Mutex::new(()),
        })
    }

    /// Sends one text message.
    ///
    /// # Errors
    ///
    /// [`HttpError`] (`TooLarge` above [`MAX_MESSAGE_BYTES`]).
    pub fn send_text(&self, text: &str) -> Result<(), HttpError> {
        if text.len() > MAX_MESSAGE_BYTES {
            return Err(HttpError::TooLarge);
        }
        let length = u32::try_from(text.len()).map_err(|_| HttpError::TooLarge)?;
        let _guard = self
            .send_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: `text` is live and `length` bytes long for this synchronous call.
        let code = unsafe {
            WinHttpWebSocketSend(
                self.socket.0,
                WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                text.as_ptr().cast(),
                length,
            )
        };
        if code != 0 {
            return Err(code_error("WinHttpWebSocketSend", code));
        }
        Ok(())
    }

    /// Blocks for the next complete text message (fragments joined); binary messages are
    /// skipped.
    ///
    /// # Errors
    ///
    /// [`HttpError`]: the connection failed or was aborted (`ERROR_WINHTTP_OPERATION_CANCELLED`),
    /// a message exceeded [`MAX_MESSAGE_BYTES`] (`TooLarge`) or was not UTF-8.
    pub fn receive(&self) -> Result<WsMessage, HttpError> {
        let _guard = self
            .receive_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut message: Vec<u8> = Vec::new();
        let mut chunk = vec![0_u8; 64 * 1_024];
        let chunk_len = u32::try_from(chunk.len()).unwrap_or(65_536);
        loop {
            let mut read = 0_u32;
            let mut kind: WINHTTP_WEB_SOCKET_BUFFER_TYPE = 0;
            // SAFETY: `chunk` is writable for `chunk_len` bytes; `read` and `kind` are writable.
            let code = unsafe {
                WinHttpWebSocketReceive(
                    self.socket.0,
                    chunk.as_mut_ptr().cast(),
                    chunk_len,
                    &raw mut read,
                    &raw mut kind,
                )
            };
            if code != 0 {
                return Err(code_error("WinHttpWebSocketReceive", code));
            }
            let got = chunk
                .get(..usize::try_from(read).unwrap_or(0))
                .ok_or(HttpError::TooLarge)?;
            match kind {
                WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE => return Ok(WsMessage::Closed),
                WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE
                | WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE
                | WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE
                | WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE => {
                    if message.len().saturating_add(got.len()) > MAX_MESSAGE_BYTES {
                        return Err(HttpError::TooLarge);
                    }
                    message.extend_from_slice(got);
                    match kind {
                        WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE => {
                            let text = String::from_utf8(core::mem::take(&mut message))
                                .map_err(|_| HttpError::InvalidHeader)?;
                            return Ok(WsMessage::Text(text));
                        }
                        WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE => message.clear(),
                        _ => {}
                    }
                }
                _ => return Err(HttpError::Os(WinError::new("WinHttpWebSocketReceive", 0))),
            }
        }
    }

    /// Closes the connection (normal closure); a receive blocked on another thread returns.
    pub fn abort(&self) {
        // SAFETY: Closes our WebSocket (status 1000, no reason buffer); the handle itself is
        // closed only on drop.
        let _ = unsafe {
            WinHttpWebSocketClose(
                self.socket.0,
                u16::try_from(WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS).unwrap_or(1000),
                core::ptr::null(),
                0,
            )
        };
    }
}
