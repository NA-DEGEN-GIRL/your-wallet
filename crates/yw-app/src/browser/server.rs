//! The named-pipe server (spec/05 §8): `\\.\pipe\YourWallet.v3.<SID>`, user-only DACL, first
//! instance only, remote clients rejected, at most 4 instances (yw-win `pipe::Server`). Each
//! connection: the hello within 2 s (`hello-ack` / `hello-reject` then close), then a reader
//! thread feeding [`BrowserCore::handle_frame`] and a writer thread assigning the outbound
//! `sequence` (1, 2, … per connection, responses and events alike). A framing error or EOF closes
//! only that connection; its pending approvals are cancelled without a response.
//!
//! SDDL and flags were compared with `archive/spec-v2.4:crates/platform-windows/src/
//! broker_channel.rs:505-558,889-918` (its random pipe naming is not used).
//!
//! 2026-11-21 (S4 W1, plan §3.3): also [`PipeHost`], the shell's end of the bridge (the server,
//! its start failure and the read worker threads), cut out of the wallet's `BrowserUi`.

use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use yw_engine::browser::read::{ReadContext, run_worker};
use yw_engine::browser::{READ_WORKERS, pinned_origin};
use yw_engine::errors::ErrorCode;
use yw_json::frame::{MAX_FRAME_BYTES, read_frame, write_frame};
use yw_win::pipe::{Duplex, PipeReader, PipeWriter, Server, ServerError, ServerStop};

use super::envelope::{
    encode_event, encode_hello_ack, encode_hello_reject, encode_response, parse_hello,
};
use super::{BrowserCore, HELLO_TIMEOUT_MS, Outbound};
use crate::logging::{self, Field};

/// The running server.
pub struct PipeServer {
    stop: ServerStop,
    thread: Option<JoinHandle<()>>,
}

impl core::fmt::Debug for PipeServer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PipeServer")
    }
}

impl PipeServer {
    /// Stops accepting (spec/04 §1.5-1); live connections end with the process.
    pub fn stop(&mut self) {
        self.stop.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The shell's end of the browser bridge (spec/05 §8.1; 2026-11-21, S4 W1, plan §3.3, spec/15
/// §11.4 S4: shell state, `App::pipe`): the named-pipe server, why there is none, and the read
/// worker threads that serve the dispatcher. Before W1 these were the fields `server`,
/// `pipe_error` and `threads` of `app_browser::BrowserUi`, which keeps the dispatcher and its
/// state (wallet).
pub struct PipeHost {
    /// The server (`None`: see [`Self::error`]).
    pub server: Option<PipeServer>,
    /// Why there is no server: E-PIPE-001, or E-PIPE-002 when the pipe name was already held
    /// by another server (`ServerError::AlreadyExists`).
    pub error: Option<ErrorCode>,
    /// Read worker threads.
    pub threads: Vec<JoinHandle<()>>,
}

impl core::fmt::Debug for PipeHost {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PipeHost")
            .field("server", &self.server.is_some())
            .field("error", &self.error)
            .field("threads", &self.threads.len())
            .finish()
    }
}

impl PipeHost {
    /// Starts the 4 read workers on the dispatcher `core` and its read context `reads`, then the
    /// pipe server (spec/05 §8.1: within 2 s of process start). A server failure keeps the
    /// dispatcher (E-PIPE-001 banner by the caller) and is logged here. 2026-11-21 (S4 W1): the
    /// second half of the old `BrowserUi::start`, moved unchanged (`BrowserUi::new` is the
    /// first).
    #[must_use]
    pub fn start(core: &Arc<BrowserCore>, reads: &Arc<ReadContext>) -> Self {
        let mut threads = Vec::new();
        for index in 0..READ_WORKERS {
            let worker_core = Arc::clone(core);
            let context = Arc::clone(reads);
            if let Ok(handle) = std::thread::Builder::new()
                .name(format!("yw-read-{index}"))
                .spawn(move || run_worker(&worker_core, &context))
            {
                threads.push(handle);
            }
        }
        let started = match (pinned_origin(), pipe_name()) {
            (Some(origin), Ok(name)) => start(Arc::clone(core), &name, origin).map_err(Some),
            _ => Err(None),
        };
        // `AlreadyExists` with the single-instance mutex held: the per-user pipe name was taken
        // by a server this app did not create (spec/05 §8.1, E-PIPE-002).
        let pipe_squatted = matches!(started, Err(Some(ServerError::AlreadyExists)));
        let server = started.ok();
        let error = match (&server, pipe_squatted) {
            (Some(_), _) => None,
            (None, true) => Some(ErrorCode::Pipe002),
            (None, false) => Some(ErrorCode::Pipe001),
        };
        if pipe_squatted {
            logging::warn(
                "pipe",
                "server.squatted",
                &[("code", Field::Code(ErrorCode::Pipe002))],
            );
        } else if server.is_none() {
            logging::warn(
                "pipe",
                "server.failed",
                &[("code", Field::Code(ErrorCode::Pipe001))],
            );
        }
        Self {
            server,
            error,
            threads,
        }
    }

    /// Stops accepting (shutdown, spec/04 §1.5-1; 2026-11-21, S4 W1: the first half of the old
    /// `BrowserUi::stop`, which now stops the dispatcher after it).
    pub fn stop(&mut self) {
        if let Some(server) = self.server.as_mut() {
            server.stop();
        }
    }
}

/// The pipe name: debug builds honour `YW_TEST_PIPE_NAME` (headless tests, like yw-host).
///
/// # Errors
///
/// [`yw_win::WinError`] when the user SID cannot be read.
pub fn pipe_name() -> Result<String, yw_win::WinError> {
    if cfg!(debug_assertions)
        && let Some(name) = std::env::var_os("YW_TEST_PIPE_NAME").and_then(|n| n.into_string().ok())
        && name.starts_with(r"\\.\pipe\")
    {
        return Ok(name);
    }
    Ok(yw_win::pipe::wallet_pipe_name(
        &yw_win::current_user_sid_string()?,
    ))
}

/// Minimum gap between two `accept.failed` warnings: a pipe squatter (another owner holding the
/// name after our instances closed, `ServerError::AlreadyExists`) fails every attempt.
pub const ACCEPT_WARN_INTERVAL_MS: u64 = 60_000;
/// Retry delay after a squatted name (other failures retry after 100 ms).
const SQUATTED_RETRY_MS: u64 = 1_000;

/// Rate limit of the accept-loop warning: the first failure of a run is logged at once, later
/// ones at most every [`ACCEPT_WARN_INTERVAL_MS`] with the number left out in between.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AcceptWarnings {
    last_ms: Option<u64>,
    suppressed: u64,
    failures: u64,
}

impl AcceptWarnings {
    /// A failed accept at `now_ms`: `Some(suppressed)` when a warning is due now.
    pub const fn failed(&mut self, now_ms: u64) -> Option<u64> {
        self.failures = self.failures.saturating_add(1);
        let due = match self.last_ms {
            None => true,
            Some(last) => now_ms.saturating_sub(last) >= ACCEPT_WARN_INTERVAL_MS,
        };
        if due {
            let suppressed = self.suppressed;
            self.last_ms = Some(now_ms);
            self.suppressed = 0;
            Some(suppressed)
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
            None
        }
    }

    /// A successful accept: the number of failures since the last success (0 = nothing to
    /// report); the limiter starts over.
    pub const fn succeeded(&mut self) -> u64 {
        let failures = self.failures;
        *self = Self {
            last_ms: None,
            suppressed: 0,
            failures: 0,
        };
        failures
    }
}

/// Creates the first instance (call at startup, spec/05 §8.1) and starts the accept thread.
///
/// # Errors
///
/// [`ServerError`] (`AlreadyExists`: another instance owns the name).
pub fn start(
    core: Arc<BrowserCore>,
    name: &str,
    pinned_origin: String,
) -> Result<PipeServer, ServerError> {
    let sid = yw_win::current_user_sid_string().map_err(ServerError::Os)?;
    let mut server = Server::create(name, &yw_win::pipe::user_only_sddl(&sid))?;
    let stop = server.stop_handle();
    let thread = std::thread::Builder::new()
        .name("yw-pipe".to_owned())
        .spawn(move || {
            let mut warnings = AcceptWarnings::default();
            loop {
                match server.accept() {
                    Ok(duplex) => {
                        let failures = warnings.succeeded();
                        if failures > 0 {
                            logging::info(
                                "pipe",
                                "accept.recovered",
                                &[("failures", Field::Num(failures))],
                            );
                        }
                        connection(&core, duplex, &pinned_origin);
                    }
                    Err(ServerError::Stopped) => break,
                    Err(error) => {
                        let squatted = matches!(error, ServerError::AlreadyExists);
                        if let Some(suppressed) = warnings.failed(yw_win::time::monotonic_ms()) {
                            logging::warn(
                                "pipe",
                                "accept.failed",
                                &[
                                    (
                                        "reason",
                                        Field::Word(if squatted { "squatted" } else { "os" }),
                                    ),
                                    ("suppressed", Field::Num(suppressed)),
                                ],
                            );
                        }
                        std::thread::sleep(Duration::from_millis(if squatted {
                            SQUATTED_RETRY_MS
                        } else {
                            100
                        }));
                    }
                }
            }
        })
        .map_err(|_| ServerError::Os(yw_win::WinError::new("CreateThread", 0)))?;
    Ok(PipeServer {
        stop,
        thread: Some(thread),
    })
}

fn connection(core: &Arc<BrowserCore>, duplex: Duplex, pinned_origin: &str) {
    let client_pid = duplex.client_pid().unwrap_or(0);
    let core = Arc::clone(core);
    let pinned = pinned_origin.to_owned();
    let spawned = std::thread::Builder::new()
        .name("yw-pipe-conn".to_owned())
        .spawn(move || serve(&core, duplex, &pinned, client_pid));
    if spawned.is_err() {
        logging::warn("pipe", "thread.failed", &[]);
    }
}

/// The hello exchange (spec/05 §8.2): `true` when the connection may carry envelopes.
fn hello_exchange(
    reader: &mut PipeReader,
    writer: &mut PipeWriter,
    pinned_origin: &str,
    client_pid: u32,
) -> bool {
    // Hello within 2 s: a watchdog cancels the blocked read. Cancels are sticky, so the state
    // (`None` waiting, `Some(true)` received, `Some(false)` timed out) is decided under a lock.
    let hello_state: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let watchdog = {
        let state = Arc::clone(&hello_state);
        let canceller = reader.cancel_handle();
        std::thread::Builder::new()
            .name("yw-pipe-hello".to_owned())
            .spawn(move || {
                let mut waited = 0;
                loop {
                    std::thread::sleep(Duration::from_millis(20));
                    waited += 20;
                    let Ok(mut state) = state.lock() else {
                        return;
                    };
                    if state.is_some() {
                        return;
                    }
                    if waited >= HELLO_TIMEOUT_MS {
                        *state = Some(false);
                        canceller.cancel();
                        return;
                    }
                }
            })
    };
    let hello = read_frame(reader, MAX_FRAME_BYTES);
    let in_time = hello_state.lock().is_ok_and(|mut state| {
        if state.is_none() {
            *state = Some(true);
        }
        *state == Some(true)
    });
    if let Ok(watchdog) = watchdog {
        let _ = watchdog.join();
    }
    let (true, Ok(Some(frame))) = (in_time, hello) else {
        logging::info(
            "pipe",
            "hello.missing",
            &[("pid", Field::Num(u64::from(client_pid)))],
        );
        return false;
    };
    match parse_hello(&frame, pinned_origin) {
        Ok(hello) => {
            if write_frame(
                writer,
                &encode_hello_ack(env!("CARGO_PKG_VERSION")),
                MAX_FRAME_BYTES,
            )
            .is_err()
            {
                return false;
            }
            logging::info(
                "pipe",
                "connected",
                &[
                    ("pid", Field::Num(u64::from(client_pid))),
                    ("host_pid", Field::Num(u64::from(hello.pid))),
                ],
            );
            true
        }
        Err(reject) => {
            let _ = write_frame(writer, &encode_hello_reject(reject), MAX_FRAME_BYTES);
            logging::warn(
                "pipe",
                "hello.rejected",
                &[
                    ("reason", Field::Word(reject.reason())),
                    ("pid", Field::Num(u64::from(client_pid))),
                ],
            );
            false
        }
    }
}

fn serve(core: &Arc<BrowserCore>, duplex: Duplex, pinned_origin: &str, client_pid: u32) {
    let (mut reader, mut writer) = duplex.split();
    let canceller = reader.cancel_handle();
    if !hello_exchange(&mut reader, &mut writer, pinned_origin, client_pid) {
        return;
    }
    let (sender, receiver) = mpsc::channel::<Outbound>();
    let conn = core.open_connection(Box::new(sender));
    let writer_thread = std::thread::Builder::new()
        .name("yw-pipe-write".to_owned())
        .spawn(move || {
            write_loop(&receiver, &mut writer);
            canceller.cancel();
        });
    loop {
        match read_frame(&mut reader, MAX_FRAME_BYTES) {
            Ok(Some(frame)) => core.handle_frame(conn, &frame),
            Ok(None) => break,
            Err(_) => {
                logging::info("pipe", "frame.error", &[("conn", Field::Num(conn))]);
                break;
            }
        }
    }
    core.close_connection(conn);
    if let Ok(thread) = writer_thread {
        let _ = thread.join();
    }
    logging::info("pipe", "closed", &[("conn", Field::Num(conn))]);
}

fn write_loop(receiver: &Receiver<Outbound>, writer: &mut PipeWriter) {
    let mut sequence: u64 = 0;
    for outbound in receiver {
        sequence = sequence.saturating_add(1);
        let bytes = match &outbound {
            Outbound::Response { correlation, body } => {
                encode_response(correlation, sequence, body.as_ref())
            }
            Outbound::Event {
                session_id,
                activation_nonce,
                event,
            } => encode_event(session_id, sequence, activation_nonce, event),
        };
        if write_frame(writer, &bytes, MAX_FRAME_BYTES).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ACCEPT_WARN_INTERVAL_MS, AcceptWarnings};

    /// A squatted pipe name fails every accept: one warning at once, then at most one per
    /// interval carrying the number left out; a success reports the failures and starts over.
    #[test]
    fn accept_warnings_are_rate_limited() {
        let mut warnings = AcceptWarnings::default();
        assert_eq!(warnings.failed(1_000), Some(0));
        for step in 1..=50 {
            assert_eq!(warnings.failed(1_000 + step * 1_000), None);
        }
        assert_eq!(warnings.failed(1_000 + ACCEPT_WARN_INTERVAL_MS - 1), None);
        assert_eq!(warnings.failed(1_000 + ACCEPT_WARN_INTERVAL_MS), Some(51));
        assert_eq!(warnings.failed(1_000 + ACCEPT_WARN_INTERVAL_MS + 10), None);
        assert_eq!(warnings.succeeded(), 54);
        assert_eq!(warnings.succeeded(), 0);
        assert_eq!(warnings.failed(500_000), Some(0), "logged at once again");
    }
}
