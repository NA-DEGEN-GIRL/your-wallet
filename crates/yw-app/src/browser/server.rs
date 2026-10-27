//! The named-pipe server (spec/05 §8): `\\.\pipe\YourWallet.v3.<SID>`, user-only DACL, first
//! instance only, remote clients rejected, at most 4 instances (yw-win `pipe::Server`). Each
//! connection: the hello within 2 s (`hello-ack` / `hello-reject` then close), then a reader
//! thread feeding [`BrowserCore::handle_frame`] and a writer thread assigning the outbound
//! `sequence` (1, 2, … per connection, responses and events alike). A framing error or EOF closes
//! only that connection; its pending approvals are cancelled without a response.
//!
//! SDDL and flags were compared with `archive/spec-v2.4:crates/platform-windows/src/
//! broker_channel.rs:505-558,889-918` (its random pipe naming is not used).

use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

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
            loop {
                match server.accept() {
                    Ok(duplex) => connection(&core, duplex, &pinned_origin),
                    Err(ServerError::Stopped) => break,
                    Err(_) => {
                        logging::warn("pipe", "accept.failed", &[]);
                        std::thread::sleep(Duration::from_millis(100));
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
