//! yw-host library: the Chrome native messaging relay of spec/05 §7, tested through `tests/`.
//!
//! Every function returns an exit code (spec/05 §7.7) instead of exiting; `main.rs` owns the
//! threads and the single `terminate`. Environment, clock, connect and spawn are injected through
//! [`ConnectEnv`] and plain `Read`/`Write` streams so R-H1–R-H4 and R-P1 run in memory. Framing is
//! `yw_json::frame` (ported from `archive/spec-v2.4:crates/native-host/src/lib.rs:149-203`); the
//! `_setmode` stdio setup of that archive (46-79) is replaced by `yw_win::{StdIn, StdOut}`.
#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread;
use std::time::{Duration, Instant};

use yw_json::frame::{FrameError, MAX_FRAME_BYTES, read_frame, write_frame};
use yw_json::{Limits, Number, Object, Value, parse, to_vec};
use yw_win::WinError;
use yw_win::pipe::{ConnectError, Duplex, PipeReader, PipeWriter};

/// stdin EOF or pipe EOF.
pub const EXIT_EOF: u8 = 0;
/// Argument or pinned extension ID error.
pub const EXIT_ARGS: u8 = 2;
/// yw-app unreachable; 4900 responses sent until stdin went quiet.
pub const EXIT_UNAVAILABLE: u8 = 3;
/// Chrome-side framing error (oversize, truncation).
pub const EXIT_CHROME_FRAMING: u8 = 4;
/// yw-app-side framing error.
pub const EXIT_APP_FRAMING: u8 = 5;
/// Any other I/O error.
pub const EXIT_IO: u8 = 6;

/// Capacity of the Chrome → yw-app frame queue (a full queue is Chrome-side backpressure).
pub const QUEUED_FRAMES: usize = 64;
/// Connect loop deadline (spec/05 §7.4).
pub const CONNECT_DEADLINE_MS: u64 = 10_000;
/// Sleep after `NotFound`/`Other`.
pub const RETRY_SLEEP_MS: u64 = 100;
/// Longest `WaitNamedPipeW` after `Busy`.
pub const BUSY_WAIT_MS: u64 = 500;
/// Hello-ack deadline (spec/05 §8.2).
pub const HELLO_TIMEOUT_MS: u64 = 2_000;
/// UNAVAILABLE mode ends after this long without a frame (spec/05 §7.6).
pub const UNAVAILABLE_IDLE_MS: u64 = 1_000;
/// `settings.json` read limit (spec/05 §7.4).
pub const SETTINGS_MAX_BYTES: u64 = 65_536;
/// `hostVersion` of the hello.
pub const HOST_VERSION: &str = env!("CARGO_PKG_VERSION");

const EXTENSION_ID_FILE: &str = include_str!("../../../extension/extension-id.txt");
const MAX_EXTRA_ARGS: usize = 8;
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// The pinned extension ID (spec/05 §2.3): 32 letters `a`–`p`, or `None` if the file is malformed.
#[must_use]
pub fn pinned_extension_id() -> Option<&'static str> {
    let id = EXTENSION_ID_FILE.trim_end();
    (id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))).then_some(id)
}

/// The stderr word for a non-zero exit code (`yw-host: <word>`, spec/05 §7.2).
#[must_use]
pub const fn code_word(code: u8) -> Option<&'static str> {
    match code {
        EXIT_ARGS => Some("args"),
        EXIT_UNAVAILABLE => Some("unavailable"),
        EXIT_CHROME_FRAMING => Some("chrome-framing"),
        EXIT_APP_FRAMING => Some("app-framing"),
        EXIT_IO => Some("io"),
        _ => None,
    }
}

/// spec/05 §7.1: `args[1]` must equal `chrome-extension://<pinned id>/` byte for byte and at most
/// 8 further arguments may follow (they are ignored). Returns the origin.
///
/// # Errors
///
/// [`EXIT_ARGS`].
pub fn check_args(args: &[OsString]) -> Result<String, u8> {
    let origin = pinned_extension_id()
        .map(|id| format!("chrome-extension://{id}/"))
        .ok_or(EXIT_ARGS)?;
    let matches = args
        .get(1)
        .is_some_and(|arg| arg.as_encoded_bytes() == origin.as_bytes());
    if !matches || args.len().saturating_sub(2) > MAX_EXTRA_ARGS {
        return Err(EXIT_ARGS);
    }
    Ok(origin)
}

/// Thread R body: queues Chrome frames until EOF ([`EXIT_EOF`]), a framing error
/// ([`EXIT_CHROME_FRAMING`]) or an I/O error ([`EXIT_IO`]). Blocks while the queue is full.
pub fn pump_stdin(input: &mut impl Read, frames: &SyncSender<Vec<u8>>) -> u8 {
    loop {
        match read_frame(input, MAX_FRAME_BYTES) {
            Ok(Some(frame)) => {
                if frames.send(frame).is_err() {
                    return EXIT_EOF;
                }
            }
            Ok(None) => return EXIT_EOF,
            Err(FrameError::Truncated | FrameError::Oversized) => return EXIT_CHROME_FRAMING,
            Err(FrameError::Allocation | FrameError::Io) => return EXIT_IO,
        }
    }
}

/// Thread W body: copies yw-app frames to Chrome byte for byte. Pipe EOF → [`EXIT_EOF`], pipe
/// framing error → [`EXIT_APP_FRAMING`], any other failure → [`EXIT_IO`].
pub fn pump_app(pipe: &mut impl Read, output: &mut impl Write) -> u8 {
    loop {
        match read_frame(pipe, MAX_FRAME_BYTES) {
            Ok(Some(frame)) => {
                if write_frame(output, &frame, MAX_FRAME_BYTES).is_err() {
                    return EXIT_IO;
                }
            }
            Ok(None) => return EXIT_EOF,
            Err(FrameError::Truncated | FrameError::Oversized) => return EXIT_APP_FRAMING,
            Err(FrameError::Allocation | FrameError::Io) => return EXIT_IO,
        }
    }
}

/// Main-thread relay after the hello: each queued frame goes to yw-app byte for byte, after
/// `before_write` (which calls `AllowSetForegroundWindow(app_pid)`, spec/05 §7.5). Ends with
/// [`EXIT_EOF`] when the queue closes or [`EXIT_IO`] when the pipe write fails.
pub fn relay_to_app(
    frames: &Receiver<Vec<u8>>,
    pipe: &mut impl Write,
    mut before_write: impl FnMut(),
) -> u8 {
    for frame in frames {
        before_write();
        if write_frame(pipe, &frame, MAX_FRAME_BYTES).is_err() {
            return EXIT_IO;
        }
    }
    EXIT_EOF
}

/// The correlation fields of a request answered in UNAVAILABLE mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Correlation {
    /// `sessionId` (id64).
    pub session_id: String,
    /// `sequence` (1..=2^53−1).
    pub sequence: u64,
    /// `activationNonce` (id64).
    pub activation_nonce: String,
    /// `requestId` (id32).
    pub request_id: String,
}

fn lower_hex_id(value: Option<&Value>, len: usize) -> Option<String> {
    let text = value?.as_str()?;
    let valid = text.len() == len
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && text.bytes().any(|b| b != b'0');
    valid.then(|| text.to_owned())
}

/// spec/05 §7.6: reads only `version`, `kind` and the four correlation fields of a request
/// (integers per spec/05 §6.1 `as_u64_allow_dot_zero`). `None` for a cancel, another version or
/// any malformed frame.
#[must_use]
pub fn unavailable_correlation(frame: &[u8]) -> Option<Correlation> {
    let Ok(Value::Object(root)) = parse(frame, &Limits::REQUEST) else {
        return None;
    };
    let integer = |key: &str| root.get(key)?.as_number()?.as_u64_allow_dot_zero();
    if integer("version") != Some(1) || root.get("kind")?.as_str() != Some("request") {
        return None;
    }
    let sequence = integer("sequence").filter(|n| (1..=MAX_SAFE_INTEGER).contains(n))?;
    Some(Correlation {
        session_id: lower_hex_id(root.get("sessionId"), 64)?,
        sequence,
        activation_nonce: lower_hex_id(root.get("activationNonce"), 64)?,
        request_id: lower_hex_id(root.get("requestId"), 32)?,
    })
}

fn object(pairs: Vec<(&str, Value)>) -> Value {
    let pairs = pairs
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
    Object::from_pairs(pairs).map_or(Value::Null, Value::Object)
}

fn text(value: &str) -> Value {
    Value::String(value.to_owned())
}

fn integer(value: u64) -> Value {
    Value::Number(Number::from_u64(value))
}

/// The 4900 response of spec/05 §7.6 (key order of `v1-unavailable-response.golden.json`);
/// `sequence` is this process's send counter.
#[must_use]
pub fn encode_unavailable(request: &Correlation, sequence: u64) -> Vec<u8> {
    to_vec(&object(vec![
        ("namespace", text("your-wallet")),
        ("version", integer(1)),
        ("role", text("native-host")),
        ("kind", text("response")),
        ("sessionId", text(&request.session_id)),
        ("sequence", integer(sequence)),
        ("requestSequence", integer(request.sequence)),
        ("activationNonce", text(&request.activation_nonce)),
        ("requestId", text(&request.request_id)),
        (
            "error",
            object(vec![
                ("code", integer(4900)),
                ("message", text("Wallet is unavailable.")),
            ]),
        ),
    ]))
}

/// UNAVAILABLE mode (spec/05 §7.6): answers each well-formed v1 request with 4900 and drops
/// everything else. Returns [`EXIT_UNAVAILABLE`] after `idle` without a frame, [`EXIT_EOF`] if
/// the queue closes, [`EXIT_IO`] if stdout fails.
pub fn run_unavailable(frames: &Receiver<Vec<u8>>, output: &mut impl Write, idle: Duration) -> u8 {
    let mut sequence = 0_u64;
    loop {
        match frames.recv_timeout(idle) {
            Ok(frame) => {
                let Some(request) = unavailable_correlation(&frame) else {
                    continue;
                };
                sequence = sequence.saturating_add(1);
                let response = encode_unavailable(&request, sequence);
                if write_frame(output, &response, MAX_FRAME_BYTES).is_err() {
                    return EXIT_IO;
                }
            }
            Err(RecvTimeoutError::Timeout) => return EXIT_UNAVAILABLE,
            Err(RecvTimeoutError::Disconnected) => return EXIT_EOF,
        }
    }
}

/// The hello frame of spec/05 §8.2 (key order of `pipe-hello.golden.json`).
#[must_use]
pub fn encode_hello(host_version: &str, origin: &str, pid: u32) -> Vec<u8> {
    to_vec(&object(vec![
        ("kind", text("hello")),
        ("protocol", integer(1)),
        ("hostVersion", text(host_version)),
        ("extensionOrigin", text(origin)),
        ("pid", integer(u64::from(pid))),
    ]))
}

/// Whether `frame` is exactly `{"kind":"hello-ack","protocol":1,"appVersion":<1–32 chars>}`
/// (any order, no other key). A `hello-reject` or anything else is `false`.
#[must_use]
pub fn parse_hello_ack(frame: &[u8]) -> bool {
    let Ok(Value::Object(root)) = parse(frame, &Limits::REQUEST) else {
        return false;
    };
    let app_version = root
        .get("appVersion")
        .and_then(Value::as_str)
        .map_or(0, |version| version.chars().count());
    root.len() == 3
        && root.get("kind").and_then(Value::as_str) == Some("hello-ack")
        && root
            .get("protocol")
            .and_then(Value::as_number)
            .and_then(Number::as_u64)
            == Some(1)
        && (1..=32).contains(&app_version)
}

/// Sends the hello and reads one reply; `true` only for a valid hello-ack.
pub fn hello_exchange(
    pipe_reader: &mut impl Read,
    pipe_writer: &mut impl Write,
    origin: &str,
    pid: u32,
) -> bool {
    let hello = encode_hello(HOST_VERSION, origin, pid);
    write_frame(pipe_writer, &hello, MAX_FRAME_BYTES).is_ok()
        && matches!(read_frame(pipe_reader, MAX_FRAME_BYTES), Ok(Some(reply)) if parse_hello_ack(&reply))
}

/// Runs `work`; if it has not finished after `timeout`, a watchdog thread calls `cancel` (which
/// must unblock `work`). Returns `None` when the watchdog fired or could not start.
pub fn run_with_deadline<T>(
    timeout: Duration,
    cancel: impl FnOnce() + Send + 'static,
    work: impl FnOnce() -> T,
) -> Option<T> {
    let (done, finished) = mpsc::channel::<()>();
    let watchdog = thread::Builder::new()
        .spawn(move || {
            let fired = matches!(
                finished.recv_timeout(timeout),
                Err(RecvTimeoutError::Timeout)
            );
            if fired {
                cancel();
            }
            fired
        })
        .ok()?;
    let result = work();
    drop(done);
    let fired = watchdog.join().unwrap_or(true);
    (!fired).then_some(result)
}

/// Whether the pipe server is trusted: the pipe object's owner ([`Duplex::owner_sid`]) equals
/// `user_sid()` (the current user's SID in production, [`yw_win::current_user_sid_string`]).
/// A pipe another user created under the predictable per-user name, or any failure to read
/// either SID, is not trusted (spec/05 §8.1).
pub fn server_owner_trusted(
    duplex: &Duplex,
    user_sid: impl FnOnce() -> Result<String, WinError>,
) -> bool {
    yw_win::pipe::owner_is(duplex.owner_sid(), user_sid())
}

/// The executable the pipe server must run (spec/05 §8.1): debug `YW_TEST_APP_IMAGE` (headless
/// tests run a fake server), else `yw-app.exe` next to this yw-host. `None` when the folder of
/// this executable is unknown.
#[must_use]
pub fn expected_app_image(lookup: Lookup<'_>, debug: bool) -> Option<PathBuf> {
    if debug && let Some(image) = lookup("YW_TEST_APP_IMAGE") {
        return Some(PathBuf::from(image));
    }
    let exe = std::env::current_exe().ok()?;
    Some(exe.parent()?.join("yw-app.exe"))
}

/// Whether the server process `pid` is the wallet (spec/05 §8.1 H1): token integrity Medium or
/// higher and an image that is the same file as `expected` ([`yw_win::security::verify_process`]).
/// A Low-integrity process of the same user can create the predictable pipe name (the owner
/// check passes for it), so this is what tells it apart.
#[must_use]
pub fn server_process_trusted(pid: u32, expected: Option<&Path>) -> bool {
    expected.is_some_and(|image| yw_win::security::verify_process(pid, image).is_ok())
}

/// Splits a fresh connection, sends the hello and waits up to 2 s for the ack (spec/05 §8.2).
/// Returns the halves and the verified server pid (`GetNamedPipeServerProcessId`), or `None`
/// (→ UNAVAILABLE). A server whose pipe is not owned by the current user, or whose process is
/// not `yw-app.exe` next to this yw-host at Medium integrity or higher, gets nothing, not even
/// the hello; only a verified pid is ever passed to `AllowSetForegroundWindow`.
#[must_use]
pub fn handshake(duplex: Duplex, origin: &str) -> Option<(PipeReader, PipeWriter, u32)> {
    let image = expected_app_image(&|key| std::env::var_os(key), cfg!(debug_assertions));
    handshake_with(duplex, origin, yw_win::current_user_sid_string, |pid| {
        server_process_trusted(pid, image.as_deref())
    })
}

/// [`handshake`] with the expected owner SID and the server-process check injected (tests
/// simulate a foreign owner or an impostor process).
#[must_use]
pub fn handshake_with(
    duplex: Duplex,
    origin: &str,
    user_sid: impl FnOnce() -> Result<String, WinError>,
    server_trusted: impl FnOnce(u32) -> bool,
) -> Option<(PipeReader, PipeWriter, u32)> {
    if !server_owner_trusted(&duplex, user_sid) {
        return None;
    }
    let app_pid = duplex.server_pid()?;
    if !server_trusted(app_pid) {
        return None;
    }
    let (mut reader, mut writer) = duplex.split();
    let canceller = reader.cancel_handle();
    let accepted = run_with_deadline(
        Duration::from_millis(HELLO_TIMEOUT_MS),
        move || canceller.cancel(),
        || hello_exchange(&mut reader, &mut writer, origin, std::process::id()),
    )?;
    accepted.then_some((reader, writer, app_pid))
}

/// Environment-variable lookup (`std::env::var_os` in production).
pub type Lookup<'a> = &'a dyn Fn(&str) -> Option<OsString>;

/// `browserAutoLaunch` from settings bytes: the value if the root is an object with
/// `version == 1` and a boolean `browserAutoLaunch`, otherwise `true`. No other key is read.
#[must_use]
pub fn auto_launch_from_bytes(bytes: &[u8]) -> bool {
    let Ok(Value::Object(root)) = parse(bytes, &Limits::REQUEST) else {
        return true;
    };
    let version = root
        .get("version")
        .and_then(Value::as_number)
        .and_then(Number::as_u64);
    if version != Some(1) {
        return true;
    }
    root.get("browserAutoLaunch")
        .and_then(Value::as_bool)
        .unwrap_or(true)
}

/// `browserAutoLaunch` from a settings file (≤ 65,536 bytes); any read error is `true`.
#[must_use]
pub fn auto_launch_from_file(path: &Path) -> bool {
    match yw_win::file::read_limited(path, SETTINGS_MAX_BYTES) {
        Ok(bytes) => auto_launch_from_bytes(&bytes),
        Err(_) => true,
    }
}

/// `settings.json`: debug `YW_TEST_DATA_DIR`, else `%LOCALAPPDATA%\YourWallet\v3` (`None` when
/// `LOCALAPPDATA` is missing or not absolute).
#[must_use]
pub fn settings_path(lookup: Lookup<'_>, debug: bool) -> Option<PathBuf> {
    if debug && let Some(dir) = lookup("YW_TEST_DATA_DIR") {
        return Some(PathBuf::from(dir).join("settings.json"));
    }
    let base = PathBuf::from(lookup("LOCALAPPDATA")?);
    base.is_absolute()
        .then(|| base.join("YourWallet").join("v3").join("settings.json"))
}

/// spec/05 §7.4 `auto_launch_enabled` with injected environment (`debug` = debug build).
#[must_use]
pub fn auto_launch_enabled_with(lookup: Lookup<'_>, debug: bool) -> bool {
    if debug && lookup("YW_TEST_NO_SPAWN").is_some_and(|value| value == "1") {
        return false;
    }
    settings_path(lookup, debug).is_none_or(|path| auto_launch_from_file(&path))
}

/// The pipe name: debug `YW_TEST_PIPE_NAME`, else `\\.\pipe\YourWallet.v3.<SID>`.
#[must_use]
pub fn pipe_name(lookup: Lookup<'_>, debug: bool) -> Option<String> {
    if debug && let Some(name) = lookup("YW_TEST_PIPE_NAME") {
        return name.into_string().ok();
    }
    let sid = yw_win::current_user_sid_string().ok()?;
    Some(yw_win::pipe::wallet_pipe_name(&sid))
}

/// The seams of the connect loop.
pub trait ConnectEnv {
    /// The connection type.
    type Conn;
    /// `yw_win::pipe::connect_client`.
    ///
    /// # Errors
    ///
    /// [`ConnectError`].
    fn connect(&mut self, name: &str) -> Result<Self::Conn, ConnectError>;
    /// `yw_win::pipe::wait`.
    fn wait_pipe(&mut self, name: &str, timeout_ms: u32);
    /// spec/05 §7.4 `auto_launch_enabled`.
    fn auto_launch_enabled(&mut self) -> bool;
    /// Starts yw-app (failures are ignored).
    fn spawn_app(&mut self);
    /// Monotonic milliseconds.
    fn now_ms(&mut self) -> u64;
    /// Sleeps.
    fn sleep_ms(&mut self, ms: u64);
}

/// The connect loop of spec/05 §7.4. `None` → UNAVAILABLE: immediately when the first
/// `NotFound` finds auto-launch disabled, otherwise at the 10 s deadline.
pub fn connect_app<E: ConnectEnv>(env: &mut E, name: &str) -> Option<E::Conn> {
    let deadline = env.now_ms().saturating_add(CONNECT_DEADLINE_MS);
    let mut spawned = false;
    loop {
        match env.connect(name) {
            Ok(conn) => return Some(conn),
            Err(ConnectError::NotFound) => {
                if !spawned {
                    if !env.auto_launch_enabled() {
                        return None;
                    }
                    env.spawn_app();
                    spawned = true;
                }
                env.sleep_ms(RETRY_SLEEP_MS);
            }
            Err(ConnectError::Busy) => {
                let remaining = deadline.saturating_sub(env.now_ms()).min(BUSY_WAIT_MS);
                if let Ok(timeout) = u32::try_from(remaining)
                    && timeout > 0
                {
                    env.wait_pipe(name, timeout);
                }
            }
            Err(ConnectError::Other(_)) => env.sleep_ms(RETRY_SLEEP_MS),
        }
        if env.now_ms() >= deadline {
            return None;
        }
    }
}

/// The real environment: yw-win pipe calls, `spawn_detached`, the process environment.
#[derive(Debug)]
pub struct SystemEnv {
    start: Instant,
}

impl Default for SystemEnv {
    fn default() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl ConnectEnv for SystemEnv {
    type Conn = Duplex;

    fn connect(&mut self, name: &str) -> Result<Duplex, ConnectError> {
        yw_win::pipe::connect_client(name)
    }

    fn wait_pipe(&mut self, name: &str, timeout_ms: u32) {
        let _ = yw_win::pipe::wait(name, timeout_ms);
    }

    fn auto_launch_enabled(&mut self) -> bool {
        auto_launch_enabled_with(&|key| std::env::var_os(key), cfg!(debug_assertions))
    }

    fn spawn_app(&mut self) {
        let exe = std::env::current_exe().ok();
        if let Some(app) = exe.as_deref().and_then(Path::parent) {
            let _ = yw_win::spawn_detached(&app.join("yw-app.exe"), &["--background"]);
        }
    }

    fn now_ms(&mut self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn sleep_ms(&mut self, ms: u64) {
        thread::sleep(Duration::from_millis(ms));
    }
}
