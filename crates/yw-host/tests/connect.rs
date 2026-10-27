//! R-H4 (spec/05 §7.4, §10.2): `auto_launch_enabled` and the connect loop with a fake connect,
//! spawn and clock. `browserAutoLaunch: false` → no spawn and UNAVAILABLE at once; every other
//! settings file → one spawn, then UNAVAILABLE at the 10 s deadline. Settings files live in a
//! fresh folder under `std::env::temp_dir()`; the real `%LOCALAPPDATA%` is never read.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use yw_host::{
    CONNECT_DEADLINE_MS, ConnectEnv, EXIT_UNAVAILABLE, auto_launch_enabled_with,
    auto_launch_from_bytes, connect_app, run_unavailable, settings_path,
};
use yw_json::frame::{MAX_FRAME_BYTES, read_frame};
use yw_json::{Limits, parse};
use yw_win::pipe::ConnectError;

const REQUEST: &str = include_str!("../../../extension/native-host/v1-request.golden.json");
const RESPONSE: &str =
    include_str!("../../../extension/native-host/v1-unavailable-response.golden.json");
const DISABLED: &str = r#"{"version":1,"browserAutoLaunch":false}"#;

type TestResult = Result<(), Box<dyn std::error::Error>>;

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A fresh folder holding `settings.json` = `content` (absent when `None`).
struct DataDir(PathBuf);

impl DataDir {
    fn new(content: Option<&[u8]>) -> std::io::Result<Self> {
        let dir = std::env::temp_dir().join(format!(
            "yw-host-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir)?;
        if let Some(bytes) = content {
            fs::write(dir.join("settings.json"), bytes)?;
        }
        Ok(Self(dir))
    }

    fn lookup(&self) -> impl Fn(&str) -> Option<OsString> + '_ {
        |key| (key == "YW_TEST_DATA_DIR").then(|| self.0.clone().into_os_string())
    }
}

impl Drop for DataDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct FakeEnv<'a> {
    now: u64,
    script: VecDeque<Result<u32, ConnectError>>,
    fallback: ConnectError,
    spawns: u32,
    auto_checks: u32,
    waits: Vec<u32>,
    auto_launch: Box<dyn FnMut() -> bool + 'a>,
}

impl<'a> FakeEnv<'a> {
    fn new(auto_launch: impl FnMut() -> bool + 'a) -> Self {
        Self {
            now: 0,
            script: VecDeque::new(),
            fallback: ConnectError::NotFound,
            spawns: 0,
            auto_checks: 0,
            waits: Vec::new(),
            auto_launch: Box::new(auto_launch),
        }
    }
}

impl ConnectEnv for FakeEnv<'_> {
    type Conn = u32;

    fn connect(&mut self, _: &str) -> Result<u32, ConnectError> {
        self.script.pop_front().unwrap_or(Err(self.fallback))
    }

    fn wait_pipe(&mut self, _: &str, timeout_ms: u32) {
        self.waits.push(timeout_ms);
        self.now += u64::from(timeout_ms);
    }

    fn auto_launch_enabled(&mut self) -> bool {
        self.auto_checks += 1;
        (self.auto_launch)()
    }

    fn spawn_app(&mut self) {
        self.spawns += 1;
    }

    fn now_ms(&mut self) -> u64 {
        self.now
    }

    fn sleep_ms(&mut self, ms: u64) {
        self.now += ms;
    }
}

/// UNAVAILABLE mode for the golden request: must answer the golden 4900 and exit 3.
fn assert_unavailable_answers_golden() -> TestResult {
    let (queue, frames) = mpsc::sync_channel(64);
    queue.send(REQUEST.as_bytes().to_vec())?;
    let mut output = Vec::new();
    let code = run_unavailable(&frames, &mut output, Duration::from_millis(20));
    assert_eq!(code, EXIT_UNAVAILABLE);
    let frame = read_frame(&mut Cursor::new(output), MAX_FRAME_BYTES)?.ok_or("no response")?;
    assert_eq!(
        parse(&frame, &Limits::RESPONSE)?,
        parse(RESPONSE.as_bytes(), &Limits::RESPONSE)?
    );
    Ok(())
}

fn padded(json: &str, total: usize) -> Vec<u8> {
    let mut bytes = json.as_bytes().to_vec();
    bytes.resize(total, b' ');
    bytes
}

#[test]
fn r_h4_auto_launch_false_spawns_nothing_and_answers_4900_at_once() -> TestResult {
    let data = DataDir::new(Some(DISABLED.as_bytes()))?;
    let lookup = data.lookup();
    let mut env = FakeEnv::new(|| auto_launch_enabled_with(&lookup, true));
    assert_eq!(connect_app(&mut env, "pipe"), None);
    assert_eq!(env.spawns, 0);
    assert_eq!(env.auto_checks, 1);
    assert_eq!(env.now, 0, "no wait before UNAVAILABLE");
    assert_unavailable_answers_golden()
}

#[test]
fn r_h4_other_settings_spawn_once_then_unavailable_at_10_s() -> TestResult {
    let cases: Vec<(&str, Option<Vec<u8>>)> = vec![
        ("missing file", None),
        (
            "broken JSON",
            Some(br#"{"version":1,"browserAutoLaunch":false"#.to_vec()),
        ),
        (
            "version 2",
            Some(br#"{"version":2,"browserAutoLaunch":false}"#.to_vec()),
        ),
        ("key missing", Some(br#"{"version":1}"#.to_vec())),
        (
            "string false",
            Some(br#"{"version":1,"browserAutoLaunch":"false"}"#.to_vec()),
        ),
        ("65,537 bytes", Some(padded(DISABLED, 65_537))),
    ];
    for (label, content) in cases {
        let data = DataDir::new(content.as_deref())?;
        let lookup = data.lookup();
        let mut env = FakeEnv::new(|| auto_launch_enabled_with(&lookup, true));
        assert_eq!(connect_app(&mut env, "pipe"), None, "{label}");
        assert_eq!(env.spawns, 1, "{label}");
        assert_eq!(env.auto_checks, 1, "{label}");
        assert_eq!(env.now, CONNECT_DEADLINE_MS, "{label}");
    }
    assert_unavailable_answers_golden()
}

#[test]
fn r_h4_settings_rules() -> TestResult {
    assert!(!auto_launch_from_bytes(DISABLED.as_bytes()));
    assert!(auto_launch_from_bytes(
        br#"{"version":1,"browserAutoLaunch":true}"#
    ));
    assert!(auto_launch_from_bytes(br#"{"browserAutoLaunch":false}"#));
    assert!(auto_launch_from_bytes(
        br#"{"version":1.0,"browserAutoLaunch":false}"#
    ));
    assert!(auto_launch_from_bytes(
        br#"[{"version":1,"browserAutoLaunch":false}]"#
    ));
    assert!(auto_launch_from_bytes(
        br#"{"version":1,"browserAutoLaunch":false,"browserAutoLaunch":false}"#
    ));
    // Other keys are not read: an unrelated malformed value does not matter.
    assert!(!auto_launch_from_bytes(
        br#"{"version":1,"evmChainId":"x","browserAutoLaunch":false}"#
    ));

    // The read limit is exactly 65,536 bytes.
    let at_limit = DataDir::new(Some(&padded(DISABLED, 65_536)))?;
    assert!(!auto_launch_enabled_with(&at_limit.lookup(), true));

    // Debug-only YW_TEST_NO_SPAWN=1 → false without reading settings.
    let no_spawn = |key: &str| (key == "YW_TEST_NO_SPAWN").then(|| OsString::from("1"));
    assert!(!auto_launch_enabled_with(&no_spawn, true));
    assert!(auto_launch_enabled_with(&no_spawn, false));
    let other = |key: &str| (key == "YW_TEST_NO_SPAWN").then(|| OsString::from("0"));
    assert!(auto_launch_enabled_with(&other, true));

    // Release builds ignore YW_TEST_*: %LOCALAPPDATA%\YourWallet\v3\settings.json.
    let local = DataDir::new(None)?;
    let v3 = local.0.join("YourWallet").join("v3");
    fs::create_dir_all(&v3)?;
    fs::write(v3.join("settings.json"), DISABLED)?;
    let base = local.0.clone();
    let release = move |key: &str| match key {
        "LOCALAPPDATA" => Some(base.clone().into_os_string()),
        "YW_TEST_DATA_DIR" => Some(OsString::from(r"C:\nonexistent")),
        _ => None,
    };
    assert_eq!(
        settings_path(&release, false),
        Some(v3.join("settings.json"))
    );
    assert!(!auto_launch_enabled_with(&release, false));
    assert_eq!(
        settings_path(&release, true),
        Some(Path::new(r"C:\nonexistent").join("settings.json"))
    );
    let relative = |key: &str| (key == "LOCALAPPDATA").then(|| OsString::from(r"relative\dir"));
    assert_eq!(settings_path(&relative, false), None);
    assert!(auto_launch_enabled_with(&relative, false));
    assert!(auto_launch_enabled_with(&|_: &str| None, false));
    Ok(())
}

#[test]
fn r_h4_connect_loop_busy_other_and_late_success() {
    // Busy → WaitNamedPipe(min(500, remaining)); Other → 100 ms; no auto-launch check.
    let mut env = FakeEnv::new(|| true);
    env.script = VecDeque::from([
        Err(ConnectError::Busy),
        Err(ConnectError::Busy),
        Err(ConnectError::Other(5)),
        Ok(7),
    ]);
    assert_eq!(connect_app(&mut env, "pipe"), Some(7));
    assert_eq!(env.waits, vec![500, 500]);
    assert_eq!(env.now, 1_100);
    assert_eq!((env.spawns, env.auto_checks), (0, 0));

    // NotFound → spawn once, keep retrying every 100 ms until the server appears.
    let mut env = FakeEnv::new(|| true);
    env.script = VecDeque::from([
        Err(ConnectError::NotFound),
        Err(ConnectError::NotFound),
        Err(ConnectError::NotFound),
        Ok(9),
    ]);
    assert_eq!(connect_app(&mut env, "pipe"), Some(9));
    assert_eq!((env.spawns, env.auto_checks, env.now), (1, 1, 300));

    // Busy until the deadline: the last wait is cut to the remaining time.
    let mut env = FakeEnv::new(|| true);
    env.script = VecDeque::from([
        Err(ConnectError::Other(5)),
        Err(ConnectError::Other(5)),
        Err(ConnectError::Other(5)),
    ]);
    env.fallback = ConnectError::Busy;
    assert_eq!(connect_app(&mut env, "pipe"), None);
    assert_eq!(env.now, CONNECT_DEADLINE_MS);
    assert_eq!(env.waits.last(), Some(&200));
    assert_eq!(env.spawns, 0);
}
