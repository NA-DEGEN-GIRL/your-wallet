//! The Android shell's process state (spec/15 §3, §5; 2026-11-25 A2-4b): the one platform I/O
//! broker that `next`/`ioComplete` serve, the data folder the start input names, the log file,
//! and the memory check with `M_PURGE` around every Argon2 run.
//!
//! - [`start`] (the start input, `crate::interim::start_dir`): the data folder is
//!   `<noBackupFilesDir>/v3` (spec/15 §5.1), made `0700`; the log file `v3/logs/yw.log` is
//!   installed as the process logger (spec/15 §3.3: nothing goes to logcat). The first start
//!   wins; a later one with another folder is refused.
//! - [`platform`] / [`app_store`]: the key worker's platform and the app store over the sealed
//!   files, with the device key served through [`BROKER`] (Rust never calls Java, §3.2).
//! - The Argon2 hooks [`argon2_gate`] and [`argon2_done`] (spec/15 §5.3, §18 45): the memory facts (an
//!   I/O request), `kdf_gate::gate`, and after the run `mallopt(M_PURGE)` whatever the result.
//!   (2026-11-25 A2-8: the key worker's every Argon2-bound vault call goes through them, through
//!   the platform's `KeyPlatform::kdf_begin`; before, the A2-4b wrapper `run_argon2` served only
//!   the device round trip of `devtest`, which is gone.)
//! - 2026-11-25 A2-6: the screen host ([`ui_input`]): a `crate::ui_host::UiHost` behind a lock,
//!   made by the start input, which `call` hands every screen input; its frames go to [`BROKER`]
//!   for `next`.
//! - 2026-11-25 A2-7: the secret windows' keys and fills ([`secret_key`], [`secret_fill`]), under
//!   the same lock (Java's main thread calls them, as it calls `call`).
//! - 2026-11-25 A2-8 (spec/15 §17 A2, §5.4): the start is Windows' `main.rs` steps 5, 7 and 8 —
//!   `settings.json` and `apikeys.ks` read (their findings to the wallet as `Cmd::Platform`), the
//!   key worker (`yw-key`, on [`platform`], the shared clock, no card readers) and the RPC worker
//!   (`yw-rpc`, with no transport: A2 has no network permission, so every read fails as on a
//!   Windows PC whose HTTPS client could not start), the event queue whose doorbell posts the
//!   frame `{"t":"events"}`, then the language and the vault's load (`KeyJob::SetLanguage`,
//!   `KeyJob::Load`); the screen is `Starting` until the key worker answers. There is no browser
//!   bridge (A4), no `WalletConnect` (A7) and no orderly shutdown: Android ends the process, which
//!   ends the DEK with it (spec/15 §5.4). The threads are not joined.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use yw_core::error::VaultError;
use yw_core::secret::Zeroizing;
use yw_core::vault::LockedSlot;
use yw_engine::cmd::PlatformNote;
use yw_engine::errors::ErrorCode;
use yw_engine::events::{EventQueue, UiEvent};
use yw_engine::flow::evm::Limits;
use yw_engine::logging::{self, Field, LogLevel};
use yw_engine::services::Services;
use yw_engine::settings::{self, Settings, SettingsLoad};
use yw_engine::wallet::Wallet;
use yw_engine::wire::WireError;
use yw_engine::workers::key::platform::{KdfRuns, KeyDeps};
use yw_engine::workers::key::{KeyWorker, run as run_key_worker};
use yw_engine::workers::rpc::{RpcWorker, run as run_rpc_worker};
use yw_engine::yubikey::NoReaders;
use yw_platform::clock::Clock;
use yw_platform::files::{Files, FsError};

use crate::android_files::AndroidFiles;
use crate::clock::{AndroidClock, SharedClock};
use crate::device_key::{BrokerKey, FACTS_TIMEOUT, memory_facts};
use crate::io_request::{IoBroker, UiKind};
use crate::kdf_gate::{self, Gate};
use crate::log_file::LogFile;
use crate::slot::AndroidSlot;
use crate::storage::{DATA_FOLDER, DataPlatform, DataStore, KdfHooks, SETTINGS_NAME};
use crate::ui_host::{self, EVENTS_FRAME, UiHost};

/// The process's platform I/O broker.
pub(crate) static BROKER: IoBroker = IoBroker::new();

/// The data folder, once started.
static DATA: OnceLock<PathBuf> = OnceLock::new();

/// The deadline of the app store's device-key requests (2026-11-25 A2-8, spec/15 §5.2): the store
/// runs on Java's main thread (the vault generation of the rollback check, `apikeys.ks`), so it
/// gives up well before Android's 5 s input deadline (`None`, a failed write).
pub(crate) const STORE_TIMEOUT: Duration = Duration::from_secs(3);

/// The key worker's platform on Android.
pub(crate) type AndroidPlatform = DataPlatform<AndroidFiles, BrokerKey<'static>>;

/// The app store on Android.
pub(crate) type AndroidStore = DataStore<AndroidFiles, BrokerKey<'static>>;

fn new_slot() -> Result<Box<dyn LockedSlot>, VaultError> {
    match AndroidSlot::new() {
        Ok(slot) => Ok(Box::new(slot)),
        Err(error) => {
            logging::warn(
                "vault",
                "slot.failed",
                &[("why", Field::Word(error.word()))],
            );
            Err(VaultError::OutOfMemory)
        }
    }
}

/// The key worker's platform: the sealed files, the locked slot and the Argon2 hooks.
pub(crate) const fn platform() -> AndroidPlatform {
    DataPlatform::new(
        AndroidFiles,
        BrokerKey::new(&BROKER),
        new_slot,
        KdfHooks {
            gate: argon2_gate,
            done: argon2_done,
        },
    )
}

/// The app store of the started data folder (2026-11-25 A2-6: the screen host's wallet holds it;
/// 2026-11-25 A2-8: its device key gives up after [`STORE_TIMEOUT`]).
pub(crate) fn app_store() -> Option<AndroidStore> {
    Some(DataStore::new(
        AndroidFiles,
        BrokerKey::with_timeout(&BROKER, STORE_TIMEOUT),
        data()?,
    ))
}

/// The wall clock in Unix milliseconds (0 when it reads before 1970), for the protection bands'
/// patch age (2026-11-25 A2-5, `crate::device`).
pub(crate) fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// The data folder, once [`start`] succeeded.
pub(crate) fn data() -> Option<&'static Path> {
    DATA.get().map(PathBuf::as_path)
}

/// The start input: the data folder under `no_backup` (module doc). `false` when the folder
/// cannot be made or another folder was started before.
pub(crate) fn start(no_backup: &Path) -> bool {
    let folder = no_backup.join(DATA_FOLDER);
    if let Some(started) = DATA.get() {
        return *started == folder;
    }
    if AndroidFiles.ensure_dir(&folder).is_err() {
        return false;
    }
    if DATA.set(folder.clone()).is_err() {
        return DATA.get() == Some(&folder);
    }
    logging::install(
        Box::new(LogFile::open(&folder.join("logs"))),
        LogLevel::Info,
    );
    logging::info("app", "app.start", &[]);
    start_screen(&folder);
    true
}

/// `settings.json` of the data folder (spec/04 §6.2), as Windows' `load_settings`: a missing file
/// is the defaults, an unreadable one the defaults with the whole-file banner.
fn load_settings(folder: &Path) -> SettingsLoad {
    let max = u64::try_from(settings::SETTINGS_MAX_BYTES).unwrap_or(65_536);
    match AndroidFiles.read_limited_no_follow(&folder.join(SETTINGS_NAME), max) {
        Ok(bytes) => settings::load(Some(&bytes)),
        Err(FsError::NotFound) => settings::load(None),
        Err(_) => SettingsLoad {
            settings: Settings::default(),
            banners: vec![SETTINGS_NAME.to_owned()],
        },
    }
}

/// The screen host (2026-11-25 A2-6, `crate::ui_host`): made by the start input. Java sends every
/// screen input on its main thread; the lock keeps one input (and the effects it queued) whole.
static HOST: Mutex<Option<UiHost>> = Mutex::new(None);

/// A frame was lost on a worker thread (the events doorbell met a full UI queue that could not make
/// room): the next input on the main thread sends the screen's state again first (2026-11-25 A2-8).
static RESYNC_DUE: AtomicBool = AtomicBool::new(false);

/// The events doorbell (2026-11-25 A2-8; any thread, never the host's lock): the frame Java answers
/// with the events input.
fn ring_events() {
    if !BROKER.post_ui(UiKind::Other, EVENTS_FRAME) {
        RESYNC_DUE.store(true, Ordering::Release);
    }
}

/// Makes the wallet, its workers and the screen host on the started data folder, and posts the
/// first frames (module doc; 2026-11-25 A2-6, A2-8).
fn start_screen(folder: &Path) {
    let Some(store) = app_store() else {
        return;
    };
    // Windows `main.rs` step 5: settings.json and the sealed API keys.
    let loaded = load_settings(folder);
    logging::set_level(loaded.settings.log_level);
    let (apikeys, apikeys_unreadable) =
        yw_engine::app_store::load_sealed_keys(&store, &loaded.settings);
    let lang = loaded.settings.language;
    let clock: Arc<dyn Clock> = Arc::new(AndroidClock::new());
    let now = clock.now_ms();
    let wallet = Wallet::new(
        Box::new(store),
        Services {
            llm: Arc::new(|_endpoint| None),
            walletconnect: None,
            ua_platform: "android",
        },
        false,
        loaded.settings,
        apikeys,
        Arc::clone(&clock),
        now,
    );
    // The host first: each finding is an entry with its drain (Windows `App::platform_note`).
    let mut host = UiHost::new(wallet);
    if !loaded.banners.is_empty() {
        logging::warn(
            "app",
            "settings.invalid",
            &[("code", Field::Code(ErrorCode::App001))],
        );
        host.start_finding(PlatformNote::SettingsRefused(loaded.banners));
    }
    if apikeys_unreadable {
        logging::warn(
            "app",
            "apikeys.unreadable",
            &[("code", Field::Code(ErrorCode::Key001))],
        );
    }
    host.start_finding(PlatformNote::ApiKeys {
        readable: !apikeys_unreadable,
    });
    // Step 7: the workers.
    let events = Arc::new(EventQueue::new(Box::new(ring_events)));
    let queue = Arc::clone(&host.wallet().key_queue);
    let signal = Arc::clone(&host.wallet().lock_signal);
    let key_events = Arc::clone(&events);
    let key_clock = Arc::clone(&clock);
    let dir = folder.to_path_buf();
    let key_thread = std::thread::Builder::new()
        .name("yw-key".to_owned())
        .spawn(move || {
            let deps = KeyDeps {
                platform: Box::new(platform()),
                clock: Box::new(SharedClock(key_clock)),
                cards: Box::new(NoReaders),
            };
            run_key_worker(
                KeyWorker::new(&dir, deps),
                &queue,
                &|result| {
                    if key_events.push(UiEvent::Key(Box::new(result))).is_err() {
                        logging::warn("key", "E-APP-005", &[]);
                    }
                },
                &signal,
            );
        });
    let (rpc_tx, rpc_rx) = std::sync::mpsc::channel();
    let rpc_events = Arc::clone(&events);
    let rpc_clock = Arc::clone(&clock);
    let rpc_thread = std::thread::Builder::new()
        .name("yw-rpc".to_owned())
        .spawn(move || {
            // No transport: A2 has no network permission (spec/15 §12, §18 42 N16).
            let worker = RpcWorker::new(None, Box::new(SharedClock(rpc_clock)), Limits::PRODUCTION);
            run_rpc_worker(worker, &rpc_rx, &rpc_events);
        });
    if key_thread.is_err() || rpc_thread.is_err() {
        // E-APP-005's sibling on Windows is the start failure `THREADS_FAILED`; here the screen
        // stays `Starting` (no key worker answers) and the line says why.
        logging::warn("app", "threads.failed", &[]);
        return;
    }
    host.wallet_mut().workers_attached(events, rpc_tx);
    // Step 8: the language, then the vault's load.
    host.wallet()
        .key(yw_engine::events::KeyJob::SetLanguage(lang));
    host.wallet().key(yw_engine::events::KeyJob::Load);
    let frames = host.start();
    post_frames(&mut host, frames);
    if let Ok(mut slot) = HOST.lock() {
        *slot = Some(host);
    }
}

/// One screen input from `call` (2026-11-25 A2-6): handed to the host, its frames
/// posted for `next`. An input that is no input is dropped with one `wire.refused` line (its kind
/// only, never its bytes).
pub(crate) fn ui_input(bytes: &[u8]) {
    let Ok(mut slot) = HOST.lock() else {
        return;
    };
    let Some(host) = slot.as_mut() else {
        return;
    };
    resync_if_due(host);
    match host.on_wire_input(bytes) {
        Ok((_outcome, frames)) => post_frames(host, frames),
        Err(error) => logging::warn(
            "ui",
            "wire.refused",
            &[("why", Field::Word(wire_word(error)))],
        ),
    }
}

/// One `secretKey(field, codeUnit)` (2026-11-25 A2-7): the host feeds the open secret window it
/// names (`crate::secret_keys`); its frames are posted for `next`.
pub(crate) fn secret_key(field: i32, code_unit: i32) {
    let Ok(mut slot) = HOST.lock() else {
        return;
    };
    let Some(host) = slot.as_mut() else {
        return;
    };
    resync_if_due(host);
    let frames = host.on_secret_key(field, code_unit);
    post_frames(host, frames);
}

/// The units a `secretFill(handle, …)` writes (2026-11-25 A2-7, `crate::secret_host`), a copy
/// wiped when dropped; `None` writes nothing.
pub(crate) fn secret_fill(handle: i64) -> Option<Zeroizing<Vec<u16>>> {
    let slot = HOST.lock().ok()?;
    slot.as_ref()?.secret_fill(handle)
}

/// The app language (`settings.language`; Korean before the start, spec/14 §1), for the main
/// screen's bands the facts input answers (2026-11-25 A2-8: before, always Korean).
pub(crate) fn language() -> yw_core::lang::Lang {
    HOST.lock()
        .ok()
        .and_then(|slot| slot.as_ref().map(|host| host.wallet().settings.language))
        .unwrap_or_default()
}

/// The screen's state again when the doorbell lost a frame (2026-11-25 A2-8, [`RESYNC_DUE`]).
fn resync_if_due(host: &mut UiHost) {
    if RESYNC_DUE.swap(false, Ordering::AcqRel) {
        logging::warn("ui", "ui.resync", &[]);
        for frame in host.resync() {
            let _ = BROKER.post_ui(ui_host::ui_kind(&frame), &frame);
        }
    }
}

/// Posts `frames` for `next`, in order. When the UI queue was full and could not make room it
/// dropped every waiting frame (`IoBroker::post_ui`, 2026-11-25 A2-6 review): the rest of the
/// batch is dropped too and the host's state is sent again (`UiHost::resync`), once.
fn post_frames(host: &mut UiHost, frames: Vec<Vec<u8>>) {
    for frame in frames {
        if !BROKER.post_ui(ui_host::ui_kind(&frame), &frame) {
            logging::warn("ui", "ui.resync", &[]);
            for frame in host.resync() {
                let _ = BROKER.post_ui(ui_host::ui_kind(&frame), &frame);
            }
            return;
        }
    }
}

const fn wire_word(error: WireError) -> &'static str {
    match error {
        WireError::TooLarge => "too_large",
        WireError::Json => "json",
        WireError::Shape => "shape",
    }
}

/// Before an Argon2-bound vault call (module doc; spec/15 §5.3): the memory facts and the gate. A
/// refusal is `VaultError::OutOfMemory` (spec/04 E-VLT-007) with one `kdf.refused` line. A call
/// that runs Argon2 twice (the password change) is refused in A2 (`why=two_runs`): the margin and
/// the purge were measured for one run only (spec/15 §5.3 "한 호출 안의 Argon2 둘").
fn argon2_gate(runs: KdfRuns) -> Result<(), VaultError> {
    if runs == KdfRuns::Two {
        logging::warn("kdf", "kdf.refused", &[("why", Field::Word("two_runs"))]);
        return Err(VaultError::OutOfMemory);
    }
    let Some(facts) = memory_facts(&BROKER, FACTS_TIMEOUT) else {
        logging::warn("kdf", "kdf.refused", &[("why", Field::Word("no_facts"))]);
        return Err(VaultError::OutOfMemory);
    };
    match kdf_gate::gate(facts) {
        Gate::Go => Ok(()),
        Gate::LowNow => {
            logging::warn("kdf", "kdf.refused", &[("why", Field::Word("low_now"))]);
            Err(VaultError::OutOfMemory)
        }
        Gate::Unsupported => {
            logging::warn("kdf", "kdf.refused", &[("why", Field::Word("unsupported"))]);
            Err(VaultError::OutOfMemory)
        }
    }
}

/// Right after an Argon2-bound vault call, whatever its result: `mallopt(M_PURGE)`, one
/// `purge.failed` line when it fails (spec/15 §5.3).
fn argon2_done() {
    if !crate::purge::purge() {
        logging::warn("kdf", "purge.failed", &[]);
    }
}
