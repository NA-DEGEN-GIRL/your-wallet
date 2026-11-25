//! The Android shell's process state (spec/15 §3, §5; 2026-11-25 A2-4b): the one platform I/O
//! broker that `next`/`ioComplete` serve, the data folder the start input names, the log file,
//! and the Argon2 wrapper with the memory check and `M_PURGE`.
//!
//! - [`start`] (the start input, `crate::interim::start_dir`): the data folder is
//!   `<noBackupFilesDir>/v3` (spec/15 §5.1), made `0700`; the log file `v3/logs/yw.log` is
//!   installed as the process logger (spec/15 §3.3: nothing goes to logcat). The first start
//!   wins; a later one with another folder is refused.
//! - [`platform`] / [`app_store`]: the key worker's platform and the app store over the sealed
//!   files, with the device key served through [`BROKER`] (Rust never calls Java, §3.2).
//! - [`run_argon2`]: every Argon2id run of the Android build goes through it (spec/15 §5.3, §18
//!   45): the memory facts (an I/O request), [`kdf_gate::gate`], the run, then `mallopt(M_PURGE)`
//!   whatever the result. In A2-4b the only runs are the device round trip's (`devtest`); A2-8
//!   wires the key worker's Argon2 jobs through it.
//! - 2026-11-25 A2-6: the screen host ([`start_screen`], [`ui_input`]): a `crate::ui_host::UiHost`
//!   behind a lock, made by the start input, which `call` hands every screen input; its frames go
//!   to [`BROKER`] for `next`.
//! - 2026-11-25 A2-7: the secret windows' keys and fills ([`secret_key`], [`secret_fill`]), under
//!   the same lock (Java's main thread calls them, as it calls `call`).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use yw_core::error::VaultError;
use yw_core::secret::Zeroizing;
use yw_core::vault::LockedSlot;
use yw_engine::apikeys::ApiKeys;
use yw_engine::logging::{self, Field, LogLevel};
use yw_engine::services::Services;
use yw_engine::settings::Settings;
use yw_engine::wallet::Wallet;
use yw_engine::wire::WireError;
use yw_platform::clock::Clock;
use yw_platform::files::Files;

use crate::android_files::AndroidFiles;
use crate::clock::AndroidClock;
use crate::device_key::{BrokerKey, FACTS_TIMEOUT, memory_facts};
use crate::io_request::IoBroker;
use crate::kdf_gate::{self, Gate};
use crate::log_file::LogFile;
use crate::slot::AndroidSlot;
use crate::storage::{DATA_FOLDER, DataPlatform, DataStore};
use crate::ui_host::{self, UiHost};

/// The process's platform I/O broker.
pub(crate) static BROKER: IoBroker = IoBroker::new();

/// The data folder, once started.
static DATA: OnceLock<PathBuf> = OnceLock::new();

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

/// The key worker's platform.
#[cfg_attr(
    not(yw_device_test),
    expect(
        dead_code,
        reason = "the key worker joins in A2-8; the device round trip uses it now"
    )
)]
pub(crate) const fn platform() -> AndroidPlatform {
    DataPlatform::new(AndroidFiles, BrokerKey::new(&BROKER), new_slot)
}

/// The app store of the started data folder (2026-11-25 A2-6: the screen host's wallet holds it).
pub(crate) fn app_store() -> Option<AndroidStore> {
    Some(DataStore::new(
        AndroidFiles,
        BrokerKey::new(&BROKER),
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
    #[cfg(yw_device_test)]
    crate::devtest::spawn(folder);
    start_screen();
    true
}

/// The screen host (2026-11-25 A2-6, `crate::ui_host`): made by the start input. Java sends every
/// screen input on its main thread; the lock keeps one input (and the effects it queued) whole.
static HOST: Mutex<Option<UiHost>> = Mutex::new(None);

/// Makes the screen host on the started data folder and posts its first frames (2026-11-25
/// A2-6). The wallet starts in `Starting` with the default settings and no workers: the key
/// worker that classifies the vault, the settings read and the locks come with A2-8. A
/// `-DeviceTest` build starts it on S01 instead, so the device run can press through the wire.
fn start_screen() {
    let Some(store) = app_store() else {
        return;
    };
    let clock = Arc::new(AndroidClock::new());
    let now = clock.now_ms();
    #[cfg_attr(
        not(yw_device_test),
        expect(unused_mut, reason = "set only in -DeviceTest")
    )]
    let mut wallet = Wallet::new(
        Box::new(store),
        Services {
            llm: Arc::new(|_endpoint| None),
            walletconnect: None,
            ua_platform: "android",
        },
        false,
        Settings::default(),
        ApiKeys::default(),
        clock,
        now,
    );
    #[cfg(yw_device_test)]
    {
        wallet.mode = yw_engine::wallet::AppMode::NoVault;
        wallet.screen = yw_engine::wallet::Screen::FirstRun;
    }
    let mut host = UiHost::new(wallet);
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
    let frames = host.on_secret_key(field, code_unit);
    post_frames(host, frames);
}

/// The units a `secretFill(handle, …)` writes (2026-11-25 A2-7, `crate::secret_host`), a copy
/// wiped when dropped; `None` writes nothing.
pub(crate) fn secret_fill(handle: i64) -> Option<Zeroizing<Vec<u16>>> {
    let slot = HOST.lock().ok()?;
    slot.as_ref()?.secret_fill(handle)
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

/// Runs one Argon2id `run` behind the memory check, then purges (module doc). A refusal is
/// `VaultError::OutOfMemory` (spec/04 E-VLT-007, "the Argon2 working memory could not be
/// reserved") with one `kdf.refused` line.
#[cfg_attr(
    not(yw_device_test),
    expect(
        dead_code,
        reason = "the key worker joins in A2-8; the device round trip uses it now"
    )
)]
pub(crate) fn run_argon2<T>(run: impl FnOnce() -> Result<T, VaultError>) -> Result<T, VaultError> {
    let Some(facts) = memory_facts(&BROKER, FACTS_TIMEOUT) else {
        logging::warn("kdf", "kdf.refused", &[("why", Field::Word("no_facts"))]);
        return Err(VaultError::OutOfMemory);
    };
    match kdf_gate::gate(facts) {
        Gate::Go => {}
        Gate::LowNow => {
            logging::warn("kdf", "kdf.refused", &[("why", Field::Word("low_now"))]);
            return Err(VaultError::OutOfMemory);
        }
        Gate::Unsupported => {
            logging::warn("kdf", "kdf.refused", &[("why", Field::Word("unsupported"))]);
            return Err(VaultError::OutOfMemory);
        }
    }
    let result = run();
    if !crate::purge::purge() {
        logging::warn("kdf", "purge.failed", &[]);
    }
    result
}
