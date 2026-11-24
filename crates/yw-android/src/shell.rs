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

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use yw_core::error::VaultError;
use yw_core::vault::LockedSlot;
use yw_engine::logging::{self, Field, LogLevel};
use yw_platform::files::Files;

use crate::android_files::AndroidFiles;
use crate::device_key::{BrokerKey, FACTS_TIMEOUT, memory_facts};
use crate::io_request::IoBroker;
use crate::kdf_gate::{self, Gate};
use crate::log_file::LogFile;
use crate::slot::AndroidSlot;
use crate::storage::{DATA_FOLDER, DataPlatform, DataStore};

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

/// The app store of the started data folder.
#[expect(
    dead_code,
    reason = "the app store is used from A2-6/A2-8 on (spec/15 §17 A2)"
)]
pub(crate) fn app_store() -> Option<AndroidStore> {
    Some(DataStore::new(
        AndroidFiles,
        BrokerKey::new(&BROKER),
        data()?,
    ))
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
    true
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
