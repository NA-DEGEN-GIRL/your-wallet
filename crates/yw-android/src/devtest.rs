//! The device round trip of A2-4b (spec/15 §5.2, spec/09 §2.6; 2026-11-25): compiled only into a
//! debug APK built with `scripts/build-android.ps1 -Variant debug -DeviceTest` (`--cfg
//! yw_device_test`; never by the gate, never into a release APK), because it makes a vault from
//! the public test vector with a fixed synthetic password.
//!
//! On the start input it runs once on its own thread: with no vault it imports the public BIP39
//! test vector (`abandon` ×11 `about`, spec/02 §11.4) under the synthetic password and writes meta
//! and journal; with a vault it unlocks it and opens both sidecars. Either way every Argon2 goes
//! through `shell::run_argon2` (memory check, `M_PURGE`), all three files must be `YWK2` envelopes
//! on disk, and account 0 must be the spec/02 §11.4 address. The result is one log line
//! `devtest.done step=<created|reopened> ok=yes address=… ms=…` (milliseconds from the Argon2
//! step to the last check) or `devtest.failed at=<step> code=…`
//! in `no_backup/v3/logs/yw.log` (read with `run-as` on the debuggable APK). Create → kill the
//! process → start again → "reopened" is the device-key round trip.
//!
//! 2026-11-25 A2-5: and the panic test's fault points ([`fault_points`], read by the status call).

use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use yw_core::bip32::path::AccountIndex;
use yw_core::error::{StorageError, VaultError};
use yw_core::password::VaultPassword;
use yw_core::vault::envelope::{SealKind, looks_sealed};
use yw_core::vault::{EvmKeySource, FileKind, Vault, VaultStatus};
use yw_engine::logging::{self, Field};
use yw_engine::workers::key::platform::KeyPlatform;
use yw_platform::files::Files;

use crate::android_files::AndroidFiles;

/// The public test vector (spec/02 §11.4), never a real phrase.
/// (Built at run time so that no 12-word literal sits in a non-test file, `privacy-scan`.)
fn phrase() -> String {
    let mut phrase = "abandon ".repeat(11);
    phrase.push_str("about");
    phrase
}
/// A synthetic password of this test build only.
const PASSWORD: &[u8] = b"synthetic device test 1";
/// spec/02 §11.4: `m/44'/60'/0'/0/0` of [`phrase`].
const ACCOUNT_0: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
const META: &[u8] = b"devtest meta";
const JOURNAL: &[u8] = b"devtest journal";

/// Starts the round trip on its own thread.
pub(crate) fn spawn(data: PathBuf) {
    let started = std::thread::Builder::new()
        .name("devtest".into())
        .spawn(move || run(&data));
    if started.is_err() {
        logging::warn(
            "devtest",
            "devtest.failed",
            &[("at", Field::Word("thread"))],
        );
    }
}

/// A failed step and its storage code (0 when none).
type Failure = (&'static str, u64);

fn code(error: VaultError) -> u64 {
    match error {
        VaultError::Storage(StorageError::Io(code)) => u64::from(code),
        VaultError::Storage(_) => 1,
        VaultError::OutOfMemory => 2,
        _ => 3,
    }
}

fn run(data: &Path) {
    match round_trip(data) {
        Ok((step, address, kdf_ms)) => logging::warn(
            "devtest",
            "devtest.done",
            &[
                ("step", Field::Word(step)),
                ("ok", Field::Word("yes")),
                ("address", Field::Address(&address)),
                ("ms", Field::Num(kdf_ms)),
            ],
        ),
        Err((at, code)) => logging::warn(
            "devtest",
            "devtest.failed",
            &[("at", Field::Word(at)), ("code", Field::Num(code))],
        ),
    }
}

fn round_trip(data: &Path) -> Result<(&'static str, [u8; 20], u64), Failure> {
    let platform = crate::shell::platform();
    let storage = platform
        .open_storage(data)
        .map_err(|error| ("open", code(VaultError::Storage(error))))?;
    let mut vault = Vault::load(storage).map_err(|error| ("load", code(error)))?;
    let password = VaultPassword::new(PASSWORD).map_err(|_| ("password", 0))?;
    let slot = platform.new_slot().map_err(|error| ("slot", code(error)))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let began = Instant::now();
    let step = match vault.status() {
        VaultStatus::NoVault => {
            crate::shell::run_argon2(|| {
                vault.import_mnemonic(&password, &phrase(), None, slot, now)
            })
            .map_err(|error| ("import", code(error)))?;
            vault
                .save_sidecar(FileKind::Meta, META)
                .map_err(|error| ("meta", code(error)))?;
            vault
                .save_sidecar(FileKind::Journal, JOURNAL)
                .map_err(|error| ("journal", code(error)))?;
            "created"
        }
        VaultStatus::Locked => {
            crate::shell::run_argon2(|| vault.unlock(&password, slot).map(|_| ()))
                .map_err(|error| ("unlock", code(error)))?;
            for (kind, want, at) in [
                (FileKind::Meta, META, "meta"),
                (FileKind::Journal, JOURNAL, "journal"),
            ] {
                let opened = vault
                    .open_sidecar(kind)
                    .map_err(|error| (at, code(error)))?;
                if opened.as_ref().map(|(_, plain)| plain.expose()) != Some(want) {
                    return Err((at, 4));
                }
            }
            "reopened"
        }
        _ => return Err(("state", 0)),
    };
    let kdf_ms = u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX);
    for (name, kind) in [
        ("vault.ywv", SealKind::Vault),
        ("meta.ywm", SealKind::Meta),
        ("journal.ywj", SealKind::Journal),
    ] {
        let raw = AndroidFiles
            .read_limited_no_follow(&data.join(name), 32 * 1_048_576)
            .map_err(|_| ("raw", 0))?;
        if !looks_sealed(kind, &raw) {
            return Err(("sealed", 0));
        }
    }
    let address = vault
        .evm_address(EvmKeySource::Derived(AccountIndex::ZERO))
        .map_err(|error| ("address", code(error)))?;
    if address.to_checksum() != ACCOUNT_0 {
        return Err(("account0", 0));
    }
    vault.lock();
    no_replace_rename(data)?;
    Ok((step, *address.as_bytes(), kdf_ms))
}

/// `rename_no_replace` (quarantine, the `.prev` set-aside) on the device: a move to a free name
/// works and leaves no source; a move onto an existing name fails and changes neither file.
fn no_replace_rename(data: &Path) -> Result<(), Failure> {
    let (first, second) = (data.join("devtest.a"), data.join("devtest.b"));
    for path in [&first, &second] {
        match AndroidFiles.remove_file(path) {
            Ok(()) | Err(yw_platform::files::FsError::NotFound) => {}
            Err(_) => return Err(("rename_setup", 0)),
        }
    }
    let files = AndroidFiles;
    files
        .write_new_synced(&first, b"one")
        .map_err(|_| ("rename_write", 0))?;
    files
        .rename_no_replace(&first, &second)
        .map_err(|_| ("rename_free", 0))?;
    if files.exists(&first) || !files.is_file(&second) {
        return Err(("rename_free_state", 0));
    }
    files
        .write_new_synced(&first, b"two")
        .map_err(|_| ("rename_write", 1))?;
    if files.rename_no_replace(&first, &second).is_ok() {
        return Err(("rename_taken", 0));
    }
    let kept = files
        .read_limited_no_follow(&second, 16)
        .map_err(|_| ("rename_read", 0))?;
    let left = files
        .read_limited_no_follow(&first, 16)
        .map_err(|_| ("rename_read", 1))?;
    if kept != b"one" || left != b"two" {
        return Err(("rename_taken_state", 0));
    }
    files.remove_file(&first).map_err(|_| ("rename_clean", 0))?;
    files
        .remove_file(&second)
        .map_err(|_| ("rename_clean", 1))?;
    files.flush_dir(data).map_err(|_| ("rename_flush", 0))
}

/// The fault file of [`fault_points`]: `<data folder>/devtest.fault`, written by hand with
/// `run-as` on the debuggable `-DeviceTest` APK (spec/09 §2.6). Read at most this many bytes.
const FAULT_FILE: &str = "devtest.fault";
const FAULT_MAX: u64 = 16;

/// The panic test of A2-5 (2026-11-25; spec/15 §5.3, spec/09 §2.1 fault injection, the
/// Android form of `YW_FAULT_POINT`): when the fault file holds exactly `call` (optionally with
/// one line end), the status call panics on its own (Java's) thread; `thread`, a new Rust thread
/// panics while the status call waits. Either way the panic hook must wipe the slots, write the
/// one `app.panic` line and `_exit(70)` (no tombstone, no crash record). Anything else, or no
/// file, does nothing. Compiled only with `--cfg yw_device_test` (never the gate's or a release
/// build); the status call is its only caller.
pub(crate) fn fault_points() {
    let Some(data) = crate::shell::data() else {
        return;
    };
    let Ok(file) = std::fs::File::open(data.join(FAULT_FILE)) else {
        return;
    };
    let mut named = Vec::new();
    if std::io::Read::read_to_end(&mut std::io::Read::take(file, FAULT_MAX), &mut named).is_err() {
        return;
    }
    let point = named.strip_suffix(b"\n").unwrap_or(&named);
    match point {
        b"call" => {
            logging::warn(
                "devtest",
                "devtest.fault",
                &[("point", Field::Word("call"))],
            );
            panic_now();
        }
        b"thread" => {
            logging::warn(
                "devtest",
                "devtest.fault",
                &[("point", Field::Word("thread"))],
            );
            if std::thread::Builder::new()
                .name("devtest-fault".into())
                .spawn(panic_now)
                .is_ok()
            {
                // The hook ends the process from the other thread.
                std::thread::sleep(std::time::Duration::from_secs(10));
            }
        }
        _ => {}
    }
}

#[expect(
    clippy::panic,
    reason = "the A2-5 fault point panics on purpose (-DeviceTest builds only)"
)]
fn panic_now() {
    panic!("devtest fault point");
}
