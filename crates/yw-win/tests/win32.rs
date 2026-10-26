//! Windows integration tests on the development PC (spec/01 §7.8, spec/09 §2.1): DPAPI round trip
//! (V-DPAPI), atomic writes on a fresh temp folder, the locked page and the single-instance mutex.
//! Files live under `std::env::temp_dir()` in a new folder per test.

use std::fs;
use std::path::PathBuf;

use yw_win::dpapi::{protect, unprotect};
use yw_win::file::{
    FileError, atomic_write, ensure_dir, read_limited, rename_no_replace, tmp_path,
};
use yw_win::mem::LockedBox;
use yw_win::process::{InstanceError, SingleInstance};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn temp_folder(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "yw-win-test-{tag}-{}-{}",
        std::process::id(),
        yw_win::time::monotonic_ms()
    ));
    ensure_dir(&dir)?;
    Ok(dir)
}

const ENTROPY: &[u8] = b"your-wallet/v3/apikeys";

#[test]
fn dpapi_round_trip_wrong_entropy_and_tamper() -> TestResult {
    let plain = b"YWAPIK01\x00";
    let blob = protect(plain, ENTROPY)?;
    assert_ne!(blob.as_slice(), plain.as_slice());
    assert_eq!(unprotect(&blob, ENTROPY)?.as_slice(), plain.as_slice());
    assert!(unprotect(&blob, b"your-wallet/v3/other").is_err());
    let mut tampered = blob.clone();
    let middle = tampered.len() / 2;
    tampered[middle] ^= 0x01;
    assert!(unprotect(&tampered, ENTROPY).is_err());
    Ok(())
}

#[test]
fn atomic_write_overwrites_and_clears_leftover_tmp() -> TestResult {
    let dir = temp_folder("atomic")?;
    let target = dir.join("settings.json");
    atomic_write(&target, b"one")?;
    assert_eq!(read_limited(&target, 64)?, b"one");
    fs::write(tmp_path(&target), b"stale partial")?;
    atomic_write(&target, b"two")?;
    assert_eq!(read_limited(&target, 64)?, b"two");
    assert!(!tmp_path(&target).exists());
    assert_eq!(read_limited(&target, 2), Err(FileError::TooLarge));
    assert_eq!(
        read_limited(&dir.join("missing"), 64),
        Err(FileError::NotFound)
    );
    fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn rename_no_replace_never_overwrites() -> TestResult {
    let dir = temp_folder("rename")?;
    let a = dir.join("a");
    let b = dir.join("b");
    fs::write(&a, b"a")?;
    fs::write(&b, b"b")?;
    assert!(rename_no_replace(&a, &b).is_err());
    assert_eq!(fs::read(&b)?, b"b");
    let c = dir.join("c");
    rename_no_replace(&a, &c)?;
    assert_eq!(fs::read(&c)?, b"a");
    fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn locked_box_allocates_and_frees() -> TestResult {
    for _ in 0..4 {
        let mut slot = LockedBox::<320>::new_zeroed()?;
        slot.expose_mut()[319] = 1;
        assert_eq!(slot.expose()[319], 1);
    }
    Ok(())
}

#[test]
fn single_instance_second_acquire_fails() -> TestResult {
    let name = format!("Local\\YourWallet.test.{}", std::process::id());
    let first = SingleInstance::acquire(&name).map_err(|_| "first acquire")?;
    assert!(matches!(
        SingleInstance::acquire(&name),
        Err(InstanceError::AlreadyRunning)
    ));
    drop(first);
    let again = SingleInstance::acquire(&name).map_err(|_| "reacquire")?;
    drop(again);
    Ok(())
}
