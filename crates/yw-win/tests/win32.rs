//! Windows integration tests on the development PC (spec/01 §7.8, spec/09 §2.1): DPAPI round trip
//! (V-DPAPI), atomic writes on a fresh temp folder, the directory flush refusing a junction, the
//! locked page, the single-instance mutex (private namespace) and the private data folder ACL.
//! Files live under `std::env::temp_dir()` in a new folder per test (pid + a counter, so
//! parallel tests never share one); ACL tests give their base folder an explicit protected ACL
//! first, so nothing depends on what the host's `%TEMP%` grants.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use yw_win::dpapi::{protect, unprotect};
use yw_win::file::{
    AtomicWrite, FileError, atomic_write, atomic_write_detailed, ensure_dir, flush_dir,
    read_limited, read_limited_no_reparse, rename_no_replace, tmp_path,
};
use yw_win::mem::LockedBox;
use yw_win::process::{InstanceError, SingleInstance};
use yw_win::security::{
    LABEL_NO_READ_UP, LABEL_NO_WRITE_UP, PathSecurity, PrivateDir, PrivateDirError,
    ensure_private_dir, grants_others, is_private_dir, path_security,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static NEXT: AtomicU32 = AtomicU32::new(0);

fn temp_folder(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "yw-win-test-{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    // A folder left by an earlier run whose pid was the same starts empty again.
    let _ = fs::remove_dir_all(&dir);
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
    assert_eq!(
        atomic_write_detailed(&target, b"333")?,
        AtomicWrite::Durable
    );
    assert_eq!(read_limited(&target, 64)?, b"333");
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
fn flush_dir_opens_a_junction_itself_and_rejects_it() -> TestResult {
    let dir = temp_folder("junction")?;
    let real = dir.join("real");
    ensure_dir(&real)?;
    flush_dir(&real)?;
    let link = dir.join("link");
    // A junction needs no privilege (a directory symlink would).
    let status = Command::new("cmd")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&link)
        .arg(&real)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    assert!(status.success(), "mklink /J failed");
    assert_eq!(flush_dir(&link), Err(FileError::ReparsePoint));
    fs::remove_dir(&link)?;
    assert!(real.exists());
    fs::remove_dir_all(&dir)?;
    Ok(())
}

/// Review L8: a vault file that is a link is refused on read, never followed out of the folder.
#[test]
fn read_limited_no_reparse_refuses_links() -> TestResult {
    let dir = temp_folder("noreparse")?;
    let real = dir.join("real.ywv");
    fs::write(&real, b"ciphertext")?;
    assert_eq!(read_limited_no_reparse(&real, 64)?, b"ciphertext");
    assert_eq!(read_limited_no_reparse(&real, 4), Err(FileError::TooLarge));
    assert_eq!(
        read_limited_no_reparse(&dir.join("missing"), 64),
        Err(FileError::NotFound)
    );
    // A junction (no privilege needed) standing where a vault file is expected.
    let target_dir = dir.join("elsewhere");
    ensure_dir(&target_dir)?;
    let junction = dir.join("vault.ywv");
    let status = Command::new("cmd")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&target_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    assert!(status.success(), "mklink /J failed");
    assert_eq!(
        read_limited_no_reparse(&junction, 64),
        Err(FileError::ReparsePoint)
    );
    fs::remove_dir(&junction)?;
    // A file symlink needs SeCreateSymbolicLinkPrivilege or Developer Mode; when it can be made,
    // the link is refused although its target is a readable ordinary file. Without that
    // privilege the junction case above already covered the refusal.
    let link = dir.join("meta.ywm");
    if std::os::windows::fs::symlink_file(&real, &link).is_ok() {
        // Where the host resolves the link, it reads its target. Some temp folders do not (a
        // filesystem filter that redirects the folder, 2026-11-10: following a link fails there
        // with NotFound); the refusal below holds either way, as it never follows the link.
        match read_limited(&link, 64) {
            Ok(bytes) => assert_eq!(bytes, b"ciphertext"),
            Err(error) => assert_eq!(error, FileError::NotFound, "{error:?}"),
        }
        assert_eq!(
            read_limited_no_reparse(&link, 64),
            Err(FileError::ReparsePoint)
        );
        fs::remove_file(&link)?;
    }
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
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let boundary = format!("YourWallet.test.{}.{n}", std::process::id());
    let alias = format!("YourWalletTest{}x{n}", std::process::id());
    let first =
        SingleInstance::acquire_private(&boundary, &alias, "app").map_err(|_| "first acquire")?;
    let second = SingleInstance::acquire_private(&boundary, &alias, "app");
    assert!(
        matches!(second, Err(InstanceError::AlreadyRunning)),
        "{second:?}"
    );
    drop(first);
    let again =
        SingleInstance::acquire_private(&boundary, &alias, "app").map_err(|_| "reacquire")?;
    drop(again);
    Ok(())
}

/// A plain `Local\` object squatting the alias does not block the private namespace: names in a
/// private namespace never collide with the session namespace.
#[test]
fn a_session_namespace_squatter_does_not_block_the_private_mutex() -> TestResult {
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let boundary = format!("YourWallet.test.{}.{n}", std::process::id());
    let alias = format!("YourWalletTest{}x{n}", std::process::id());
    // The squatter holds `Local\<alias>` until its stdin closes.
    let mut squat = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "$m = New-Object System.Threading.Mutex($false, 'Local\\{alias}'); [Console]::Out.WriteLine('ready'); [Console]::Out.Flush(); [void][Console]::In.ReadToEnd(); $m.Dispose()"
            ),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut line = String::new();
    if let Some(stdout) = squat.stdout.take() {
        std::io::BufRead::read_line(&mut std::io::BufReader::new(stdout), &mut line)?;
    }
    let held = SingleInstance::acquire_private(&boundary, &alias, "app");
    drop(squat.stdin.take());
    let _ = squat.wait();
    assert_eq!(line.trim(), "ready");
    assert!(held.is_ok(), "squatted by a Local\\ mutex");
    Ok(())
}

/// The protected DACL (user, SYSTEM, Administrators) and the Medium NR/NW label of a private data
/// folder, and nothing else.
fn assert_private(security: &PathSecurity, user: &str, what: &str) {
    assert!(
        !grants_others(security, user),
        "{what}: grants others: {security:?}"
    );
    let label = security.label.as_ref();
    assert!(
        label.is_some_and(|label| label.sid == "S-1-16-8192"
            && label.mask & (LABEL_NO_READ_UP | LABEL_NO_WRITE_UP)
                == (LABEL_NO_READ_UP | LABEL_NO_WRITE_UP)),
        "{what}: label {label:?}"
    );
}

/// A test base folder with an explicit protected ACL, so nothing is inherited from `%TEMP%` (a
/// host may grant extra groups there).
fn hermetic_base(
    tag: &str,
    user: &str,
    extra: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = temp_folder(tag)?;
    let mut args = vec![
        dir.as_os_str().to_owned(),
        "/inheritance:r".into(),
        "/grant:r".into(),
        format!("*{user}:(OI)(CI)F").into(),
        "/grant:r".into(),
        "*S-1-5-18:(OI)(CI)F".into(),
    ];
    if !extra.is_empty() {
        args.push("/grant:r".into());
        args.push(extra.into());
    }
    let status = Command::new("icacls")
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    assert!(status.success(), "icacls failed");
    Ok(dir)
}

#[test]
fn a_new_data_folder_is_private_and_everything_inside_inherits_it() -> TestResult {
    let user = yw_win::current_user_sid_string()?;
    // Everyone may read the base: the new folders must not inherit that.
    let base = hermetic_base("private-new", &user, "*S-1-1-0:(OI)(CI)RX")?;
    let root = base.join("YourWallet");
    let data = root.join("v3");
    let logs = data.join("logs");
    for dir in [&root, &data, &logs] {
        let outcome = ensure_private_dir(dir, &user)?;
        assert_eq!(
            outcome,
            PrivateDir {
                created: true,
                repaired: false,
                entries_repaired: 0
            }
        );
        let security = path_security(dir)?;
        assert!(is_private_dir(&security, &user), "{security:?}");
    }
    atomic_write(&data.join("vault.ywv"), b"vault")?;
    atomic_write(&data.join("apikeys.dpapi"), b"keys")?;
    fs::write(logs.join("yw-app.log"), b"log")?;
    for (file, what) in [
        (data.join("vault.ywv"), "vault"),
        (data.join("apikeys.dpapi"), "apikeys"),
        (logs.join("yw-app.log"), "log"),
    ] {
        let security = path_security(&file)?;
        assert_private(&security, &user, what);
        // Exactly the folder's three full-access entries (from its inheritable ACEs).
        let mut sids: Vec<&str> = security.aces.iter().map(|ace| ace.sid.as_str()).collect();
        sids.sort_unstable();
        let mut expected = vec![user.as_str(), "S-1-5-18", "S-1-5-32-544"];
        expected.sort_unstable();
        assert_eq!(sids, expected, "{what}: {security:?}");
        assert!(
            security
                .aces
                .iter()
                .all(|ace| ace.ace_type == 0 && ace.mask == 0x001F_01FF),
            "{what}: {security:?}"
        );
    }
    // A second start finds everything private: nothing to repair.
    for dir in [&root, &data, &logs] {
        assert_eq!(ensure_private_dir(dir, &user)?, PrivateDir::default());
    }
    fs::remove_dir_all(&base)?;
    Ok(())
}

#[test]
fn an_existing_folder_with_extra_grants_is_repaired_with_its_files() -> TestResult {
    let user = yw_win::current_user_sid_string()?;
    // The folder (created the old way) inherits a read grant for another group, like a host
    // that gives a sandbox group RX on the whole profile; a file inside got an explicit grant.
    let base = hermetic_base("private-repair", &user, "*S-1-5-32-545:(OI)(CI)RX")?;
    let root = base.join("YourWallet");
    let data = root.join("v3");
    ensure_dir(&data)?;
    fs::write(data.join("vault.ywv"), b"vault")?;
    let explicit = data.join("settings.json");
    fs::write(&explicit, b"{}")?;
    let status = Command::new("icacls")
        .arg(&explicit)
        .args(["/grant", "*S-1-1-0:(M)"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    assert!(status.success(), "icacls failed");
    assert!(grants_others(&path_security(&data)?, &user));

    let outcome = ensure_private_dir(&root, &user)?;
    assert!(outcome.repaired && !outcome.created);
    let outcome = ensure_private_dir(&data, &user)?;
    assert!(outcome.repaired);
    assert_eq!(
        outcome.entries_repaired, 1,
        "settings.json had an explicit grant"
    );
    for (path, what) in [
        (root.clone(), "root"),
        (data.clone(), "data"),
        (data.join("vault.ywv"), "vault"),
        (explicit.clone(), "settings"),
    ] {
        assert_private(&path_security(&path)?, &user, what);
    }
    assert!(is_private_dir(&path_security(&data)?, &user));
    fs::remove_dir_all(&base)?;
    Ok(())
}

#[test]
fn a_reparse_point_is_never_a_data_folder() -> TestResult {
    let user = yw_win::current_user_sid_string()?;
    let base = hermetic_base("private-junction", &user, "")?;
    let real = base.join("real");
    ensure_dir(&real)?;
    let link = base.join("YourWallet");
    let status = Command::new("cmd")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&link)
        .arg(&real)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    assert!(status.success(), "mklink /J failed");
    assert_eq!(
        ensure_private_dir(&link, &user),
        Err(PrivateDirError::NotPlainDir)
    );
    fs::remove_dir(&link)?;
    fs::remove_dir_all(&base)?;
    Ok(())
}
