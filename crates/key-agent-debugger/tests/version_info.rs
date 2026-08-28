//! Built-binary VERSIONINFO contract for the unsigned debugger candidate.

#[cfg(windows)]
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(windows)]
fn inspector_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/release/assert-key-agent-debugger-version.ps1")
}

#[cfg(windows)]
fn inspect(executable: &Path, quiet: bool) -> Result<ExitStatus, Box<dyn std::error::Error>> {
    let mut command = Command::new("powershell.exe");
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(inspector_path())
        .arg("-ExecutablePath")
        .arg(executable);
    if quiet {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }
    Ok(command.status()?)
}

#[cfg(windows)]
#[test]
fn built_executable_has_exact_release_candidate_version_info()
-> Result<(), Box<dyn std::error::Error>> {
    let status = inspect(Path::new(env!("CARGO_BIN_EXE_key-agent-debugger")), false)?;
    assert!(status.success());
    Ok(())
}

#[cfg(windows)]
#[test]
fn non_pe_candidate_with_exact_filename_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "your-wallet-key-agent-debugger-version-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&directory)?;
    let candidate = directory.join("key-agent-debugger.exe");
    fs::write(&candidate, b"not a portable executable")?;

    let inspection = inspect(&candidate, true);
    fs::remove_file(&candidate)?;
    fs::remove_dir(&directory)?;

    assert!(!inspection?.success());
    Ok(())
}
