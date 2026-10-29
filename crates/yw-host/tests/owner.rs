//! spec/05 §8.1: yw-host trusts the pipe server only when the pipe object is owned by the current
//! user. A real pipe created by this user passes; a foreign owner (simulated through the injected
//! SID) or an unreadable SID is refused before the hello is sent, so the request gets 4900. The
//! server process must also be the wallet: Medium integrity or higher and the expected image.
//! Pipe names are `\\.\pipe\YourWallet.test.host.<pid>.<n>`.

use std::io::Read;
use std::sync::atomic::{AtomicU32, Ordering};

use yw_host::{expected_app_image, handshake_with, server_owner_trusted, server_process_trusted};
use yw_win::WinError;
use yw_win::pipe::{Duplex, Server, connect_client, user_only_sddl};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static NEXT: AtomicU32 = AtomicU32::new(0);

const ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";
const OTHER_USER: &str = "S-1-5-21-1000000000-2000000000-3000000000-1001";

fn pipe() -> String {
    format!(
        r"\\.\pipe\YourWallet.test.host.{}.{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
}

fn user_server(name: &str) -> Result<Server, Box<dyn std::error::Error>> {
    let sid = yw_win::current_user_sid_string()?;
    Ok(Server::create(name, &user_only_sddl(&sid))?)
}

fn client(name: &str) -> Result<Duplex, Box<dyn std::error::Error>> {
    connect_client(name).map_err(|error| error.to_string().into())
}

#[test]
fn a_pipe_created_by_this_user_is_trusted() -> TestResult {
    let name = pipe();
    let mut server = user_server(&name)?;
    let client = client(&name)?;
    let _accepted = server.accept()?;
    assert_eq!(client.owner_sid()?, yw_win::current_user_sid_string()?);
    assert!(client.owned_by_current_user());
    assert!(server_owner_trusted(
        &client,
        yw_win::current_user_sid_string
    ));
    Ok(())
}

#[test]
fn a_foreign_or_unknown_owner_is_refused() -> TestResult {
    let name = pipe();
    let mut server = user_server(&name)?;
    let client = client(&name)?;
    let _accepted = server.accept()?;
    assert!(!server_owner_trusted(&client, || Ok(OTHER_USER.to_owned())));
    assert!(!server_owner_trusted(&client, || Err(WinError::new(
        "OpenProcessToken",
        5
    ))));
    Ok(())
}

#[test]
fn an_untrusted_server_never_receives_the_hello() -> TestResult {
    let name = pipe();
    let mut server = user_server(&name)?;
    let client = client(&name)?;
    let (mut server_reader, _server_writer) = server.accept()?.split();
    assert!(handshake_with(client, ORIGIN, || Ok(OTHER_USER.to_owned()), |_| true).is_none());
    // The client end was dropped without writing: the server reads EOF and no bytes.
    let mut received = Vec::new();
    server_reader.read_to_end(&mut received)?;
    assert!(received.is_empty());
    Ok(())
}

/// H1 (spec/05 §8.1): a pipe owned by this user but served by a process that is not the wallet
/// (a Low-integrity squatter of the same user passes the owner check) is refused before the
/// hello; the check sees the real server pid.
#[test]
fn an_impostor_server_process_never_receives_the_hello() -> TestResult {
    let name = pipe();
    let mut server = user_server(&name)?;
    let client = client(&name)?;
    let (mut server_reader, _server_writer) = server.accept()?.split();
    let mut seen = None;
    let result = handshake_with(client, ORIGIN, yw_win::current_user_sid_string, |pid| {
        seen = Some(pid);
        false
    });
    assert!(result.is_none());
    assert_eq!(seen, Some(std::process::id()));
    let mut received = Vec::new();
    server_reader.read_to_end(&mut received)?;
    assert!(received.is_empty());
    Ok(())
}

/// The real check: this test process (the server here) runs the test executable at Medium
/// integrity or higher, so it passes for its own image and fails for any other file or an
/// unknown image.
#[test]
fn the_server_process_must_run_the_expected_image() -> TestResult {
    let own = std::env::current_exe()?;
    let pid = std::process::id();
    assert!(server_process_trusted(pid, Some(&own)));
    let system = std::env::var_os("SystemRoot").ok_or("SystemRoot")?;
    let other = std::path::Path::new(&system)
        .join("System32")
        .join("cmd.exe");
    assert!(!server_process_trusted(pid, Some(&other)));
    assert!(!server_process_trusted(pid, None));
    assert!(!server_process_trusted(
        pid,
        Some(&own.with_file_name("yw-app.exe"))
    ));
    // A pid that is not a running process cannot be opened.
    assert!(!server_process_trusted(u32::MAX - 3, Some(&own)));
    Ok(())
}

#[test]
fn the_expected_image_is_yw_app_next_to_the_host_unless_a_debug_override() {
    let none = |_: &str| None;
    let image = expected_app_image(&none, true);
    let exe = std::env::current_exe().ok();
    assert_eq!(
        image,
        exe.as_deref()
            .and_then(std::path::Path::parent)
            .map(|dir| dir.join("yw-app.exe"))
    );
    let fake = |key: &str| {
        (key == "YW_TEST_APP_IMAGE").then(|| std::ffi::OsString::from(r"C:\fake\node.exe"))
    };
    assert_eq!(
        expected_app_image(&fake, true),
        Some(std::path::PathBuf::from(r"C:\fake\node.exe"))
    );
    // Release builds ignore YW_TEST_*.
    assert_eq!(expected_app_image(&fake, false), image);
}
