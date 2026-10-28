//! spec/05 §8.1: yw-host trusts the pipe server only when the pipe object is owned by the current
//! user. A real pipe created by this user passes; a foreign owner (simulated through the injected
//! SID) or an unreadable SID is refused before the hello is sent, so the request gets 4900.
//! Pipe names are `\\.\pipe\YourWallet.test.host.<pid>.<n>`.

use std::io::Read;
use std::sync::atomic::{AtomicU32, Ordering};

use yw_host::{handshake_with, server_owner_trusted};
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
    assert!(handshake_with(client, ORIGIN, || Ok(OTHER_USER.to_owned())).is_none());
    // The client end was dropped without writing: the server reads EOF and no bytes.
    let mut received = Vec::new();
    server_reader.read_to_end(&mut received)?;
    assert!(received.is_empty());
    Ok(())
}
