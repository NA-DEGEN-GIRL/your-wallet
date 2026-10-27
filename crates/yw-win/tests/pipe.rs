//! Named pipe integration tests on the development PC (spec/01 §7.8, spec/05 §8.1, R-P2 pieces):
//! round trip and full duplex on one connection, `AlreadyExists`, the 4-instance limit and a
//! freed slot, `stop`, the DACL of a user-only server, EOF after the peer drops and cancellation.
//! Every test uses its own `\\.\pipe\YourWallet.test.<pid>.<n>` name.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use yw_win::current_user_sid_string;
use yw_win::pipe::{
    AceSummary, ConnectError, Duplex, PipeCanceller, PipeReader, PipeWriter, Server, ServerError,
    ServerStop, connect_client, user_only_sddl, wait,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static NEXT: AtomicU32 = AtomicU32::new(0);

/// `FILE_ALL_ACCESS`: what `GA` maps to on a pipe object.
const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
/// `ERROR_OPERATION_ABORTED`.
const ABORTED: i32 = 995;

fn test_name() -> String {
    format!(
        r"\\.\pipe\YourWallet.test.{}.{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
}

fn user_server(name: &str) -> Result<Server, Box<dyn std::error::Error>> {
    let sid = current_user_sid_string()?;
    Ok(Server::create(name, &user_only_sddl(&sid))?)
}

fn client(name: &str) -> Result<Duplex, Box<dyn std::error::Error>> {
    connect_client(name).map_err(|error| error.to_string().into())
}

/// Connects, waiting through `Busy`/`NotFound` for up to `limit`.
fn connect_within(name: &str, limit: Duration) -> Result<Duplex, ConnectError> {
    let start = Instant::now();
    loop {
        match connect_client(name) {
            Err(ConnectError::Busy | ConnectError::NotFound) if start.elapsed() < limit => {
                let _ = wait(name, 50);
                thread::sleep(Duration::from_millis(10));
            }
            other => return other,
        }
    }
}

fn join<T>(handle: thread::JoinHandle<T>) -> Result<T, Box<dyn std::error::Error>> {
    handle.join().map_err(|_| "thread panicked".into())
}

#[test]
fn halves_and_handles_are_thread_safe() {
    fn send<T: Send>() {}
    fn send_sync<T: Send + Sync>() {}
    send::<PipeReader>();
    send::<PipeWriter>();
    send::<Duplex>();
    send::<Server>();
    send_sync::<PipeCanceller>();
    send_sync::<ServerStop>();
}

#[test]
fn missing_pipe_is_not_found() {
    let name = test_name();
    assert!(matches!(connect_client(&name), Err(ConnectError::NotFound)));
    assert!(!wait(&name, 10));
}

#[test]
fn round_trip_with_readers_blocked_while_writing() -> TestResult {
    let name = test_name();
    let mut server = user_server(&name)?;
    let client = client(&name)?;
    let accepted = server.accept()?;
    assert_eq!(accepted.client_pid(), Some(std::process::id()));
    assert_eq!(client.server_pid(), Some(std::process::id()));
    let (mut server_reader, mut server_writer) = accepted.split();
    let (mut client_reader, mut client_writer) = client.split();

    // A read is pending on each side's handle while other threads write on the same handles.
    let blocked_server = thread::spawn(move || {
        let mut buffer = [0_u8; 5];
        server_reader.read_exact(&mut buffer).map(|()| buffer)
    });
    let blocked_client = thread::spawn(move || {
        let mut buffer = [0_u8; 5];
        client_reader.read_exact(&mut buffer).map(|()| buffer)
    });
    thread::sleep(Duration::from_millis(100));
    assert!(!blocked_server.is_finished() && !blocked_client.is_finished());
    let writer = thread::spawn(move || {
        client_writer
            .write_all(b"hello")
            .and_then(|()| client_writer.flush())
    });
    server_writer.write_all(b"world")?;
    server_writer.flush()?;
    join(writer)??;
    assert_eq!(&join(blocked_server)??, b"hello");
    assert_eq!(&join(blocked_client)??, b"world");
    Ok(())
}

#[test]
fn big_transfers_both_ways_concurrently() -> TestResult {
    let name = test_name();
    let mut server = user_server(&name)?;
    let client = client(&name)?;
    let (mut server_reader, mut server_writer) = server.accept()?.split();
    let (mut client_reader, mut client_writer) = client.split();
    // Several times the 64 KiB pipe buffer, so writers block until the peer reads.
    let payload: Vec<u8> = (0..400_000_u32)
        .map(|value| (value % 251).to_le_bytes()[0])
        .collect();
    let to_server = payload.clone();
    let to_client = payload.clone();
    let client_send = thread::spawn(move || client_writer.write_all(&to_server));
    let server_send = thread::spawn(move || server_writer.write_all(&to_client));
    let client_receive = thread::spawn(move || {
        let mut received = vec![0_u8; 400_000];
        client_reader.read_exact(&mut received).map(|()| received)
    });
    let mut received = vec![0_u8; 400_000];
    server_reader.read_exact(&mut received)?;
    assert!(received == payload);
    assert!(join(client_receive)?? == payload);
    join(client_send)??;
    join(server_send)??;
    Ok(())
}

#[test]
fn second_create_with_the_same_name_already_exists() -> TestResult {
    let name = test_name();
    let first = user_server(&name)?;
    let sid = current_user_sid_string()?;
    assert!(matches!(
        Server::create(&name, &user_only_sddl(&sid)),
        Err(ServerError::AlreadyExists)
    ));
    drop(first);
    drop(user_server(&name)?);
    Ok(())
}

#[test]
fn four_connections_then_busy_until_one_closes() -> TestResult {
    let name = test_name();
    let mut server = user_server(&name)?;
    let stop = server.stop_handle();
    let (accepted_tx, accepted_rx) = mpsc::channel::<()>();
    let acceptor = thread::spawn(move || {
        loop {
            match server.accept() {
                Ok(duplex) => {
                    // Like yw-app: the server side lives until its client goes away.
                    let (mut reader, writer) = duplex.split();
                    thread::spawn(move || {
                        let mut sink = [0_u8; 16];
                        while matches!(reader.read(&mut sink), Ok(count) if count > 0) {}
                        drop(writer);
                    });
                    let _ = accepted_tx.send(());
                }
                Err(error) => return error,
            }
        }
    });
    let wait_limit = Duration::from_secs(3);
    let mut clients = Vec::new();
    for _ in 0..4 {
        clients.push(connect_within(&name, wait_limit).map_err(|error| error.to_string())?);
        accepted_rx.recv_timeout(wait_limit)?;
    }
    assert!(matches!(connect_client(&name), Err(ConnectError::Busy)));
    assert!(
        accepted_rx
            .recv_timeout(Duration::from_millis(300))
            .is_err()
    );

    // A client disconnect lets the server side drop, which frees a slot.
    drop(clients.remove(0));
    let fifth = connect_within(&name, wait_limit).map_err(|error| error.to_string())?;
    accepted_rx.recv_timeout(wait_limit)?;
    assert!(matches!(connect_client(&name), Err(ConnectError::Busy)));

    stop.stop();
    assert_eq!(join(acceptor)?, ServerError::Stopped);
    drop(fifth);
    drop(clients);
    Ok(())
}

#[test]
fn stop_unblocks_a_waiting_accept() -> TestResult {
    let name = test_name();
    let mut server = user_server(&name)?;
    let stop = server.stop_handle();
    let acceptor = thread::spawn(move || {
        let result = server.accept().err();
        (result, server)
    });
    thread::sleep(Duration::from_millis(100));
    assert!(!acceptor.is_finished());
    stop.stop();
    let (error, mut server) = join(acceptor)?;
    assert_eq!(error, Some(ServerError::Stopped));
    assert!(matches!(server.accept(), Err(ServerError::Stopped)));
    // The waiting instance was closed with the stop.
    assert!(matches!(connect_client(&name), Err(ConnectError::NotFound)));
    Ok(())
}

#[test]
fn user_only_server_has_one_allow_ace_for_the_user() -> TestResult {
    let name = test_name();
    let sid = current_user_sid_string()?;
    assert!(sid.starts_with("S-1-5-"), "{sid}");
    let server = Server::create(&name, &user_only_sddl(&sid))?;
    let summary = server.security_summary()?;
    assert_eq!(summary.owner, sid);
    assert!(summary.dacl_protected);
    assert_eq!(
        summary.aces,
        vec![AceSummary {
            ace_type: 0,
            mask: FILE_ALL_ACCESS,
            sid,
        }]
    );
    Ok(())
}

#[test]
fn eof_after_the_peer_drops() -> TestResult {
    let name = test_name();
    let mut server = user_server(&name)?;

    // Client writes and leaves: the server reads the data, then EOF (repeatedly).
    let first = client(&name)?;
    let (mut server_reader, _server_writer) = server.accept()?.split();
    let (client_reader, mut client_writer) = first.split();
    client_writer.write_all(b"bye")?;
    drop(client_writer);
    drop(client_reader);
    let mut received = Vec::new();
    server_reader.read_to_end(&mut received)?;
    assert_eq!(received, b"bye");
    assert_eq!(server_reader.read(&mut [0_u8; 4])?, 0);

    // Server side leaves: the client reads EOF and its writes fail.
    let second =
        connect_within(&name, Duration::from_secs(2)).map_err(|error| error.to_string())?;
    drop(server.accept()?);
    let (mut client_reader, mut client_writer) = second.split();
    assert_eq!(client_reader.read(&mut [0_u8; 4])?, 0);
    assert!(client_writer.write_all(b"x").is_err());
    Ok(())
}

#[test]
fn cancel_aborts_a_pending_read_and_later_reads() -> TestResult {
    let name = test_name();
    let mut server = user_server(&name)?;
    let _client = client(&name)?;
    let (mut reader, _writer) = server.accept()?.split();
    let canceller = reader.cancel_handle();
    let pending = thread::spawn(move || {
        let result = reader
            .read(&mut [0_u8; 4])
            .map_err(|error| error.raw_os_error());
        (result, reader)
    });
    thread::sleep(Duration::from_millis(100));
    assert!(!pending.is_finished());
    canceller.cancel();
    let (result, mut reader) = join(pending)?;
    assert_eq!(result, Err(Some(ABORTED)));
    assert_eq!(
        reader
            .read(&mut [0_u8; 4])
            .map_err(|error| error.raw_os_error()),
        Err(Some(ABORTED))
    );
    Ok(())
}
