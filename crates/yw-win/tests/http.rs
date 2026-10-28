//! `WinHTTP` against a loopback server on the development PC (spec/01 §7.4): a normal response,
//! and a server that trickles its body forever, which must end with `Timeout` at the request's
//! total deadline (the sum of the phase timeouts) instead of running for as long as bytes arrive.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use yw_win::http::{Client, EndpointUrl, HttpError, Timeouts};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Reads the request head and the `{}` body the tests send.
fn read_request(stream: &mut TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut seen = Vec::new();
    let mut byte = [0_u8; 1];
    while !seen.ends_with(b"\r\n\r\n{}") {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        seen.push(byte[0]);
    }
    Ok(())
}

/// Serves one connection with `respond`; returns the URL.
fn serve_once(
    respond: impl FnOnce(TcpStream) + Send + 'static,
) -> Result<(EndpointUrl, thread::JoinHandle<()>), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept()
            && read_request(&mut stream).is_ok()
        {
            respond(stream);
        }
    });
    let url = EndpointUrl::parse(&format!("http://127.0.0.1:{port}/v1/chat/completions"))?;
    Ok((url, handle))
}

#[test]
fn a_complete_response_is_read() -> TestResult {
    let (url, server) = serve_once(|mut stream| {
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
        );
    })?;
    let client = Client::new_loopback(Timeouts {
        resolve_ms: 2_000,
        connect_ms: 2_000,
        send_ms: 2_000,
        receive_ms: 2_000,
    })?;
    let response = client.post(&url, &[("Content-Type", "application/json")], b"{}", 1_024)?;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"{\"ok\":true}");
    assert_eq!(response.content_type.as_deref(), Some("application/json"));
    server.join().map_err(|_| "server thread panicked")?;
    Ok(())
}

#[test]
fn a_trickling_body_times_out_at_the_total_deadline() -> TestResult {
    let (url, server) = serve_once(|mut stream| {
        let head =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n";
        if stream.write_all(head).is_err() {
            return;
        }
        // One byte every 100 ms: every single receive succeeds well within its own timeout.
        let stop = Instant::now() + Duration::from_mins(1);
        while Instant::now() < stop {
            if stream
                .write_all(b" ")
                .and_then(|()| stream.flush())
                .is_err()
            {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    })?;
    let client = Client::new_loopback(Timeouts {
        resolve_ms: 200,
        connect_ms: 200,
        send_ms: 200,
        receive_ms: 1_000,
    })?;
    let started = Instant::now();
    let result = client.post(
        &url,
        &[("Content-Type", "application/json")],
        b"{}",
        1_000_000,
    );
    let elapsed = started.elapsed();
    assert_eq!(result.map(|_| ()), Err(HttpError::Timeout));
    // The total deadline is 1.6 s; a generous bound keeps a loaded machine from failing the test
    // while still far below the ~10,000 s the trickle would take.
    assert!(elapsed < Duration::from_secs(20), "{elapsed:?}");
    drop(client);
    server.join().map_err(|_| "server thread panicked")?;
    Ok(())
}
