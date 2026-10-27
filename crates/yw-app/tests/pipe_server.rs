//! spec/05 §10.2 R-P2 (user-only DACL, first-instance rule, the fifth client is busy) and the
//! yw-app pipe server end to end over a real named pipe: hello/hello-ack, hello-reject for a
//! foreign origin, per-request answers with the connection's own outbound sequence, a malformed
//! frame that keeps the connection, and a framing error that closes only that connection.
//! Pipe names are `\\.\pipe\YourWallet.test.<pid>.<n>` (spec/09 §2.1).

mod common;

use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use common::FakeClock;
use common::browser::{GOLDEN_ID, NOW_UNIX, RequestSpec, Sink, json, request_frame, wallet};
use yw_app::browser::server::start;
use yw_app::browser::{BrowserCore, DappSink, VaultView};
use yw_app::settings::Settings;
use yw_json::frame::{MAX_FRAME_BYTES, read_frame, write_frame};
use yw_json::{Limits, Number, Value};
use yw_win::pipe::{ConnectError, Server, ServerError, connect_client, user_only_sddl};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

static NEXT: AtomicU32 = AtomicU32::new(1);

fn name() -> String {
    format!(
        r"\\.\pipe\YourWallet.test.{}.{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

fn origin() -> String {
    format!("chrome-extension://{GOLDEN_ID}/")
}

fn hello(origin: &str) -> Vec<u8> {
    format!(
        r#"{{"kind":"hello","protocol":1,"hostVersion":"0.3.0","extensionOrigin":"{origin}","pid":4321}}"#
    )
    .into_bytes()
}

fn core() -> Arc<BrowserCore> {
    let core = BrowserCore::new(
        GOLDEN_ID,
        Arc::new(Sink::default()) as Arc<dyn DappSink>,
        Arc::new(FakeClock::at(NOW_UNIX)) as Arc<dyn yw_app::flow::evm::Clock>,
    );
    core.set_wallet(wallet(VaultView::Locked, &Settings::default()));
    core
}

fn field(frame: &[u8], key: &str) -> TestResult<Value> {
    let value = yw_json::parse(frame, &Limits::RESPONSE)?;
    Ok(value
        .as_object()
        .and_then(|object| object.get(key))
        .cloned()
        .unwrap_or(Value::Null))
}

fn number(value: &Value) -> Option<u64> {
    value.as_number().and_then(Number::as_u64)
}

fn request(sequence: u64, request: u8) -> Vec<u8> {
    request_frame(&RequestSpec {
        sequence,
        request,
        document: 1,
        origin: "https://app.example",
        method: "eth_chainId",
        params: json("[]"),
        route: "permission",
        deadline: NOW_UNIX + 600_000,
    })
}

#[test]
fn r_p2_user_only_dacl_first_instance_and_busy() -> TestResult {
    let sid = yw_win::current_user_sid_string()?;
    let pipe = name();
    let server = Server::create(&pipe, &user_only_sddl(&sid))?;
    let summary = server.security_summary()?;
    assert_eq!(summary.owner, sid);
    assert!(summary.dacl_protected);
    assert_eq!(summary.aces.len(), 1);
    assert_eq!(summary.aces[0].sid, sid);
    assert_eq!(summary.aces[0].ace_type, 0, "ACCESS_ALLOWED_ACE_TYPE");
    assert!(matches!(
        Server::create(&pipe, &user_only_sddl(&sid)),
        Err(ServerError::AlreadyExists)
    ));
    drop(server);
    // The app server: four instances, the fifth client is busy.
    let pipe = name();
    let mut running = start(core(), &pipe, origin())?;
    let mut clients = Vec::new();
    for _ in 0..4 {
        let mut client = None;
        for _ in 0..100 {
            match connect_client(&pipe) {
                Ok(duplex) => {
                    client = Some(duplex);
                    break;
                }
                Err(ConnectError::Busy | ConnectError::NotFound) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(other) => return Err(format!("connect: {other:?}").into()),
            }
        }
        clients.push(client.ok_or("no instance")?);
    }
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(matches!(connect_client(&pipe), Err(ConnectError::Busy)));
    drop(clients);
    running.stop();
    Ok(())
}

#[test]
fn server_hello_requests_and_framing_errors() -> TestResult {
    let pipe = name();
    let mut running = start(core(), &pipe, origin())?;
    // A foreign origin is refused (the reject may be discarded with the instance; either way
    // the connection ends without carrying envelopes).
    let (mut reader, mut writer) = connect_client(&pipe)
        .map_err(|error| format!("{error:?}"))?
        .split();
    write_frame(
        &mut writer,
        &hello("chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba/"),
        MAX_FRAME_BYTES,
    )?;
    if let Ok(Some(frame)) = read_frame(&mut reader, MAX_FRAME_BYTES) {
        assert_eq!(frame, br#"{"kind":"hello-reject","reason":"origin"}"#);
    }
    assert!(matches!(
        read_frame(&mut reader, MAX_FRAME_BYTES),
        Ok(None) | Err(_)
    ));
    drop((reader, writer));
    // The pinned origin is accepted.
    let (mut reader, mut writer) = connect_client(&pipe)
        .map_err(|error| format!("{error:?}"))?
        .split();
    write_frame(&mut writer, &hello(&origin()), MAX_FRAME_BYTES)?;
    let ack = read_frame(&mut reader, MAX_FRAME_BYTES)?.ok_or("no ack")?;
    assert_eq!(field(&ack, "kind")?, Value::String("hello-ack".to_owned()));
    assert_eq!(
        field(&ack, "appVersion")?,
        Value::String(env!("CARGO_PKG_VERSION").to_owned())
    );
    // A request is answered with outbound sequence 1.
    write_frame(&mut writer, &request(1, 1), MAX_FRAME_BYTES)?;
    let first = read_frame(&mut reader, MAX_FRAME_BYTES)?.ok_or("no response")?;
    assert_eq!(number(&field(&first, "sequence")?), Some(1));
    assert_eq!(number(&field(&first, "requestSequence")?), Some(1));
    assert_eq!(
        field(&first, "result")?,
        Value::String("0xaa36a7".to_owned())
    );
    // Not JSON: dropped, the connection stays; the next request gets sequence 2.
    write_frame(&mut writer, b"not json", MAX_FRAME_BYTES)?;
    write_frame(&mut writer, &request(2, 2), MAX_FRAME_BYTES)?;
    let second = read_frame(&mut reader, MAX_FRAME_BYTES)?.ok_or("no response")?;
    assert_eq!(number(&field(&second, "sequence")?), Some(2));
    assert_eq!(number(&field(&second, "requestSequence")?), Some(2));
    // A zero-length frame is a framing error: this connection closes.
    writer.write_all(&[0, 0, 0, 0])?;
    writer.flush()?;
    assert!(matches!(
        read_frame(&mut reader, MAX_FRAME_BYTES),
        Ok(None) | Err(_)
    ));
    running.stop();
    Ok(())
}
