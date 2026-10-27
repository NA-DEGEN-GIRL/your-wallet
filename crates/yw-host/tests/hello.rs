//! R-P1, host side (spec/05 §8.2, §10.2): the hello equals `pipe-hello.golden.json`, the golden
//! hello-ack is accepted, a hello-reject or any other reply is not, and the 2 s deadline cancels
//! a reply that never comes.

use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use yw_host::{HOST_VERSION, encode_hello, hello_exchange, parse_hello_ack, run_with_deadline};
use yw_json::{Limits, parse};

const HELLO: &str = include_str!("../../../extension/native-host/pipe-hello.golden.json");
const ACK: &str = include_str!("../../../extension/native-host/pipe-hello-ack.golden.json");
const PLACEHOLDER_ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";

fn framed(payload: &[u8]) -> Vec<u8> {
    let mut frame = u32::try_from(payload.len())
        .map_or_else(|_| Vec::new(), |length| length.to_le_bytes().to_vec());
    frame.extend_from_slice(payload);
    frame
}

#[test]
fn r_p1_hello_matches_the_golden() {
    let hello = encode_hello("0.3.0", PLACEHOLDER_ORIGIN, 1234);
    // Order-sensitive `Value` equality: same keys, values and key order as the golden.
    assert_eq!(
        parse(&hello, &Limits::REQUEST).unwrap(),
        parse(HELLO.as_bytes(), &Limits::REQUEST).unwrap()
    );
    assert_eq!(HOST_VERSION, env!("CARGO_PKG_VERSION"));
    assert!((1..=32).contains(&HOST_VERSION.chars().count()));
}

#[test]
fn r_p1_golden_ack_is_accepted() {
    assert!(parse_hello_ack(ACK.as_bytes()));
    assert!(parse_hello_ack(
        br#"{"appVersion":"0.3.0","kind":"hello-ack","protocol":1}"#
    ));
    let longest = format!(
        r#"{{"kind":"hello-ack","protocol":1,"appVersion":"{}"}}"#,
        "v".repeat(32)
    );
    assert!(parse_hello_ack(longest.as_bytes()));
}

#[test]
fn r_p1_reject_and_malformed_replies_are_refused() {
    let too_long = format!(
        r#"{{"kind":"hello-ack","protocol":1,"appVersion":"{}"}}"#,
        "v".repeat(33)
    );
    let refused: Vec<&[u8]> = vec![
        br#"{"kind":"hello-reject","reason":"origin"}"#,
        br#"{"kind":"hello-reject","reason":"protocol"}"#,
        br#"{"kind":"hello-ack","protocol":2,"appVersion":"0.3.0"}"#,
        br#"{"kind":"hello-ack","protocol":"1","appVersion":"0.3.0"}"#,
        br#"{"kind":"hello-ack","protocol":1.0,"appVersion":"0.3.0"}"#,
        br#"{"kind":"hello-ack","protocol":1,"appVersion":"0.3.0","extra":true}"#,
        br#"{"kind":"hello-ack","protocol":1}"#,
        br#"{"kind":"hello-ack","protocol":1,"appVersion":""}"#,
        br#"{"kind":"hello-ack","protocol":1,"appVersion":3}"#,
        br#"{"kind":"hello","protocol":1,"appVersion":"0.3.0"}"#,
        br#"{"kind":"hello-ack","protocol":1,"appVersion":"0.3.0","protocol":1}"#,
        br#"[{"kind":"hello-ack","protocol":1,"appVersion":"0.3.0"}]"#,
        b"not json",
        too_long.as_bytes(),
    ];
    for reply in refused {
        assert!(
            !parse_hello_ack(reply),
            "{}",
            String::from_utf8_lossy(reply)
        );
    }
}

#[test]
fn r_p1_exchange_sends_the_hello_and_needs_an_ack() {
    let mut sent = Vec::new();
    let mut reply = Cursor::new(framed(ACK.as_bytes()));
    assert!(hello_exchange(
        &mut reply,
        &mut sent,
        PLACEHOLDER_ORIGIN,
        1234
    ));
    assert_eq!(
        sent,
        framed(&encode_hello(HOST_VERSION, PLACEHOLDER_ORIGIN, 1234))
    );

    let reject = framed(br#"{"kind":"hello-reject","reason":"origin"}"#);
    assert!(!hello_exchange(
        &mut Cursor::new(reject),
        &mut Vec::new(),
        PLACEHOLDER_ORIGIN,
        1
    ));
    assert!(!hello_exchange(
        &mut Cursor::new(Vec::new()),
        &mut Vec::new(),
        PLACEHOLDER_ORIGIN,
        1
    ));
}

#[test]
fn r_p1_deadline_cancels_a_missing_reply() {
    // A reply in time: the watchdog never fires.
    let fired = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&fired);
    let result = run_with_deadline(
        Duration::from_secs(5),
        move || flag.store(true, Ordering::SeqCst),
        || 42,
    );
    assert_eq!(result, Some(42));
    assert!(!fired.load(Ordering::SeqCst));

    // No reply: the cancel unblocks the waiting work and the result is discarded.
    let (unblock, blocked) = mpsc::channel::<()>();
    let result = run_with_deadline(
        Duration::from_millis(30),
        move || {
            let _ = unblock.send(());
        },
        || blocked.recv().is_ok(),
    );
    assert_eq!(result, None);
}
