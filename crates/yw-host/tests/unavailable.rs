//! R-H2 (spec/05 §7.6, §10.2): the UNAVAILABLE responder answers a golden request with exactly
//! `v1-unavailable-response.golden.json` (sequence 1) and stays silent for everything else.

use std::io::{self, Cursor, Write};
use std::sync::mpsc;
use std::time::Duration;

use yw_host::{
    EXIT_EOF, EXIT_IO, EXIT_UNAVAILABLE, encode_unavailable, run_unavailable,
    unavailable_correlation,
};
use yw_json::frame::{MAX_FRAME_BYTES, read_frame};
use yw_json::{Limits, Value, parse};

const REQUEST: &str = include_str!("../../../extension/native-host/v1-request.golden.json");
const CANCEL: &str = include_str!("../../../extension/native-host/v1-cancel.golden.json");
const RESPONSE: &str =
    include_str!("../../../extension/native-host/v1-unavailable-response.golden.json");

type Outcome = Result<(u8, Vec<Value>), Box<dyn std::error::Error>>;

/// Runs the responder over `frames` with the queue kept open (so it ends by idling).
fn respond(frames: &[Vec<u8>]) -> Outcome {
    let (queue, received) = mpsc::sync_channel(64);
    for frame in frames {
        queue.send(frame.clone())?;
    }
    let mut output = Vec::new();
    let code = run_unavailable(&received, &mut output, Duration::from_millis(20));
    drop(queue);
    let mut reader = Cursor::new(output);
    let mut responses = Vec::new();
    while let Some(frame) = read_frame(&mut reader, MAX_FRAME_BYTES)? {
        responses.push(parse(&frame, &Limits::RESPONSE)?);
    }
    Ok((code, responses))
}

struct Broken;

impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn golden(text: &str) -> Result<Value, yw_json::ParseError> {
    parse(text.as_bytes(), &Limits::RESPONSE)
}

fn variant(from: &str, to: &str) -> Vec<u8> {
    REQUEST.replacen(from, to, 1).into_bytes()
}

#[test]
fn r_h2_golden_request_gets_the_golden_response() -> Result<(), Box<dyn std::error::Error>> {
    let (code, responses) = respond(&[REQUEST.as_bytes().to_vec()])?;
    assert_eq!(code, EXIT_UNAVAILABLE);
    // `Value` equality is order-sensitive for objects, so this also checks the key order.
    assert_eq!(responses, vec![golden(RESPONSE)?]);
    Ok(())
}

#[test]
fn r_h2_sequence_counts_responses_and_echoes_the_request_sequence()
-> Result<(), Box<dyn std::error::Error>> {
    let (code, responses) = respond(&[
        REQUEST.as_bytes().to_vec(),
        CANCEL.as_bytes().to_vec(),
        variant("\"sequence\": 1,", "\"sequence\": 7.0,"),
    ])?;
    assert_eq!(code, EXIT_UNAVAILABLE);
    assert_eq!(responses.len(), 2);
    let second = responses[1].as_object().unwrap();
    let number = |key: &str| {
        second
            .get(key)
            .and_then(Value::as_number)
            .and_then(yw_json::Number::as_u64)
    };
    assert_eq!(number("sequence"), Some(2));
    assert_eq!(number("requestSequence"), Some(7));
    Ok(())
}

#[test]
fn r_h2_cancel_other_versions_and_malformed_frames_get_no_output()
-> Result<(), Box<dyn std::error::Error>> {
    let zero64 = "0".repeat(64);
    let frames = vec![
        CANCEL.as_bytes().to_vec(),
        variant("\"version\": 1,", "\"version\": 2,"),
        variant("\"version\": 1,", "\"version\": \"1\","),
        variant("\"version\": 1,", "\"version\": 1e0,"),
        variant("\"kind\": \"request\"", "\"kind\": \"event\""),
        variant("\"sequence\": 1,", "\"sequence\": 0,"),
        variant("\"sequence\": 1,", "\"sequence\": -1,"),
        variant("\"sequence\": 1,", "\"sequence\": 1.5,"),
        variant("\"sequence\": 1,", "\"sequence\": 9007199254740992,"),
        variant("\"sequence\": 1,", "\"sequence\": \"1\","),
        variant("\"sessionId\"", "\"session\""),
        variant(&"b".repeat(64), &"B".repeat(64)),
        variant(&"b".repeat(64), &"b".repeat(63)),
        variant(&"b".repeat(64), &zero64),
        variant(
            "01010101010101010101010101010101",
            "00000000000000000000000000000000",
        ),
        variant(
            "01010101010101010101010101010101",
            "0101010101010101010101010101010g",
        ),
        variant(
            "000000000000000000000000000000000000000000000000000000000000000c",
            "000000000000000000000000000000000000000000000000000000000000000",
        ),
        variant("\"method\"", "\"sequence\": 2, \"x\""),
        format!("{REQUEST} {{}}").into_bytes(),
        REQUEST.as_bytes()[..REQUEST.len() / 2].to_vec(),
        b"[]".to_vec(),
        b"null".to_vec(),
        b"\xff\xfe".to_vec(),
    ];
    let (code, responses) = respond(&frames)?;
    assert_eq!(code, EXIT_UNAVAILABLE);
    assert!(responses.is_empty(), "{responses:?}");
    Ok(())
}

#[test]
fn r_h2_only_correlation_fields_are_read() {
    // Unknown extra keys and a broken `params` do not matter: nothing else is interpreted.
    let frame = variant("\"params\": []", "\"params\": 5, \"zzz\": {\"a\": [1]}");
    let correlation = unavailable_correlation(&frame).unwrap();
    assert_eq!(correlation.sequence, 1);
    assert_eq!(correlation.request_id, "01".repeat(16));
    let golden_bytes = encode_unavailable(&correlation, 1);
    assert_eq!(
        parse(&golden_bytes, &Limits::RESPONSE).ok(),
        golden(RESPONSE).ok()
    );
}

/// The mode ends `idle` after it began even while requests keep coming (2026-11-12): a page
/// that asks twice a second must not keep a host alive that never looks for the app again.
#[test]
fn r_h2_steady_requests_do_not_keep_the_mode_alive() {
    let (queue, received) = mpsc::sync_channel(64);
    let sender = std::thread::spawn(move || {
        // Far more often than the life of the mode; ends when the receiver is gone.
        while queue.send(REQUEST.as_bytes().to_vec()).is_ok() {
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let mut output = Vec::new();
    let code = run_unavailable(&received, &mut output, Duration::from_millis(60));
    drop(received);
    assert_eq!(code, EXIT_UNAVAILABLE);
    assert!(!output.is_empty());
    assert!(sender.join().is_ok());
}

#[test]
fn r_h2_closed_queue_is_eof_and_stdout_failure_is_io() -> Result<(), Box<dyn std::error::Error>> {
    let (queue, received) = mpsc::sync_channel::<Vec<u8>>(1);
    drop(queue);
    assert_eq!(
        run_unavailable(&received, &mut Vec::new(), Duration::from_secs(5)),
        EXIT_EOF
    );

    let (queue, received) = mpsc::sync_channel(1);
    queue.send(REQUEST.as_bytes().to_vec())?;
    assert_eq!(
        run_unavailable(&received, &mut Broken, Duration::from_millis(20)),
        EXIT_IO
    );
    Ok(())
}
