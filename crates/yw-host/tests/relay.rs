//! R-H3 (spec/05 §7.3, §7.5, §10.2): the relay copies frames byte for byte in both directions;
//! more than 1 MiB from Chrome exits 4, from yw-app exits 5; other I/O failures exit 6.

use std::io::{self, Cursor, Write};
use std::sync::mpsc;

use yw_host::{
    EXIT_APP_FRAMING, EXIT_CHROME_FRAMING, EXIT_EOF, EXIT_IO, pump_app, pump_stdin, relay_to_app,
};
use yw_json::frame::MAX_FRAME_BYTES;

const REQUEST: &str = include_str!("../../../extension/native-host/v1-request.golden.json");

fn framed(payload: &[u8]) -> Vec<u8> {
    let mut frame = u32::try_from(payload.len())
        .map_or_else(|_| Vec::new(), |length| length.to_le_bytes().to_vec());
    frame.extend_from_slice(payload);
    frame
}

/// Non-JSON bytes are relayed unchanged too: yw-host does not interpret frames.
fn sample_stream() -> Vec<u8> {
    let mut largest = vec![b' '; MAX_FRAME_BYTES];
    largest[0] = b'{';
    largest[MAX_FRAME_BYTES - 1] = b'}';
    [
        framed(b"{}"),
        framed(REQUEST.as_bytes()),
        framed(&[0x00, 0xff, 0x0a, 0x0d, 0x1a]),
        framed(&largest),
        framed(b"x"),
    ]
    .concat()
}

fn oversize_header() -> Vec<u8> {
    u32::try_from(MAX_FRAME_BYTES + 1)
        .map_or_else(|_| Vec::new(), |length| length.to_le_bytes().to_vec())
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

#[test]
fn r_h3_chrome_to_app_is_byte_identical() {
    let stream = sample_stream();
    let (queue, frames) = mpsc::sync_channel(64);
    assert_eq!(
        pump_stdin(&mut Cursor::new(stream.clone()), &queue),
        EXIT_EOF
    );
    drop(queue);
    let mut pipe = Vec::new();
    let mut foreground_calls = 0;
    let code = relay_to_app(&frames, &mut pipe, || foreground_calls += 1);
    assert_eq!(code, EXIT_EOF);
    assert!(pipe == stream);
    assert_eq!(foreground_calls, 5);
}

#[test]
fn r_h3_app_to_chrome_is_byte_identical() {
    let stream = sample_stream();
    let mut stdout = Vec::new();
    assert_eq!(
        pump_app(&mut Cursor::new(stream.clone()), &mut stdout),
        EXIT_EOF
    );
    assert!(stdout == stream);
}

#[test]
fn r_h3_oversize_or_truncated_from_chrome_exits_4() {
    let mut input = framed(b"{}");
    input.extend(oversize_header());
    input.extend(vec![b'a'; 16]);
    let (queue, frames) = mpsc::sync_channel(64);
    assert_eq!(
        pump_stdin(&mut Cursor::new(input), &queue),
        EXIT_CHROME_FRAMING
    );
    drop(queue);
    assert_eq!(frames.iter().collect::<Vec<_>>(), vec![b"{}".to_vec()]);

    let (queue, _frames) = mpsc::sync_channel(64);
    let zero = 0_u32.to_le_bytes().to_vec();
    assert_eq!(
        pump_stdin(&mut Cursor::new(zero), &queue),
        EXIT_CHROME_FRAMING
    );
    let mut truncated = framed(b"{\"a\":1}");
    truncated.pop();
    assert_eq!(
        pump_stdin(&mut Cursor::new(truncated), &queue),
        EXIT_CHROME_FRAMING
    );
}

#[test]
fn r_h3_oversize_or_truncated_from_app_exits_5() {
    let mut input = framed(b"{}");
    input.extend(oversize_header());
    input.extend(vec![b'a'; 16]);
    let mut stdout = Vec::new();
    assert_eq!(
        pump_app(&mut Cursor::new(input), &mut stdout),
        EXIT_APP_FRAMING
    );
    assert_eq!(stdout, framed(b"{}"));

    let mut truncated = framed(b"{\"a\":1}");
    truncated.pop();
    assert_eq!(
        pump_app(&mut Cursor::new(truncated), &mut Vec::new()),
        EXIT_APP_FRAMING
    );
}

#[test]
fn r_h3_write_failures_exit_6() {
    assert_eq!(
        pump_app(&mut Cursor::new(framed(b"{}")), &mut Broken),
        EXIT_IO
    );
    let (queue, frames) = mpsc::sync_channel(1);
    queue.send(b"{}".to_vec()).unwrap();
    assert_eq!(relay_to_app(&frames, &mut Broken, || {}), EXIT_IO);
}
