//! R-F1 (spec/05 §10.2): the frame codec, ported from
//! `archive/spec-v2.4:crates/native-host/src/lib.rs:444-572` with the JSON cases removed (parsing
//! is separate now) and the length fixed to little-endian.

use std::io::{self, Cursor, Read};

use yw_json::frame::{FrameError, MAX_FRAME_BYTES, read_frame, write_frame};

fn framed(payload: &[u8]) -> Vec<u8> {
    let mut frame = u32::try_from(payload.len())
        .map_or_else(|_| Vec::new(), |length| length.to_le_bytes().to_vec());
    frame.extend_from_slice(payload);
    frame
}

/// Serves the 4 length bytes, then fails any further read: proves the payload is never read.
struct LengthOnly {
    length: [u8; 4],
    served: usize,
}

impl Read for LengthOnly {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self.length.get(self.served..).unwrap_or_default();
        if remaining.is_empty() {
            return Err(io::Error::other("payload must not be read"));
        }
        let count = remaining.len().min(buffer.len());
        for (slot, byte) in buffer.iter_mut().zip(remaining) {
            *slot = *byte;
        }
        self.served += count;
        Ok(count)
    }
}

/// Returns one byte per call, with an `Interrupted` error before every byte.
struct Trickle {
    bytes: Vec<u8>,
    position: usize,
    interrupt_next: bool,
}

impl Read for Trickle {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.interrupt_next {
            self.interrupt_next = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.interrupt_next = true;
        match (self.bytes.get(self.position), buffer.first_mut()) {
            (Some(byte), Some(slot)) => {
                *slot = *byte;
                self.position += 1;
                Ok(1)
            }
            _ => Ok(0),
        }
    }
}

#[test]
fn r_f1_round_trip_keeps_bytes() {
    let payload = br#"{"message_type":"HealthCheck","sequence":1}"#;
    let mut bytes = Vec::new();
    write_frame(&mut bytes, payload, MAX_FRAME_BYTES).unwrap();
    assert_eq!(bytes, framed(payload));
    let mut reader = Cursor::new(bytes);
    assert_eq!(
        read_frame(&mut reader, MAX_FRAME_BYTES).unwrap().as_deref(),
        Some(payload.as_slice())
    );
    assert_eq!(read_frame(&mut reader, MAX_FRAME_BYTES), Ok(None));
}

#[test]
fn r_f1_round_trip_at_the_limit_and_across_short_reads() {
    let payload = vec![b'x'; MAX_FRAME_BYTES];
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &payload, MAX_FRAME_BYTES).unwrap();
    assert_eq!(bytes.len(), MAX_FRAME_BYTES + 4);
    assert_eq!(
        read_frame(&mut Cursor::new(bytes), MAX_FRAME_BYTES).unwrap(),
        Some(payload)
    );
    let mut trickle = Trickle {
        bytes: [framed(b"{}"), framed(b"[1]")].concat(),
        position: 0,
        interrupt_next: true,
    };
    assert_eq!(
        read_frame(&mut trickle, MAX_FRAME_BYTES)
            .unwrap()
            .as_deref(),
        Some(b"{}".as_slice())
    );
    assert_eq!(
        read_frame(&mut trickle, MAX_FRAME_BYTES)
            .unwrap()
            .as_deref(),
        Some(b"[1]".as_slice())
    );
    assert_eq!(read_frame(&mut trickle, MAX_FRAME_BYTES), Ok(None));
}

#[test]
fn r_f1_clean_eof_is_none() {
    assert_eq!(
        read_frame(&mut Cursor::new(Vec::<u8>::new()), MAX_FRAME_BYTES),
        Ok(None)
    );
}

#[test]
fn r_f1_zero_and_oversize_lengths_fail_before_payload_read() {
    let over = u32::try_from(MAX_FRAME_BYTES + 1).unwrap();
    assert_eq!(over, 1_048_577);
    for length in [0_u32, over, u32::MAX] {
        let mut reader = LengthOnly {
            length: length.to_le_bytes(),
            served: 0,
        };
        assert_eq!(
            read_frame(&mut reader, MAX_FRAME_BYTES),
            Err(FrameError::Oversized),
            "{length}"
        );
        assert_eq!(reader.served, 4);
    }
    let mut reader = LengthOnly {
        length: 3_u32.to_le_bytes(),
        served: 0,
    };
    assert_eq!(read_frame(&mut reader, 2), Err(FrameError::Oversized));
}

#[test]
fn r_f1_truncated_length_and_payload() {
    assert_eq!(
        read_frame(&mut Cursor::new([1_u8, 0]), MAX_FRAME_BYTES),
        Err(FrameError::Truncated)
    );
    let mut partial = 5_u32.to_le_bytes().to_vec();
    partial.extend_from_slice(b"{}");
    assert_eq!(
        read_frame(&mut Cursor::new(partial), MAX_FRAME_BYTES),
        Err(FrameError::Truncated)
    );
}

#[test]
fn r_f1_length_is_little_endian() {
    let bytes = [0x02_u8, 0x00, 0x00, 0x00, 0x7b, 0x7d];
    assert_eq!(
        read_frame(&mut Cursor::new(bytes), MAX_FRAME_BYTES)
            .unwrap()
            .as_deref(),
        Some(b"{}".as_slice())
    );
    let mut written = Vec::new();
    write_frame(&mut written, b"{}", MAX_FRAME_BYTES).unwrap();
    assert_eq!(written, bytes);
}

#[test]
fn r_f1_write_rejects_empty_and_oversize_without_writing() {
    let mut written = Vec::new();
    assert_eq!(
        write_frame(&mut written, b"", MAX_FRAME_BYTES),
        Err(FrameError::Oversized)
    );
    assert_eq!(
        write_frame(
            &mut written,
            &vec![b'a'; MAX_FRAME_BYTES + 1],
            MAX_FRAME_BYTES
        ),
        Err(FrameError::Oversized)
    );
    assert_eq!(
        write_frame(&mut written, b"abc", 2),
        Err(FrameError::Oversized)
    );
    assert!(written.is_empty());
}

#[test]
fn r_f1_io_errors_map_to_io() {
    struct Failing;
    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("secret detail"))
        }
    }
    impl io::Write for Failing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("secret detail"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        read_frame(&mut Failing, MAX_FRAME_BYTES),
        Err(FrameError::Io)
    );
    assert_eq!(
        write_frame(&mut Failing, b"{}", MAX_FRAME_BYTES),
        Err(FrameError::Io)
    );
}

#[test]
fn r_f1_error_display_has_no_detail() {
    for error in [
        FrameError::Truncated,
        FrameError::Oversized,
        FrameError::Allocation,
        FrameError::Io,
    ] {
        let text = error.to_string();
        assert!(text.starts_with("frame "), "{text}");
        assert!(std::error::Error::source(&error).is_none());
    }
}
