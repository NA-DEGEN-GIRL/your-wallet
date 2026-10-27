//! Native messaging and pipe framing (spec/05 §7.3): a 4-byte little-endian length followed by
//! that many payload bytes, at most [`MAX_FRAME_BYTES`].
//!
//! Ported from `archive/spec-v2.4:crates/native-host/src/lib.rs:81-225` as a byte-level API: JSON
//! parsing is the caller's job, the length is fixed to little-endian (the archive used native
//! endianness) and the limit is an argument. The length is checked before any payload byte is
//! read or any buffer is allocated.

use core::fmt;
use std::io::{self, Read, Write};

/// Largest frame in either direction (Chrome's host→extension limit; spec/05 §7.3).
pub const MAX_FRAME_BYTES: usize = 1_048_576;

/// Framing failure. `Display` carries no frame content or OS detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The stream ended inside the length prefix or the payload.
    Truncated,
    /// The length is 0 or exceeds the limit.
    Oversized,
    /// The payload buffer could not be reserved.
    Allocation,
    /// The underlying reader or writer failed.
    Io,
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "frame truncated",
            Self::Oversized => "frame length out of range",
            Self::Allocation => "frame allocation failed",
            Self::Io => "frame I/O failed",
        })
    }
}

impl std::error::Error for FrameError {}

/// Reads one frame of at most `max` bytes.
///
/// A clean EOF before the first length byte returns `Ok(None)`. A length of 0 or above `max`
/// returns [`FrameError::Oversized`] before the payload is allocated or read.
///
/// # Errors
///
/// [`FrameError::Truncated`] for EOF inside the frame, [`FrameError::Oversized`],
/// [`FrameError::Allocation`] or [`FrameError::Io`].
pub fn read_frame(reader: &mut impl Read, max: usize) -> Result<Option<Vec<u8>>, FrameError> {
    let mut first = [0_u8; 1];
    loop {
        match reader.read(&mut first) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(FrameError::Io),
        }
    }
    let mut rest = [0_u8; 3];
    read_exact_or_truncated(reader, &mut rest)?;
    let [b0] = first;
    let [b1, b2, b3] = rest;
    let length =
        usize::try_from(u32::from_le_bytes([b0, b1, b2, b3])).map_err(|_| FrameError::Oversized)?;
    if length == 0 || length > max {
        return Err(FrameError::Oversized);
    }
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(length)
        .map_err(|_| FrameError::Allocation)?;
    payload.resize(length, 0);
    read_exact_or_truncated(reader, &mut payload)?;
    Ok(Some(payload))
}

/// Writes `payload` as one frame (little-endian `u32` length, then the bytes) and flushes.
///
/// # Errors
///
/// [`FrameError::Oversized`] for an empty payload or one above `max` (nothing is written), or
/// [`FrameError::Io`].
pub fn write_frame(writer: &mut impl Write, payload: &[u8], max: usize) -> Result<(), FrameError> {
    if payload.is_empty() || payload.len() > max {
        return Err(FrameError::Oversized);
    }
    let length = u32::try_from(payload.len()).map_err(|_| FrameError::Oversized)?;
    writer
        .write_all(&length.to_le_bytes())
        .and_then(|()| writer.write_all(payload))
        .and_then(|()| writer.flush())
        .map_err(|_| FrameError::Io)
}

fn read_exact_or_truncated(reader: &mut impl Read, buffer: &mut [u8]) -> Result<(), FrameError> {
    reader.read_exact(buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            FrameError::Truncated
        } else {
            FrameError::Io
        }
    })
}
