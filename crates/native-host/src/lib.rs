//! Bounded Chrome Native Messaging framing and strict JSON parsing.
//!
//! The shim intentionally owns no wallet state. Its only security-sensitive job
//! is to reject malformed frames before forwarding them to the broker.

use std::cell::Cell;
use std::collections::HashSet;
use std::fmt;
use std::io::{self, Read, Write};

use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use thiserror::Error;

mod wire;

#[cfg(all(feature = "broker-ipc-contract-test-hook", debug_assertions))]
mod contract_bridge;

pub use wire::{
    BrokerEndpoint, BrokerEndpointError, DispatchOutcome, DownstreamExecutor, ExecutionOutcome,
    ExtensionEnvelope, NativeHostDispatcher, NativeRpcError, ProtocolError, RuntimeSummary,
    UnattestedOutcome, parse_extension_envelope, run_persistent_stream,
    run_release_disabled_stream, run_unattested_once,
};

#[cfg(all(feature = "broker-ipc-contract-test-hook", debug_assertions))]
pub use contract_bridge::{ContractBridgeError, run_broker_contract_test_stream};

/// Failure to put the Chrome native-messaging pipe into binary mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("binary standard I/O mode is unavailable")]
pub struct BinaryStdioError;

/// Configures stdin and stdout for Chrome's binary native-messaging framing.
///
/// Windows otherwise treats the inherited descriptors as text streams and may
/// rewrite bytes in a length-prefixed frame. Other platforms need no setup.
///
/// # Errors
///
/// Returns [`BinaryStdioError`] when Windows rejects binary mode for either
/// inherited descriptor.
#[cfg_attr(windows, allow(unsafe_code))]
pub fn set_binary_stdio() -> Result<(), BinaryStdioError> {
    #[cfg(windows)]
    {
        const O_BINARY: i32 = 0x8000;

        unsafe extern "C" {
            fn _setmode(fd: i32, mode: i32) -> i32;
        }

        // SAFETY: `_setmode` is invoked for the process' inherited stdin (0)
        // and stdout (1) descriptors with the documented `_O_BINARY` flag.
        let (input_mode, output_mode) = unsafe { (_setmode(0, O_BINARY), _setmode(1, O_BINARY)) };
        if input_mode == -1 || output_mode == -1 {
            return Err(BinaryStdioError);
        }
    }

    Ok(())
}

/// Wallet-enforced frame limit in either direction.
pub const MAX_FRAME_BYTES: usize = 1_048_576;

/// Maximum accepted JSON object/array nesting.
pub const MAX_JSON_DEPTH: usize = 32;

/// Maximum aggregate value/key nodes accepted in one JSON document.
pub const MAX_JSON_NODES: usize = 8_192;

/// Maximum aggregate array elements and object members accepted in one document.
pub const MAX_JSON_CONTAINER_ITEMS: usize = 4_096;

/// A framing or strict-JSON failure.
#[derive(Error)]
pub enum FrameError {
    /// The stream ended between length bytes or payload bytes.
    #[error("truncated native-messaging frame")]
    Truncated,
    /// The advertised frame exceeds the wallet policy cap.
    #[error("native-messaging frame exceeds policy limit")]
    Oversized,
    /// Allocation failed without attempting an unbounded fallback.
    #[error("native-messaging frame allocation failed")]
    Allocation,
    /// Payload bytes were not strict UTF-8.
    #[error("native-messaging payload is not UTF-8")]
    InvalidUtf8,
    /// JSON syntax or structural policy validation failed.
    #[error("native-messaging payload is not canonical strict JSON")]
    InvalidJson,
    /// A duplicate object member was found.
    #[error("native-messaging JSON contains a duplicate object member")]
    DuplicateKey,
    /// Object/array nesting exceeded the fixed bound.
    #[error("native-messaging JSON nesting exceeds policy limit")]
    ExcessiveDepth,
    /// Aggregate values and object-key nodes exceeded the fixed bound.
    #[error("native-messaging JSON node count exceeds policy limit")]
    ExcessiveNodes,
    /// Aggregate array elements and object members exceeded the fixed bound.
    #[error("native-messaging JSON container item count exceeds policy limit")]
    ExcessiveContainerItems,
    /// The root must be an object so message dispatch cannot depend on type coercion.
    #[error("native-messaging JSON root must be an object")]
    RootNotObject,
    /// Underlying I/O failed for a reason other than an incomplete frame.
    #[error("native-messaging I/O failed")]
    Io,
}

impl fmt::Debug for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "FrameError::Truncated",
            Self::Oversized => "FrameError::Oversized",
            Self::Allocation => "FrameError::Allocation",
            Self::InvalidUtf8 => "FrameError::InvalidUtf8",
            Self::InvalidJson => "FrameError::InvalidJson",
            Self::DuplicateKey => "FrameError::DuplicateKey",
            Self::ExcessiveDepth => "FrameError::ExcessiveDepth",
            Self::ExcessiveNodes => "FrameError::ExcessiveNodes",
            Self::ExcessiveContainerItems => "FrameError::ExcessiveContainerItems",
            Self::RootNotObject => "FrameError::RootNotObject",
            Self::Io => "FrameError::Io([REDACTED])",
        })
    }
}

/// Read exactly one Chrome Native Messaging frame.
///
/// A clean EOF before any length byte returns `Ok(None)`. Any partial length or
/// payload is a terminal error. The length is checked before allocation.
///
/// # Errors
///
/// Returns a bounded framing, UTF-8, JSON-policy, allocation, or I/O error.
pub fn read_frame(reader: &mut impl Read) -> Result<Option<Value>, FrameError> {
    let mut length_bytes = [0_u8; 4];
    let first = reader
        .read(&mut length_bytes[..1])
        .map_err(|_| FrameError::Io)?;
    if first == 0 {
        return Ok(None);
    }
    read_exact_or_truncated(reader, &mut length_bytes[1..])?;

    let length_u32 = u32::from_ne_bytes(length_bytes);
    let length = usize::try_from(length_u32).map_err(|_| FrameError::Oversized)?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(FrameError::Oversized);
    }

    let mut payload = Vec::new();
    payload
        .try_reserve_exact(length)
        .map_err(|_| FrameError::Allocation)?;
    payload.resize(length, 0);
    read_exact_or_truncated(reader, &mut payload)?;

    let text = std::str::from_utf8(&payload).map_err(|_| FrameError::InvalidUtf8)?;
    parse_strict_json(text)
}

/// Write one Chrome Native Messaging frame and flush it immediately.
///
/// # Errors
///
/// Returns an error for a non-object/oversized value, serialization failure, or I/O failure.
pub fn write_frame(writer: &mut impl Write, value: &Value) -> Result<(), FrameError> {
    if !value.is_object() {
        return Err(FrameError::RootNotObject);
    }
    let payload = serde_json::to_vec(value).map_err(|_| FrameError::InvalidJson)?;
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(FrameError::Oversized);
    }
    let length = u32::try_from(payload.len()).map_err(|_| FrameError::Oversized)?;
    writer
        .write_all(&length.to_ne_bytes())
        .and_then(|()| writer.write_all(&payload))
        .and_then(|()| writer.flush())
        .map_err(|_| FrameError::Io)
}

/// Parse one strict JSON object with duplicate-key and structural-limit rejection.
///
/// # Errors
///
/// Returns an error for malformed UTF-8 text, duplicate keys, excessive depth,
/// aggregate node/container limits, trailing JSON, or a non-object root.
pub fn parse_strict_json(text: &str) -> Result<Option<Value>, FrameError> {
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let budget = ParseBudget::default();
    let value = StrictValueSeed {
        depth: 0,
        budget: &budget,
    }
    .deserialize(&mut deserializer)
    .map_err(|error| map_json_error(&error))?;
    deserializer.end().map_err(|_| FrameError::InvalidJson)?;
    if !value.is_object() {
        return Err(FrameError::RootNotObject);
    }
    Ok(Some(value))
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

fn map_json_error(error: &serde_json::Error) -> FrameError {
    let message = error.to_string();
    if message.starts_with("duplicate object member") {
        FrameError::DuplicateKey
    } else if message.starts_with("JSON nesting limit exceeded") {
        FrameError::ExcessiveDepth
    } else if message.starts_with("JSON node limit exceeded") {
        FrameError::ExcessiveNodes
    } else if message.starts_with("JSON container item limit exceeded") {
        FrameError::ExcessiveContainerItems
    } else {
        FrameError::InvalidJson
    }
}

#[derive(Debug, Default)]
struct ParseBudget {
    nodes: Cell<usize>,
    container_items: Cell<usize>,
}

impl ParseBudget {
    fn consume_node<E>(&self) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        let nodes = self
            .nodes
            .get()
            .checked_add(1)
            .ok_or_else(|| E::custom("JSON node limit exceeded"))?;
        if nodes > MAX_JSON_NODES {
            return Err(E::custom("JSON node limit exceeded"));
        }
        self.nodes.set(nodes);
        Ok(())
    }

    fn consume_container_item<E>(&self) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        let container_items = self
            .container_items
            .get()
            .checked_add(1)
            .ok_or_else(|| E::custom("JSON container item limit exceeded"))?;
        if container_items > MAX_JSON_CONTAINER_ITEMS {
            return Err(E::custom("JSON container item limit exceeded"));
        }
        self.container_items.set(container_items);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct StrictValueSeed<'budget> {
    depth: usize,
    budget: &'budget ParseBudget,
}

impl<'de> DeserializeSeed<'de> for StrictValueSeed<'_> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.budget.consume_node::<D::Error>()?;
        deserializer.deserialize_any(StrictValueVisitor {
            depth: self.depth,
            budget: self.budget,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct StrictValueVisitor<'budget> {
    depth: usize,
    budget: &'budget ParseBudget,
}

impl<'budget> StrictValueVisitor<'budget> {
    fn nested<E>(self) -> Result<StrictValueSeed<'budget>, E>
    where
        E: serde::de::Error,
    {
        let depth = self
            .depth
            .checked_add(1)
            .ok_or_else(|| E::custom("JSON nesting limit exceeded"))?;
        if depth > MAX_JSON_DEPTH {
            return Err(E::custom("JSON nesting limit exceeded"));
        }
        Ok(StrictValueSeed {
            depth,
            budget: self.budget,
        })
    }
}

impl<'de> Visitor<'de> for StrictValueVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON value without duplicate object members")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StrictValueSeed {
            depth: self.depth,
            budget: self.budget,
        }
        .deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let seed = self.nested::<A::Error>()?;
        let item_seed = ContainerItemSeed { value: seed };
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(item_seed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let seed = self.nested::<A::Error>()?;
        let mut keys = HashSet::new();
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            self.budget.consume_container_item::<A::Error>()?;
            self.budget.consume_node::<A::Error>()?;
            if !keys.insert(key.clone()) {
                return Err(A::Error::custom("duplicate object member"));
            }
            let value = object.next_value_seed(seed)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[derive(Clone, Copy, Debug)]
struct ContainerItemSeed<'budget> {
    value: StrictValueSeed<'budget>,
}

impl<'de> DeserializeSeed<'de> for ContainerItemSeed<'_> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.value.budget.consume_container_item::<D::Error>()?;
        self.value.deserialize(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use serde_json::json;

    use super::{
        FrameError, MAX_FRAME_BYTES, MAX_JSON_CONTAINER_ITEMS, MAX_JSON_DEPTH, MAX_JSON_NODES,
        parse_strict_json, read_frame, write_frame,
    };

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut frame = u32::try_from(payload.len())
            .map_or_else(|_| Vec::new(), |length| length.to_ne_bytes().to_vec());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn frame_error_formatting_never_repeats_io_details() {
        let error = FrameError::Io;
        assert_eq!(format!("{error:?}"), "FrameError::Io([REDACTED])");
        assert_eq!(error.to_string(), "native-messaging I/O failed");
        assert!(std::error::Error::source(&error).is_none());
    }

    #[test]
    fn round_trip_object_frame() -> Result<(), FrameError> {
        let value = json!({"message_type":"HealthCheck","sequence":1});
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &value)?;
        let decoded = read_frame(&mut Cursor::new(bytes))?.ok_or(FrameError::Truncated)?;
        assert_eq!(decoded, value);
        Ok(())
    }

    #[test]
    fn rejects_duplicate_keys() {
        let bytes = framed(br#"{"sequence":1,"sequence":2}"#);
        assert!(matches!(
            read_frame(&mut Cursor::new(bytes)),
            Err(FrameError::DuplicateKey)
        ));
    }

    #[test]
    fn rejects_non_object_root() {
        assert!(matches!(
            parse_strict_json("[]"),
            Err(FrameError::RootNotObject)
        ));
    }

    #[test]
    fn rejects_trailing_root() {
        assert!(matches!(
            parse_strict_json("{}{}"),
            Err(FrameError::InvalidJson)
        ));
    }

    #[test]
    fn rejects_oversize_before_payload_read() {
        let advertised = u32::try_from(MAX_FRAME_BYTES + 1)
            .unwrap_or(u32::MAX)
            .to_ne_bytes();
        assert!(matches!(
            read_frame(&mut Cursor::new(advertised)),
            Err(FrameError::Oversized)
        ));
    }

    #[test]
    fn rejects_partial_length_and_payload() {
        assert!(matches!(
            read_frame(&mut Cursor::new([1_u8, 0])),
            Err(FrameError::Truncated)
        ));
        assert!(matches!(
            read_frame(&mut Cursor::new(framed(b"{"))),
            Err(FrameError::InvalidJson)
        ));

        let mut partial = 5_u32.to_ne_bytes().to_vec();
        partial.extend_from_slice(b"{}");
        assert!(matches!(
            read_frame(&mut Cursor::new(partial)),
            Err(FrameError::Truncated)
        ));
    }

    #[test]
    fn rejects_excessive_depth() {
        let text = format!(
            "{{\"v\":{}}}",
            "[".repeat(MAX_JSON_DEPTH + 1) + &"]".repeat(MAX_JSON_DEPTH + 1)
        );
        assert!(matches!(
            parse_strict_json(&text),
            Err(FrameError::ExcessiveDepth)
        ));
    }

    #[test]
    fn rejects_excessive_aggregate_nodes() {
        let member_count = MAX_JSON_NODES / 2;
        let members = (0..member_count)
            .map(|index| format!("\"key{index}\":0"))
            .collect::<Vec<_>>()
            .join(",");
        let text = format!("{{{members}}}");
        assert!(matches!(
            parse_strict_json(&text),
            Err(FrameError::ExcessiveNodes)
        ));
    }

    #[test]
    fn rejects_excessive_aggregate_container_items() {
        let items = (0..=MAX_JSON_CONTAINER_ITEMS)
            .map(|_| "0")
            .collect::<Vec<_>>()
            .join(",");
        let text = format!("[{items}]");
        assert!(matches!(
            parse_strict_json(&text),
            Err(FrameError::ExcessiveContainerItems)
        ));
    }
}
