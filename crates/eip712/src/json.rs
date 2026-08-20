use core::fmt;
use std::collections::HashSet;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::{LimitKind, TypedDataError, schema::Limits};

const DUPLICATE_KEY_MARKER: &str = "wallet-eip712:duplicate-key";
const DEPTH_MARKER: &str = "wallet-eip712:limit-depth";
const VALUES_MARKER: &str = "wallet-eip712:limit-values";
const STRING_MARKER: &str = "wallet-eip712:limit-string";
const ARRAY_MARKER: &str = "wallet-eip712:limit-array";
const OBJECT_MARKER: &str = "wallet-eip712:limit-object";

pub(crate) fn parse_strict(source: &[u8], limits: Limits) -> Result<Value, TypedDataError> {
    let mut deserializer = serde_json::Deserializer::from_slice(source);
    let mut state = ParseState { limits, values: 0 };
    let value = StrictValueSeed {
        state: &mut state,
        depth: 1,
    }
    .deserialize(&mut deserializer)
    .map_err(|error| map_json_error(&error))?;
    deserializer.end().map_err(|error| map_json_error(&error))?;
    reject_noncanonical_number_tokens(source)?;
    Ok(value.0)
}

fn map_json_error(error: &serde_json::Error) -> TypedDataError {
    let message = error.to_string();
    if message.contains(DUPLICATE_KEY_MARKER) {
        TypedDataError::DuplicateJsonKey
    } else if message.contains(DEPTH_MARKER) {
        TypedDataError::LimitExceeded(LimitKind::Depth)
    } else if message.contains(VALUES_MARKER) {
        TypedDataError::LimitExceeded(LimitKind::Values)
    } else if message.contains(STRING_MARKER) {
        TypedDataError::LimitExceeded(LimitKind::StringBytes)
    } else if message.contains(ARRAY_MARKER) {
        TypedDataError::LimitExceeded(LimitKind::ArrayElements)
    } else if message.contains(OBJECT_MARKER) {
        TypedDataError::LimitExceeded(LimitKind::ObjectEntries)
    } else {
        TypedDataError::InvalidJson
    }
}

fn reject_noncanonical_number_tokens(source: &[u8]) -> Result<(), TypedDataError> {
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < source.len() {
        let byte = source[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index = index.saturating_add(1);
            continue;
        }
        if byte == b'"' {
            in_string = true;
            index = index.saturating_add(1);
            continue;
        }
        if byte != b'-' && !byte.is_ascii_digit() {
            index = index.saturating_add(1);
            continue;
        }

        let start = index;
        index = index.saturating_add(1);
        while index < source.len()
            && !matches!(
                source[index],
                b' ' | b'\t' | b'\r' | b'\n' | b',' | b']' | b'}'
            )
        {
            index = index.saturating_add(1);
        }
        let token = &source[start..index];
        if token == b"-0" || token.contains(&b'.') || token.contains(&b'e') || token.contains(&b'E')
        {
            return Err(TypedDataError::InvalidValue);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct ParseState {
    limits: Limits,
    values: usize,
}

struct StrictValue(Value);

struct StrictValueSeed<'a> {
    state: &'a mut ParseState,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictValueSeed<'_> {
    type Value = StrictValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.depth > self.state.limits.depth {
            return Err(de::Error::custom(DEPTH_MARKER));
        }
        self.state.values = self
            .state
            .values
            .checked_add(1)
            .ok_or_else(|| de::Error::custom(VALUES_MARKER))?;
        if self.state.values > self.state.limits.values {
            return Err(de::Error::custom(VALUES_MARKER));
        }
        deserializer.deserialize_any(StrictValueVisitor {
            state: self.state,
            depth: self.depth,
        })
    }
}

struct StrictValueVisitor<'a> {
    state: &'a mut ParseState,
    depth: usize,
}

impl<'de> Visitor<'de> for StrictValueVisitor<'_> {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() > self.state.limits.string_bytes {
            return Err(E::custom(STRING_MARKER));
        }
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() > self.state.limits.string_bytes {
            return Err(E::custom(STRING_MARKER));
        }
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictValueSeed {
            state: self.state,
            depth: self.depth.saturating_add(1),
        })? {
            if values.len() >= self.state.limits.array_elements {
                return Err(de::Error::custom(ARRAY_MARKER));
            }
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.len() >= self.state.limits.object_entries {
                return Err(de::Error::custom(OBJECT_MARKER));
            }
            if key.len() > self.state.limits.string_bytes {
                return Err(de::Error::custom(STRING_MARKER));
            }
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(DUPLICATE_KEY_MARKER));
            }
            let value = map.next_value_seed(StrictValueSeed {
                state: self.state,
                depth: self.depth.saturating_add(1),
            })?;
            values.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}
