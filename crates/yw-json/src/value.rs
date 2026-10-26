//! JSON value model (spec/01 §2.3).

use crate::parse::{ParseError, scan_number};

/// A parsed JSON value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number, kept as its validated source token.
    Number(Number),
    /// A string (escapes resolved, always valid UTF-8 without lone surrogates).
    String(String),
    /// An array in source order.
    Array(Vec<Value>),
    /// An object in source order with unique keys.
    Object(Object),
}

impl Value {
    /// Returns the string if this is a JSON string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(text) => Some(text),
            _ => None,
        }
    }

    /// Returns the elements if this is a JSON array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Returns the object if this is a JSON object.
    #[must_use]
    pub const fn as_object(&self) -> Option<&Object> {
        match self {
            Self::Object(object) => Some(object),
            _ => None,
        }
    }

    /// Returns the boolean if this is `true` or `false`.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// Returns the number if this is a JSON number.
    #[must_use]
    pub const fn as_number(&self) -> Option<&Number> {
        match self {
            Self::Number(number) => Some(number),
            _ => None,
        }
    }

    /// Whether this is `null`.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

/// A JSON number kept as its grammar-validated source token. There is no `f64` conversion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Number(String);

impl Number {
    pub(crate) const fn from_validated(token: String) -> Self {
        Self(token)
    }

    /// The decimal token of `value`.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        Self(value.to_string())
    }

    /// Validates `text` against the RFC 8259 number grammar and keeps it verbatim.
    ///
    /// # Errors
    ///
    /// [`ParseError::Syntax`] if `text` is not exactly one JSON number.
    pub fn from_literal(text: &str) -> Result<Self, ParseError> {
        let bytes = text.as_bytes();
        match scan_number(bytes, 0) {
            Ok(end) if end == bytes.len() => Ok(Self(text.to_owned())),
            Ok(end) => Err(ParseError::Syntax { offset: end }),
            Err(offset) => Err(ParseError::Syntax { offset }),
        }
    }

    /// The value as `u64` when the token is digits only (no sign, `.` or exponent).
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        digits_only(&self.0)
            .then(|| self.0.parse::<u64>().ok())
            .flatten()
    }

    /// Like [`Number::as_u64`] but also accepts `<digits>.0` (spec/05 §6.1 envelope integers).
    #[must_use]
    pub fn as_u64_allow_dot_zero(&self) -> Option<u64> {
        match self.0.strip_suffix(".0") {
            Some(integer) if digits_only(integer) => integer.parse::<u64>().ok(),
            Some(_) => None,
            None => self.as_u64(),
        }
    }

    /// The value as `i64` when the token is an optional `-` followed by digits only.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        let magnitude = self.0.strip_prefix('-').unwrap_or(&self.0);
        digits_only(magnitude)
            .then(|| self.0.parse::<i64>().ok())
            .flatten()
    }

    /// Whether the token has neither a fraction nor an exponent.
    #[must_use]
    pub fn is_integer(&self) -> bool {
        !self
            .0
            .bytes()
            .any(|byte| matches!(byte, b'.' | b'e' | b'E'))
    }

    /// Whether the token is a negative zero such as `-0`, `-0.0` or `-0e5`.
    #[must_use]
    pub fn is_negative_zero(&self) -> bool {
        let Some(magnitude) = self.0.strip_prefix('-') else {
            return false;
        };
        let mantissa = magnitude.split(['e', 'E']).next().unwrap_or("");
        mantissa
            .bytes()
            .filter(u8::is_ascii_digit)
            .all(|digit| digit == b'0')
    }

    /// The validated source token, for decimal amount parsing.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn digits_only(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// A JSON object: members in source order, keys unique.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Object(Vec<(String, Value)>);

impl Object {
    pub(crate) const fn from_members(members: Vec<(String, Value)>) -> Self {
        Self(members)
    }

    /// Builds an object from members in the given order (the writer keeps this order).
    /// Returns `None` if a key repeats, so every `Object` keeps unique keys.
    #[must_use]
    pub fn from_pairs(members: Vec<(String, Value)>) -> Option<Self> {
        for (index, (key, _)) in members.iter().enumerate() {
            if members
                .iter()
                .skip(index.checked_add(1)?)
                .any(|(other, _)| other == key)
            {
                return None;
            }
        }
        Some(Self(members))
    }

    /// Looks up a member by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0
            .iter()
            .find_map(|(name, value)| (name == key).then_some(value))
    }

    /// Keys in source order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|(name, _)| name.as_str())
    }

    /// Members in source order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.0.iter().map(|(name, value)| (name.as_str(), value))
    }

    /// Number of members.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the object has no members.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
