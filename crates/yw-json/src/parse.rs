//! Strict RFC 8259 parser with the spec/05 §2.9 limits.

use core::fmt;
use std::collections::HashSet;

use crate::value::{Number, Object, Value};

/// Parser limits (spec/05 §2.9). The counting rules match the extension's `checkJson`:
///
/// - depth: a scalar is 0, a container is 1 + the deepest child; reject when depth > `max_depth`.
/// - nodes: every value (including the root) plus every object key.
/// - items: every array element plus every object member.
/// - bytes: the input length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_field_names,
    reason = "field names are fixed by spec/01 §2.3 and spec/05 §2.9"
)]
pub struct Limits {
    /// Maximum input length in bytes.
    pub max_bytes: usize,
    /// Maximum container nesting depth.
    pub max_depth: u32,
    /// Maximum number of values plus object keys.
    pub max_nodes: u32,
    /// Maximum number of array elements plus object members.
    pub max_items: u32,
}

impl Limits {
    /// Requests: page→content→background→native and frames received by yw-app.
    pub const REQUEST: Self = Self {
        max_bytes: 1_048_576,
        max_depth: 32,
        max_nodes: 8_192,
        max_items: 4_096,
    };
    /// Responses: results sent by yw-app and native→background→content.
    pub const RESPONSE: Self = Self {
        max_bytes: 1_048_576,
        max_depth: 32,
        max_nodes: 262_144,
        max_items: 262_144,
    };
}

/// Parse failure. `Display` never contains input content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Input longer than `Limits::max_bytes`.
    TooLarge,
    /// Input is not valid UTF-8.
    InvalidUtf8,
    /// Grammar violation at a byte offset.
    Syntax {
        /// Byte offset of the violation.
        offset: usize,
    },
    /// An object repeats a key; offset of the repeated key.
    DuplicateKey {
        /// Byte offset of the repeated key.
        offset: usize,
    },
    /// Nesting deeper than `Limits::max_depth`.
    TooDeep,
    /// More values plus keys than `Limits::max_nodes`.
    TooManyNodes,
    /// More elements plus members than `Limits::max_items`.
    TooManyItems,
    /// A `\u` escape encodes an unpaired surrogate.
    LoneSurrogate {
        /// Byte offset of the escape.
        offset: usize,
    },
    /// Non-whitespace data after the top-level value.
    TrailingData {
        /// Byte offset of the first trailing byte.
        offset: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => formatter.write_str("JSON input exceeds the size limit"),
            Self::InvalidUtf8 => formatter.write_str("JSON input is not valid UTF-8"),
            Self::Syntax { offset } => write!(formatter, "JSON syntax error at byte {offset}"),
            Self::DuplicateKey { offset } => {
                write!(formatter, "duplicate JSON key at byte {offset}")
            }
            Self::TooDeep => formatter.write_str("JSON nesting exceeds the depth limit"),
            Self::TooManyNodes => formatter.write_str("JSON value count exceeds the node limit"),
            Self::TooManyItems => formatter.write_str("JSON member count exceeds the item limit"),
            Self::LoneSurrogate { offset } => {
                write!(formatter, "unpaired surrogate escape at byte {offset}")
            }
            Self::TrailingData { offset } => {
                write!(formatter, "trailing JSON data at byte {offset}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// Parses exactly one JSON value from `bytes` under `limits`.
///
/// # Errors
///
/// Any [`ParseError`]; the input is rejected as a whole.
pub fn parse(bytes: &[u8], limits: &Limits) -> Result<Value, ParseError> {
    if bytes.len() > limits.max_bytes {
        return Err(ParseError::TooLarge);
    }
    if core::str::from_utf8(bytes).is_err() {
        return Err(ParseError::InvalidUtf8);
    }
    let mut parser = Parser {
        bytes,
        pos: 0,
        limits,
        nodes: 0,
        items: 0,
    };
    parser.skip_whitespace();
    let value = parser.value(0)?;
    parser.skip_whitespace();
    if parser.pos != bytes.len() {
        return Err(ParseError::TrailingData { offset: parser.pos });
    }
    Ok(value)
}

/// Scans one number token starting at `start`. Returns the end offset or the error offset.
pub(crate) fn scan_number(bytes: &[u8], start: usize) -> Result<usize, usize> {
    let at = |index: usize| bytes.get(index).copied();
    let digits_from = |mut index: usize| {
        while at(index).is_some_and(|byte| byte.is_ascii_digit()) {
            index = index.saturating_add(1);
        }
        index
    };
    let mut pos = start;
    if at(pos) == Some(b'-') {
        pos = pos.saturating_add(1);
    }
    match at(pos) {
        Some(b'0') => pos = pos.saturating_add(1),
        Some(b'1'..=b'9') => pos = digits_from(pos),
        _ => return Err(pos),
    }
    if at(pos) == Some(b'.') {
        let fraction = pos.saturating_add(1);
        let end = digits_from(fraction);
        if end == fraction {
            return Err(fraction);
        }
        pos = end;
    }
    if matches!(at(pos), Some(b'e' | b'E')) {
        let mut exponent = pos.saturating_add(1);
        if matches!(at(exponent), Some(b'+' | b'-')) {
            exponent = exponent.saturating_add(1);
        }
        let end = digits_from(exponent);
        if end == exponent {
            return Err(exponent);
        }
        pos = end;
    }
    Ok(pos)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    limits: &'a Limits,
    nodes: u32,
    items: u32,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    fn syntax(&self) -> ParseError {
        ParseError::Syntax { offset: self.pos }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }

    fn count_node(&mut self) -> Result<(), ParseError> {
        self.nodes = self.nodes.checked_add(1).ok_or(ParseError::TooManyNodes)?;
        if self.nodes > self.limits.max_nodes {
            return Err(ParseError::TooManyNodes);
        }
        Ok(())
    }

    fn count_item(&mut self) -> Result<(), ParseError> {
        self.items = self.items.checked_add(1).ok_or(ParseError::TooManyItems)?;
        if self.items > self.limits.max_items {
            return Err(ParseError::TooManyItems);
        }
        Ok(())
    }

    /// `depth` is the nesting level of the enclosing container (0 at the root).
    fn value(&mut self, depth: u32) -> Result<Value, ParseError> {
        self.count_node()?;
        match self.peek() {
            Some(b'{' | b'[') => {
                let level = depth.checked_add(1).ok_or(ParseError::TooDeep)?;
                if level > self.limits.max_depth {
                    return Err(ParseError::TooDeep);
                }
                if self.peek() == Some(b'{') {
                    self.object(level)
                } else {
                    self.array(level)
                }
            }
            Some(b'"') => self.string().map(Value::String),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.syntax()),
        }
    }

    fn literal(&mut self, token: &[u8], value: Value) -> Result<Value, ParseError> {
        let end = self.pos.saturating_add(token.len());
        if self.bytes.get(self.pos..end) != Some(token) {
            return Err(self.syntax());
        }
        self.pos = end;
        Ok(value)
    }

    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.pos;
        let end = scan_number(self.bytes, start).map_err(|offset| ParseError::Syntax { offset })?;
        let token = self.bytes.get(start..end).ok_or_else(|| self.syntax())?;
        let text = core::str::from_utf8(token).map_err(|_| ParseError::InvalidUtf8)?;
        self.pos = end;
        Ok(Value::Number(Number::from_validated(text.to_owned())))
    }

    fn array(&mut self, level: u32) -> Result<Value, ParseError> {
        self.bump();
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.bump();
            return Ok(Value::Array(items));
        }
        loop {
            self.count_item()?;
            self.skip_whitespace();
            items.push(self.value(level)?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.bump(),
                Some(b']') => {
                    self.bump();
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.syntax()),
            }
        }
    }

    fn object(&mut self, level: u32) -> Result<Value, ParseError> {
        self.bump();
        let mut members: Vec<(String, Value)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok(Value::Object(Object::from_members(members)));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.syntax());
            }
            let key_offset = self.pos;
            self.count_item()?;
            self.count_node()?;
            let key = self.string()?;
            if !seen.insert(key.clone()) {
                return Err(ParseError::DuplicateKey { offset: key_offset });
            }
            self.skip_whitespace();
            if self.peek() != Some(b':') {
                return Err(self.syntax());
            }
            self.bump();
            self.skip_whitespace();
            let value = self.value(level)?;
            members.push((key, value));
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.bump(),
                Some(b'}') => {
                    self.bump();
                    return Ok(Value::Object(Object::from_members(members)));
                }
                _ => return Err(self.syntax()),
            }
        }
    }

    fn hex4(&self, at: usize) -> Result<u32, ParseError> {
        let end = at.saturating_add(4);
        let digits = self
            .bytes
            .get(at..end)
            .ok_or(ParseError::Syntax { offset: at })?;
        digits.iter().try_fold(0_u32, |acc, &byte| {
            let nibble = char::from(byte)
                .to_digit(16)
                .ok_or(ParseError::Syntax { offset: at })?;
            Ok(acc.wrapping_shl(4) | nibble)
        })
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.bump();
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(self.syntax());
            };
            match byte {
                b'"' => {
                    self.bump();
                    return String::from_utf8(out).map_err(|_| ParseError::InvalidUtf8);
                }
                b'\\' => self.escape(&mut out)?,
                0x00..=0x1f => return Err(self.syntax()),
                _ => {
                    out.push(byte);
                    self.bump();
                }
            }
        }
    }

    fn escape(&mut self, out: &mut Vec<u8>) -> Result<(), ParseError> {
        let escape_offset = self.pos;
        self.bump();
        let Some(kind) = self.peek() else {
            return Err(self.syntax());
        };
        let simple = match kind {
            b'"' => Some(b'"'),
            b'\\' => Some(b'\\'),
            b'/' => Some(b'/'),
            b'b' => Some(0x08),
            b'f' => Some(0x0c),
            b'n' => Some(b'\n'),
            b'r' => Some(b'\r'),
            b't' => Some(b'\t'),
            b'u' => None,
            _ => return Err(self.syntax()),
        };
        if let Some(byte) = simple {
            out.push(byte);
            self.bump();
            return Ok(());
        }
        let first = self.hex4(self.pos.saturating_add(1))?;
        self.pos = self.pos.saturating_add(5);
        let scalar = match first {
            0xd800..=0xdbff => {
                let next = self.pos;
                if self.bytes.get(next..next.saturating_add(2)) != Some(b"\\u".as_slice()) {
                    return Err(ParseError::LoneSurrogate {
                        offset: escape_offset,
                    });
                }
                let second = self.hex4(next.saturating_add(2))?;
                if !(0xdc00..=0xdfff).contains(&second) {
                    return Err(ParseError::LoneSurrogate {
                        offset: escape_offset,
                    });
                }
                self.pos = next.saturating_add(6);
                let high = first.wrapping_sub(0xd800);
                let low = second.wrapping_sub(0xdc00);
                high.wrapping_shl(10)
                    .wrapping_add(low)
                    .wrapping_add(0x1_0000)
            }
            0xdc00..=0xdfff => {
                return Err(ParseError::LoneSurrogate {
                    offset: escape_offset,
                });
            }
            other => other,
        };
        let character = char::from_u32(scalar).ok_or(ParseError::LoneSurrogate {
            offset: escape_offset,
        })?;
        let mut buffer = [0_u8; 4];
        out.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
        Ok(())
    }
}
