//! EIP-712 schema parsing and hashing on `yw_json::Value`.
//!
//! Port of `archive/spec-v2.4:crates/eip712/src/schema.rs:100-233,426-543,606-1023`; the hash
//! core (encodeType, typeHash, hashStruct, arrays, string/bytes) is unchanged. Hashing also
//! builds the display value tree in the same traversal so every displayed value was validated.

use std::collections::{BTreeMap, BTreeSet};

use sha3::{Digest, Keccak256};
use yw_json::{Number, Object, Value};

use super::{LimitKind, TdDomain, TypedDataError};
use crate::evm::address::{Address, parse_address};
use crate::evm::amount::U256;

pub(super) const DOMAIN_TYPE: &str = "EIP712Domain";
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const ENVELOPE_KEYS: [&str; 4] = ["domain", "message", "primaryType", "types"];
const MAX_DEPTH: usize = 32;
const MAX_VALUES: usize = 16_384;
const MAX_STRING_BYTES: usize = 131_072;
const MAX_ARRAY_ELEMENTS: usize = 4_096;
const MAX_OBJECT_ENTRIES: usize = 4_096;
const MAX_TYPES: usize = 256;
const MAX_FIELDS: usize = 256;
const MAX_ARRAY_DIMENSIONS: usize = 8;

/// A typed-data value tree node (display).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TdNode {
    /// A struct with its fields in declaration order.
    Struct {
        /// Struct type name.
        type_name: String,
        /// Fields.
        fields: Vec<(String, TdNode)>,
    },
    /// An array.
    Array(Vec<TdNode>),
    /// A leaf.
    Value(TdValue),
}

/// A typed-data leaf value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TdValue {
    /// `address`.
    Address(Address),
    /// `uintN`.
    Uint(U256),
    /// `intN` as sign and magnitude.
    Int {
        /// Negative.
        negative: bool,
        /// Magnitude.
        magnitude: U256,
    },
    /// `bool`.
    Bool(bool),
    /// `bytes` / `bytesN`.
    Bytes(Vec<u8>),
    /// `string`.
    String(String),
}

impl TdNode {
    /// A struct field by name.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&Self> {
        match self {
            Self::Struct { fields, .. } => fields
                .iter()
                .find_map(|(field, node)| (field == name).then_some(node)),
            _ => None,
        }
    }

    /// The leaf value.
    #[must_use]
    pub const fn value(&self) -> Option<&TdValue> {
        match self {
            Self::Value(value) => Some(value),
            _ => None,
        }
    }

    /// The array elements.
    #[must_use]
    pub fn elements(&self) -> Option<&[Self]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The address leaf.
    #[must_use]
    pub fn address(&self) -> Option<Address> {
        match self.value()? {
            TdValue::Address(address) => Some(*address),
            _ => None,
        }
    }

    /// The unsigned integer leaf.
    #[must_use]
    pub fn uint(&self) -> Option<U256> {
        match self.value()? {
            TdValue::Uint(value) => Some(*value),
            _ => None,
        }
    }

    /// The boolean leaf.
    #[must_use]
    pub fn boolean(&self) -> Option<bool> {
        match self.value()? {
            TdValue::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// The string leaf.
    #[must_use]
    pub fn string(&self) -> Option<&str> {
        match self.value()? {
            TdValue::String(value) => Some(value),
            _ => None,
        }
    }

    /// The bytes leaf.
    #[must_use]
    pub fn bytes(&self) -> Option<&[u8]> {
        match self.value()? {
            TdValue::Bytes(value) => Some(value),
            _ => None,
        }
    }
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

/// Enforces the archive `Limits::default` on the parsed value (depth, value count, string bytes,
/// array elements, object entries).
pub(super) fn check_value_limits(value: &Value) -> Result<(), TypedDataError> {
    let mut count = 0_usize;
    walk_limits(value, 0, &mut count)
}

fn walk_limits(value: &Value, depth: usize, count: &mut usize) -> Result<(), TypedDataError> {
    *count = count.saturating_add(1);
    if *count > MAX_VALUES {
        return Err(TypedDataError::LimitExceeded(LimitKind::Values));
    }
    match value {
        Value::String(text) if text.len() > MAX_STRING_BYTES => {
            Err(TypedDataError::LimitExceeded(LimitKind::StringBytes))
        }
        Value::Array(items) => {
            if depth >= MAX_DEPTH {
                return Err(TypedDataError::LimitExceeded(LimitKind::Depth));
            }
            if items.len() > MAX_ARRAY_ELEMENTS {
                return Err(TypedDataError::LimitExceeded(LimitKind::ArrayElements));
            }
            for item in items {
                walk_limits(item, depth.saturating_add(1), count)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            if depth >= MAX_DEPTH {
                return Err(TypedDataError::LimitExceeded(LimitKind::Depth));
            }
            if object.len() > MAX_OBJECT_ENTRIES {
                return Err(TypedDataError::LimitExceeded(LimitKind::ObjectEntries));
            }
            for (key, item) in object.iter() {
                if key.len() > MAX_STRING_BYTES {
                    return Err(TypedDataError::LimitExceeded(LimitKind::StringBytes));
                }
                walk_limits(item, depth.saturating_add(1), count)?;
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(()),
    }
}

pub(super) struct Envelope<'a> {
    pub types: &'a Object,
    pub primary_type: &'a str,
    pub domain: &'a Object,
    pub message: &'a Object,
}

fn require_exact_keys(
    object: &Object,
    expected: &[&str],
    error: TypedDataError,
) -> Result<(), TypedDataError> {
    if object.len() != expected.len() || !expected.iter().all(|key| object.get(key).is_some()) {
        return Err(error);
    }
    Ok(())
}

impl<'a> Envelope<'a> {
    pub(super) fn parse(document: &'a Value) -> Result<Self, TypedDataError> {
        let object = document
            .as_object()
            .ok_or(TypedDataError::InvalidEnvelope)?;
        require_exact_keys(object, &ENVELOPE_KEYS, TypedDataError::InvalidEnvelope)?;
        let get_object = |key: &str| {
            object
                .get(key)
                .and_then(Value::as_object)
                .ok_or(TypedDataError::InvalidEnvelope)
        };
        let primary_type = object
            .get("primaryType")
            .and_then(Value::as_str)
            .ok_or(TypedDataError::InvalidEnvelope)?;
        if primary_type == DOMAIN_TYPE || !is_identifier(primary_type) {
            return Err(TypedDataError::InvalidEnvelope);
        }
        Ok(Self {
            types: get_object("types")?,
            primary_type,
            domain: get_object("domain")?,
            message: get_object("message")?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum BaseType {
    Address,
    Bool,
    String,
    Bytes,
    BytesN(usize),
    Int(u16),
    Uint(u16),
    Struct(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArrayDimension {
    Dynamic,
    Fixed(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SolidityType {
    base: BaseType,
    arrays: Vec<ArrayDimension>,
    canonical: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FieldDefinition {
    name: String,
    field_type: SolidityType,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StructDefinition {
    name: String,
    fields: Vec<FieldDefinition>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VisitState {
    Visiting,
    Complete,
}

fn is_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn parse_canonical_width(source: &str) -> Result<usize, TypedDataError> {
    if source.is_empty()
        || source.starts_with('0')
        || !source.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(TypedDataError::InvalidTypeDefinition);
    }
    source
        .parse::<usize>()
        .map_err(|_| TypedDataError::InvalidTypeDefinition)
}

fn parse_integer_width(source: &str) -> Result<u16, TypedDataError> {
    let width = parse_canonical_width(source)?;
    if !(8..=256).contains(&width) || width % 8 != 0 {
        return Err(TypedDataError::InvalidTypeDefinition);
    }
    u16::try_from(width).map_err(|_| TypedDataError::InvalidTypeDefinition)
}

impl BaseType {
    fn parse(source: &str) -> Result<Self, TypedDataError> {
        match source {
            "address" => Ok(Self::Address),
            "bool" => Ok(Self::Bool),
            "string" => Ok(Self::String),
            "bytes" => Ok(Self::Bytes),
            _ => {
                if let Some(width) = source.strip_prefix("bytes") {
                    let width = parse_canonical_width(width)?;
                    if (1..=32).contains(&width) {
                        return Ok(Self::BytesN(width));
                    }
                    return Err(TypedDataError::InvalidTypeDefinition);
                }
                if let Some(bits) = source.strip_prefix("uint") {
                    return parse_integer_width(bits).map(Self::Uint);
                }
                if let Some(bits) = source.strip_prefix("int") {
                    return parse_integer_width(bits).map(Self::Int);
                }
                if is_identifier(source) {
                    Ok(Self::Struct(source.to_owned()))
                } else {
                    Err(TypedDataError::InvalidTypeDefinition)
                }
            }
        }
    }
}

fn is_primitive_name(name: &str) -> bool {
    BaseType::parse(name).is_ok_and(|base| !matches!(base, BaseType::Struct(_)))
}

impl SolidityType {
    fn parse(source: &str) -> Result<Self, TypedDataError> {
        let array_start = source.find('[').unwrap_or(source.len());
        let (base_source, mut suffix) = source.split_at(array_start);
        let base = BaseType::parse(base_source)?;
        let mut arrays = Vec::new();
        while !suffix.is_empty() {
            if arrays.len() >= MAX_ARRAY_DIMENSIONS {
                return Err(TypedDataError::LimitExceeded(LimitKind::ArrayDimensions));
            }
            let inner_start = suffix
                .strip_prefix('[')
                .ok_or(TypedDataError::InvalidTypeDefinition)?;
            let (length, rest) = inner_start
                .split_once(']')
                .ok_or(TypedDataError::InvalidTypeDefinition)?;
            let dimension = if length.is_empty() {
                ArrayDimension::Dynamic
            } else {
                if length.starts_with('0') || !length.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(TypedDataError::InvalidTypeDefinition);
                }
                let parsed = length
                    .parse::<usize>()
                    .map_err(|_| TypedDataError::InvalidTypeDefinition)?;
                if parsed == 0 || parsed > MAX_ARRAY_ELEMENTS {
                    return Err(TypedDataError::LimitExceeded(LimitKind::ArrayElements));
                }
                ArrayDimension::Fixed(parsed)
            };
            arrays.push(dimension);
            suffix = rest;
        }
        Ok(Self {
            base,
            arrays,
            canonical: source.to_owned(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Schema {
    definitions: BTreeMap<String, StructDefinition>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ParsedInteger {
    negative: bool,
    magnitude: U256,
}

impl Schema {
    pub(super) fn parse(definitions: &Object) -> Result<Self, TypedDataError> {
        if definitions.is_empty() || definitions.len() > MAX_TYPES {
            return Err(TypedDataError::LimitExceeded(LimitKind::Types));
        }
        let mut parsed = BTreeMap::new();
        for (name, value) in definitions.iter() {
            if !is_identifier(name) || is_primitive_name(name) {
                return Err(TypedDataError::InvalidTypeDefinition);
            }
            let fields = value
                .as_array()
                .ok_or(TypedDataError::InvalidTypeDefinition)?;
            if fields.len() > MAX_FIELDS {
                return Err(TypedDataError::LimitExceeded(LimitKind::Fields));
            }
            let mut parsed_fields = Vec::with_capacity(fields.len());
            let mut field_names = BTreeSet::new();
            for field in fields {
                let object = field
                    .as_object()
                    .ok_or(TypedDataError::InvalidTypeDefinition)?;
                require_exact_keys(
                    object,
                    &["name", "type"],
                    TypedDataError::InvalidTypeDefinition,
                )?;
                let field_name = object
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or(TypedDataError::InvalidTypeDefinition)?;
                let field_type = object
                    .get("type")
                    .and_then(Value::as_str)
                    .ok_or(TypedDataError::InvalidTypeDefinition)?;
                if !is_identifier(field_name) {
                    return Err(TypedDataError::InvalidTypeDefinition);
                }
                if !field_names.insert(field_name.to_owned()) {
                    return Err(TypedDataError::DuplicateField);
                }
                parsed_fields.push(FieldDefinition {
                    name: field_name.to_owned(),
                    field_type: SolidityType::parse(field_type)?,
                });
            }
            parsed.insert(
                name.to_owned(),
                StructDefinition {
                    name: name.to_owned(),
                    fields: parsed_fields,
                },
            );
        }
        if !parsed.contains_key(DOMAIN_TYPE) {
            return Err(TypedDataError::UndefinedType);
        }
        Ok(Self {
            definitions: parsed,
        })
    }

    /// Every referenced struct is declared and the graph is acyclic. Unreachable types are
    /// allowed (v3 change #4) and never used for hashing or display.
    pub(super) fn validate_graph(&self, primary_type: &str) -> Result<(), TypedDataError> {
        if !self.definitions.contains_key(primary_type) {
            return Err(TypedDataError::UndefinedType);
        }
        for definition in self.definitions.values() {
            for field in &definition.fields {
                if let BaseType::Struct(name) = &field.field_type.base
                    && !self.definitions.contains_key(name)
                {
                    return Err(TypedDataError::UndefinedType);
                }
            }
        }
        let mut states = BTreeMap::new();
        for name in self.definitions.keys() {
            self.visit_acyclic(name, &mut states)?;
        }
        Ok(())
    }

    fn definition(&self, name: &str) -> Result<&StructDefinition, TypedDataError> {
        self.definitions
            .get(name)
            .ok_or(TypedDataError::UndefinedType)
    }

    fn visit_acyclic(
        &self,
        name: &str,
        states: &mut BTreeMap<String, VisitState>,
    ) -> Result<(), TypedDataError> {
        match states.get(name) {
            Some(VisitState::Visiting) => return Err(TypedDataError::CyclicType),
            Some(VisitState::Complete) => return Ok(()),
            None => {}
        }
        states.insert(name.to_owned(), VisitState::Visiting);
        for field in &self.definition(name)?.fields {
            if let BaseType::Struct(dependency) = &field.field_type.base {
                self.visit_acyclic(dependency, states)?;
            }
        }
        states.insert(name.to_owned(), VisitState::Complete);
        Ok(())
    }

    fn collect_reachable(
        &self,
        name: &str,
        reachable: &mut BTreeSet<String>,
    ) -> Result<(), TypedDataError> {
        if !reachable.insert(name.to_owned()) {
            return Ok(());
        }
        for field in &self.definition(name)?.fields {
            if let BaseType::Struct(dependency) = &field.field_type.base {
                self.collect_reachable(dependency, reachable)?;
            }
        }
        Ok(())
    }

    fn encode_declaration(&self, name: &str) -> Result<String, TypedDataError> {
        let definition = self.definition(name)?;
        let mut encoded = String::new();
        encoded.push_str(&definition.name);
        encoded.push('(');
        for (index, field) in definition.fields.iter().enumerate() {
            if index != 0 {
                encoded.push(',');
            }
            encoded.push_str(&field.field_type.canonical);
            encoded.push(' ');
            encoded.push_str(&field.name);
        }
        encoded.push(')');
        Ok(encoded)
    }

    /// `encodeType(name)`: the primary declaration followed by its dependencies sorted by name.
    pub(super) fn encode_type(&self, primary_type: &str) -> Result<String, TypedDataError> {
        let mut dependencies = BTreeSet::new();
        self.collect_reachable(primary_type, &mut dependencies)?;
        dependencies.remove(primary_type);
        let mut encoded = self.encode_declaration(primary_type)?;
        for dependency in dependencies {
            encoded.push_str(&self.encode_declaration(&dependency)?);
        }
        Ok(encoded)
    }

    pub(super) fn type_hash(&self, name: &str) -> Result<[u8; 32], TypedDataError> {
        Ok(keccak(self.encode_type(name)?.as_bytes()))
    }

    /// `hashStruct(name, value)` and the display tree of `value`.
    pub(super) fn hash_struct_tree(
        &self,
        name: &str,
        value: &Object,
        depth: usize,
    ) -> Result<([u8; 32], TdNode), TypedDataError> {
        if depth > MAX_DEPTH {
            return Err(TypedDataError::LimitExceeded(LimitKind::Depth));
        }
        let definition = self.definition(name)?;
        validate_struct_shape(definition, value)?;
        let mut encoded =
            Vec::with_capacity(definition.fields.len().saturating_add(1).saturating_mul(32));
        encoded.extend_from_slice(&self.type_hash(name)?);
        let mut fields = Vec::with_capacity(definition.fields.len());
        for field in &definition.fields {
            let field_value = value.get(&field.name).ok_or(TypedDataError::MissingValue)?;
            let (word, node) = self.encode_type_parts(
                &field.field_type.base,
                &field.field_type.arrays,
                field_value,
                depth.saturating_add(1),
            )?;
            encoded.extend_from_slice(&word);
            fields.push((field.name.clone(), node));
        }
        Ok((
            keccak(&encoded),
            TdNode::Struct {
                type_name: name.to_owned(),
                fields,
            },
        ))
    }

    fn encode_type_parts(
        &self,
        base: &BaseType,
        arrays: &[ArrayDimension],
        value: &Value,
        depth: usize,
    ) -> Result<([u8; 32], TdNode), TypedDataError> {
        if let Some((outer, inner)) = arrays.split_last() {
            let values = value.as_array().ok_or(TypedDataError::InvalidValue)?;
            if let ArrayDimension::Fixed(expected) = outer
                && values.len() != *expected
            {
                return Err(TypedDataError::InvalidValue);
            }
            let mut encoded = Vec::with_capacity(values.len().saturating_mul(32));
            let mut nodes = Vec::with_capacity(values.len());
            for element in values {
                let (word, node) =
                    self.encode_type_parts(base, inner, element, depth.saturating_add(1))?;
                encoded.extend_from_slice(&word);
                nodes.push(node);
            }
            return Ok((keccak(&encoded), TdNode::Array(nodes)));
        }
        let leaf = |word: [u8; 32], value: TdValue| Ok((word, TdNode::Value(value)));
        match base {
            BaseType::Address => {
                let address = parse_address_value(value)?;
                let mut word = [0_u8; 32];
                if let Some(low) = word.get_mut(12..) {
                    low.copy_from_slice(address.as_bytes());
                }
                leaf(word, TdValue::Address(address))
            }
            BaseType::Bool => {
                let flag = value.as_bool().ok_or(TypedDataError::InvalidValue)?;
                leaf(
                    U256::from_u64(u64::from(flag)).to_be_bytes(),
                    TdValue::Bool(flag),
                )
            }
            BaseType::String => {
                let text = value.as_str().ok_or(TypedDataError::InvalidValue)?;
                leaf(keccak(text.as_bytes()), TdValue::String(text.to_owned()))
            }
            BaseType::Bytes => {
                let bytes = decode_hex_bytes(value.as_str().ok_or(TypedDataError::InvalidValue)?)?;
                leaf(keccak(&bytes), TdValue::Bytes(bytes))
            }
            BaseType::BytesN(width) => {
                let bytes = decode_hex_bytes(value.as_str().ok_or(TypedDataError::InvalidValue)?)?;
                if bytes.len() != *width {
                    return Err(TypedDataError::InvalidValue);
                }
                let mut word = [0_u8; 32];
                word.get_mut(..*width)
                    .ok_or(TypedDataError::InvalidValue)?
                    .copy_from_slice(&bytes);
                leaf(word, TdValue::Bytes(bytes))
            }
            BaseType::Int(bits) => {
                let parsed = parse_integer_value(value, true)?;
                let word = encode_signed(parsed, *bits)?;
                leaf(
                    word,
                    TdValue::Int {
                        negative: parsed.negative,
                        magnitude: parsed.magnitude,
                    },
                )
            }
            BaseType::Uint(bits) => {
                let parsed = parse_integer_value(value, false)?;
                if parsed.negative || !parsed.magnitude.fits_bits(*bits) {
                    return Err(TypedDataError::InvalidValue);
                }
                leaf(
                    parsed.magnitude.to_be_bytes(),
                    TdValue::Uint(parsed.magnitude),
                )
            }
            BaseType::Struct(name) => {
                let object = value.as_object().ok_or(TypedDataError::InvalidValue)?;
                self.hash_struct_tree(name, object, depth)
            }
        }
    }

    /// Standard domain fields and the chain binding (T01 on mismatch).
    pub(super) fn domain(
        &self,
        domain: &Object,
        tree: TdNode,
        expected_chain_id: u64,
    ) -> Result<TdDomain, TypedDataError> {
        let definition = self.definition(DOMAIN_TYPE)?;
        let field_type = |name: &str| {
            definition
                .fields
                .iter()
                .find(|field| field.name == name)
                .map(|field| &field.field_type)
        };
        let chain_id = match field_type("chainId") {
            Some(kind) if kind.base == BaseType::Uint(256) && kind.arrays.is_empty() => {
                let value = domain.get("chainId").ok_or(TypedDataError::MissingValue)?;
                let parsed = parse_integer_value(value, false)?;
                if parsed.negative || parsed.magnitude != U256::from_u64(expected_chain_id) {
                    return Err(TypedDataError::ChainIdMismatch);
                }
                Some(parsed.magnitude)
            }
            Some(_) => return Err(TypedDataError::InvalidDomainBindingType),
            None => None,
        };
        let verifying_contract = match field_type("verifyingContract") {
            Some(kind) if kind.base == BaseType::Address && kind.arrays.is_empty() => {
                let value = domain
                    .get("verifyingContract")
                    .ok_or(TypedDataError::MissingValue)?;
                let address = parse_address_value(value)?;
                (address != Address::from_bytes([0; 20])).then_some(address)
            }
            Some(_) => return Err(TypedDataError::InvalidDomainBindingType),
            None => None,
        };
        let name = tree
            .field("name")
            .and_then(TdNode::string)
            .map(str::to_owned);
        let version = tree
            .field("version")
            .and_then(TdNode::string)
            .map(str::to_owned);
        let salt = tree
            .field("salt")
            .and_then(TdNode::bytes)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());
        Ok(TdDomain {
            name,
            version,
            chain_id,
            verifying_contract,
            salt,
            tree,
        })
    }

    /// The witness struct type of a Permit2 witness schema (spec/03 §8.2 W), `None` if the
    /// structure does not match.
    pub(super) fn witness_type(
        &self,
        primary: &str,
        batch: bool,
    ) -> Result<Option<String>, TypedDataError> {
        let definition = self.definition(primary)?;
        let [permitted, spender, nonce, deadline, witness] = definition.fields.as_slice() else {
            return Ok(None);
        };
        let permitted_type = if batch {
            "TokenPermissions[]"
        } else {
            "TokenPermissions"
        };
        let shape_ok = permitted.name == "permitted"
            && permitted.field_type.canonical == permitted_type
            && spender.name == "spender"
            && spender.field_type.canonical == "address"
            && nonce.name == "nonce"
            && nonce.field_type.canonical == "uint256"
            && deadline.name == "deadline"
            && deadline.field_type.canonical == "uint256"
            && witness.field_type.arrays.is_empty();
        let BaseType::Struct(witness_type) = &witness.field_type.base else {
            return Ok(None);
        };
        let token_permissions_ok = self.definitions.contains_key("TokenPermissions")
            && self.encode_declaration("TokenPermissions")?
                == "TokenPermissions(address token,uint256 amount)";
        Ok(
            (shape_ok && token_permissions_ok && witness_type != "TokenPermissions")
                .then(|| witness_type.clone()),
        )
    }
}

fn validate_struct_shape(
    definition: &StructDefinition,
    value: &Object,
) -> Result<(), TypedDataError> {
    for field in &definition.fields {
        if value.get(&field.name).is_none() {
            return Err(TypedDataError::MissingValue);
        }
    }
    if value
        .keys()
        .any(|key| !definition.fields.iter().any(|field| field.name == key))
    {
        return Err(TypedDataError::ExtraValue);
    }
    Ok(())
}

fn parse_address_value(value: &Value) -> Result<Address, TypedDataError> {
    let text = value.as_str().ok_or(TypedDataError::InvalidValue)?;
    parse_address(text).map_err(|_| TypedDataError::InvalidValue)
}

fn decode_hex_bytes(value: &str) -> Result<Vec<u8>, TypedDataError> {
    let digits = value
        .strip_prefix("0x")
        .ok_or(TypedDataError::InvalidValue)?;
    if digits.len() % 2 != 0 {
        return Err(TypedDataError::InvalidValue);
    }
    let mut bytes = vec![0_u8; digits.len() / 2];
    crate::hex::decode_into(digits.as_bytes(), &mut bytes, true)
        .map_err(|_| TypedDataError::InvalidValue)?;
    Ok(bytes)
}

fn parse_integer_value(value: &Value, signed: bool) -> Result<ParsedInteger, TypedDataError> {
    match value {
        Value::String(text) => parse_integer_text(text, signed),
        Value::Number(number) => parse_integer_number(number, signed),
        _ => Err(TypedDataError::InvalidValue),
    }
}

fn parse_integer_number(number: &Number, signed: bool) -> Result<ParsedInteger, TypedDataError> {
    if number.is_negative_zero() {
        return Err(TypedDataError::InvalidValue);
    }
    if let Some(value) = number.as_u64() {
        if value > MAX_SAFE_JSON_INTEGER {
            return Err(TypedDataError::InvalidValue);
        }
        return Ok(ParsedInteger {
            negative: false,
            magnitude: U256::from_u64(value),
        });
    }
    if signed && let Some(value) = number.as_i64() {
        let magnitude = value.unsigned_abs();
        if magnitude > MAX_SAFE_JSON_INTEGER {
            return Err(TypedDataError::InvalidValue);
        }
        return Ok(ParsedInteger {
            negative: value.is_negative(),
            magnitude: U256::from_u64(magnitude),
        });
    }
    Err(TypedDataError::InvalidValue)
}

fn parse_integer_text(text: &str, signed: bool) -> Result<ParsedInteger, TypedDataError> {
    if let Some(hex) = text.strip_prefix("0x") {
        // v3: leading zeros and uppercase digits are allowed when the value is in range.
        if hex.is_empty() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(TypedDataError::InvalidValue);
        }
        let trimmed = hex.trim_start_matches('0');
        let digits = if trimmed.is_empty() { "0" } else { trimmed };
        let magnitude = U256::parse_quantity_lenient(&format!("0x{digits}"))
            .map_err(|_| TypedDataError::InvalidValue)?;
        return Ok(ParsedInteger {
            negative: false,
            magnitude,
        });
    }
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) if signed => (true, rest),
        Some(_) => return Err(TypedDataError::InvalidValue),
        None => (false, text),
    };
    if negative && digits == "0" {
        return Err(TypedDataError::InvalidValue);
    }
    let magnitude = U256::from_decimal_str(digits).map_err(|_| TypedDataError::InvalidValue)?;
    Ok(ParsedInteger {
        negative,
        magnitude,
    })
}

fn encode_signed(value: ParsedInteger, bits: u16) -> Result<[u8; 32], TypedDataError> {
    // |value| must fit: positive < 2^(bits-1), negative ≤ 2^(bits-1).
    let limit = power_of_two(bits.saturating_sub(1)).ok_or(TypedDataError::InvalidValue)?;
    let fits = if value.negative {
        value.magnitude <= limit
    } else {
        value.magnitude < limit
    };
    if !fits {
        return Err(TypedDataError::InvalidValue);
    }
    if !value.negative {
        return Ok(value.magnitude.to_be_bytes());
    }
    // Two's complement in 256 bits: !(m) + 1 = 2^256 − m.
    let inverted = value.magnitude.to_be_bytes().map(|byte| !byte);
    U256::from_be_bytes(inverted)
        .checked_add(U256::ONE)
        .map(U256::to_be_bytes)
        .ok_or(TypedDataError::InvalidValue)
}

fn power_of_two(exponent: u16) -> Option<U256> {
    if exponent >= 256 {
        return None;
    }
    let mut bytes = [0_u8; 32];
    let byte_index = 31_usize.checked_sub(usize::from(exponent / 8))?;
    *bytes.get_mut(byte_index)? = 1_u8.checked_shl(u32::from(exponent % 8))?;
    Some(U256::from_be_bytes(bytes))
}
