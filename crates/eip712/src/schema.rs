use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Number, Value};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use wallet_model::{Address20, Hash32, U256, UntrustedTypedDataV4};

use crate::{LimitKind, TypedDataError, json::parse_strict};

const DOMAIN_TYPE: &str = "EIP712Domain";
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const ENVELOPE_KEYS: [&str; 4] = ["domain", "message", "primaryType", "types"];

/// Resource ceilings applied before schema traversal and hashing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Limits {
    /// Maximum UTF-8 bytes in the exact source document.
    pub source_bytes: usize,
    /// Maximum nesting depth across objects and arrays.
    pub depth: usize,
    /// Maximum total JSON values visited.
    pub values: usize,
    /// Maximum UTF-8 bytes in one object key or string value.
    pub string_bytes: usize,
    /// Maximum elements in one JSON array.
    pub array_elements: usize,
    /// Maximum entries in one JSON object.
    pub object_entries: usize,
    /// Maximum declared struct types.
    pub types: usize,
    /// Maximum fields in one struct declaration.
    pub fields_per_type: usize,
    /// Maximum array suffixes in one Solidity type.
    pub array_dimensions: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            source_bytes: 1_048_576,
            depth: 32,
            values: 16_384,
            string_bytes: 131_072,
            array_elements: 4_096,
            object_entries: 4_096,
            types: 256,
            fields_per_type: 256,
            array_dimensions: 8,
        }
    }
}

/// Context that binds a typed-data request to the selected chain and limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ValidationContext {
    /// Nonzero chain selected in the approval context.
    pub expected_chain_id: U256,
    /// Resource ceilings.
    pub limits: Limits,
    /// Explicit signed-schema identifier offered by the request, if any.
    pub schema_exception_id: Option<Hash32>,
}

/// Exact inputs a registry must authenticate before allowing an unbound domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SchemaExceptionRequest<'a> {
    /// Explicit identifier supplied by the caller.
    pub identifier: Hash32,
    /// SHA-256 fingerprint of the canonical type graph and primary type.
    pub schema_fingerprint: Hash32,
    /// SHA-256 of the exact JSON bytes admitted for this request.
    pub source_document_hash: Hash32,
    /// Validated primary struct name.
    pub primary_type: &'a str,
    /// Whether `chainId` is absent from the domain schema.
    pub chain_id_unbound: bool,
    /// Whether `verifyingContract` is absent or zero.
    pub verifying_contract_unbound: bool,
}

/// Verifies a signed schema exception for otherwise unbound domain fields.
trait SchemaExceptionVerifier {
    /// Authenticates the explicit identifier against the canonical schema.
    ///
    /// A mismatching chain ID is rejected before this method is called.
    fn verify_exception(&self, request: SchemaExceptionRequest<'_>) -> bool;
}

/// Exception verifier that denies every exception.
#[derive(Clone, Copy, Debug, Default)]
struct DenySchemaExceptions;

impl SchemaExceptionVerifier for DenySchemaExceptions {
    fn verify_exception(&self, _request: SchemaExceptionRequest<'_>) -> bool {
        false
    }
}

/// Opaque proof that exact source bytes passed strict EIP-712 v4 admission.
///
/// Signing authorization code should accept this type, not a caller-constructed
/// digest-ready protocol struct.
#[derive(Clone, Eq, PartialEq)]
pub struct ValidatedTypedDataV4 {
    protocol_value: UntrustedTypedDataV4,
    exact_source: Vec<u8>,
}

impl fmt::Debug for ValidatedTypedDataV4 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedTypedDataV4")
            .field("protocol_value", &"[REDACTED]")
            .field("exact_source", &"[REDACTED]")
            .finish()
    }
}

impl ValidatedTypedDataV4 {
    /// Borrows the validated value for display and protocol binding.
    #[must_use]
    pub const fn as_untrusted(&self) -> &UntrustedTypedDataV4 {
        &self.protocol_value
    }

    /// Borrows the exact JSON bytes that were strictly parsed and hashed.
    #[must_use]
    pub fn exact_source(&self) -> &[u8] {
        &self.exact_source
    }

    /// Converts the proof into the protocol-layer untrusted representation.
    ///
    /// This conversion is intended for transport after validation. A signing
    /// boundary should continue to require this opaque type or revalidate the
    /// exact source bytes itself.
    #[must_use]
    pub fn into_untrusted(self) -> UntrustedTypedDataV4 {
        self.protocol_value
    }
}

/// Parses, bounds, validates, and hashes one exact EIP-712 v4 source document.
///
/// Duplicate JSON object keys are rejected here, before conversion to a generic
/// value tree. The returned protocol value is created only after every schema,
/// value, domain-binding, and resource check succeeds.
pub fn validate_typed_data_v4(
    source: &[u8],
    expected_chain_id: U256,
) -> Result<ValidatedTypedDataV4, TypedDataError> {
    validate_typed_data_v4_with_policy(
        source,
        ValidationContext {
            expected_chain_id,
            limits: Limits::default(),
            schema_exception_id: None,
        },
        &DenySchemaExceptions,
    )
}

fn validate_typed_data_v4_with_policy(
    source: &[u8],
    context: ValidationContext,
    exceptions: &dyn SchemaExceptionVerifier,
) -> Result<ValidatedTypedDataV4, TypedDataError> {
    if source.len() > context.limits.source_bytes {
        return Err(TypedDataError::LimitExceeded(LimitKind::SourceBytes));
    }
    if context.expected_chain_id.is_zero() {
        return Err(TypedDataError::InvalidExpectedChainId);
    }

    let document = parse_strict(source, context.limits)?;
    let source_document_hash = sha256(source);
    let envelope = parse_envelope(&document)?;
    let schema = Schema::parse(envelope.types, context.limits)?;
    schema.validate_graph(envelope.primary_type)?;

    let domain_separator = schema.hash_struct(DOMAIN_TYPE, envelope.domain)?;
    let message_hash = schema.hash_struct(envelope.primary_type, envelope.message)?;
    let bindings = schema.domain_bindings(envelope.domain, context.expected_chain_id)?;

    let schema_id = if bindings.chain_id.is_none() || bindings.verifying_contract.is_none() {
        let identifier = context
            .schema_exception_id
            .ok_or(TypedDataError::SchemaExceptionRequired)?;
        if identifier == Hash32::ZERO {
            return Err(TypedDataError::InvalidSchemaIdentifier);
        }
        let request = SchemaExceptionRequest {
            identifier,
            schema_fingerprint: schema.fingerprint(envelope.primary_type)?,
            source_document_hash,
            primary_type: envelope.primary_type,
            chain_id_unbound: bindings.chain_id.is_none(),
            verifying_contract_unbound: bindings.verifying_contract.is_none(),
        };
        if exceptions.verify_exception(request) {
            Some(identifier)
        } else {
            return Err(TypedDataError::SchemaExceptionRequired);
        }
    } else {
        None
    };

    Ok(ValidatedTypedDataV4 {
        protocol_value: UntrustedTypedDataV4 {
            domain_separator,
            message_hash,
            source_document_hash,
            chain_id: bindings.chain_id,
            verifying_contract: bindings.verifying_contract,
            schema_id,
        },
        exact_source: source.to_vec(),
    })
}

/// Computes `keccak256(0x1901 || domainSeparator || hashStruct(message))`.
#[must_use]
pub fn eip712_signing_digest(value: &ValidatedTypedDataV4) -> Hash32 {
    let value = value.as_untrusted();
    let mut preimage = [0_u8; 66];
    preimage[0] = 0x19;
    preimage[1] = 0x01;
    preimage[2..34].copy_from_slice(value.domain_separator.as_bytes());
    preimage[34..].copy_from_slice(value.message_hash.as_bytes());
    keccak256(&preimage)
}

struct Envelope<'a> {
    types: &'a Map<String, Value>,
    primary_type: &'a str,
    domain: &'a Map<String, Value>,
    message: &'a Map<String, Value>,
}

fn parse_envelope(document: &Value) -> Result<Envelope<'_>, TypedDataError> {
    let object = document
        .as_object()
        .ok_or(TypedDataError::InvalidEnvelope)?;
    require_exact_keys(object, &ENVELOPE_KEYS, TypedDataError::InvalidEnvelope)?;

    let types = object
        .get("types")
        .and_then(Value::as_object)
        .ok_or(TypedDataError::InvalidEnvelope)?;
    let primary_type = object
        .get("primaryType")
        .and_then(Value::as_str)
        .ok_or(TypedDataError::InvalidEnvelope)?;
    let domain = object
        .get("domain")
        .and_then(Value::as_object)
        .ok_or(TypedDataError::InvalidEnvelope)?;
    let message = object
        .get("message")
        .and_then(Value::as_object)
        .ok_or(TypedDataError::InvalidEnvelope)?;

    if primary_type == DOMAIN_TYPE || !is_identifier(primary_type) {
        return Err(TypedDataError::InvalidEnvelope);
    }
    Ok(Envelope {
        types,
        primary_type,
        domain,
        message,
    })
}

fn require_exact_keys(
    object: &Map<String, Value>,
    expected: &[&str],
    error: TypedDataError,
) -> Result<(), TypedDataError> {
    if object.len() != expected.len() || !expected.iter().all(|key| object.contains_key(*key)) {
        return Err(error);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Schema {
    definitions: BTreeMap<String, StructDefinition>,
}

impl Schema {
    fn parse(definitions: &Map<String, Value>, limits: Limits) -> Result<Self, TypedDataError> {
        if definitions.is_empty() || definitions.len() > limits.types {
            return Err(TypedDataError::LimitExceeded(LimitKind::Types));
        }
        let mut parsed = BTreeMap::new();
        for (name, value) in definitions {
            if !is_identifier(name) || is_primitive_name(name) {
                return Err(TypedDataError::InvalidTypeDefinition);
            }
            let fields = value
                .as_array()
                .ok_or(TypedDataError::InvalidTypeDefinition)?;
            if fields.len() > limits.fields_per_type {
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
                    field_type: SolidityType::parse(field_type, limits)?,
                });
            }
            parsed.insert(
                name.clone(),
                StructDefinition {
                    name: name.clone(),
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

    fn validate_graph(&self, primary_type: &str) -> Result<(), TypedDataError> {
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

        let mut reachable = BTreeSet::new();
        self.collect_reachable(DOMAIN_TYPE, &mut reachable)?;
        self.collect_reachable(primary_type, &mut reachable)?;
        if reachable.len() != self.definitions.len() {
            return Err(TypedDataError::UnreachableType);
        }
        Ok(())
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
        let definition = self
            .definitions
            .get(name)
            .ok_or(TypedDataError::UndefinedType)?;
        for field in &definition.fields {
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
        let definition = self
            .definitions
            .get(name)
            .ok_or(TypedDataError::UndefinedType)?;
        for field in &definition.fields {
            if let BaseType::Struct(dependency) = &field.field_type.base {
                self.collect_reachable(dependency, reachable)?;
            }
        }
        Ok(())
    }

    fn encode_type(&self, primary_type: &str) -> Result<String, TypedDataError> {
        let mut dependencies = BTreeSet::new();
        self.collect_reachable(primary_type, &mut dependencies)?;
        dependencies.remove(primary_type);

        let mut encoded = self.encode_declaration(primary_type)?;
        for dependency in dependencies {
            encoded.push_str(&self.encode_declaration(&dependency)?);
        }
        Ok(encoded)
    }

    fn encode_declaration(&self, name: &str) -> Result<String, TypedDataError> {
        let definition = self
            .definitions
            .get(name)
            .ok_or(TypedDataError::UndefinedType)?;
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

    fn type_hash(&self, name: &str) -> Result<Hash32, TypedDataError> {
        Ok(keccak256(self.encode_type(name)?.as_bytes()))
    }

    fn fingerprint(&self, primary_type: &str) -> Result<Hash32, TypedDataError> {
        const DOMAIN: &[u8] = b"your-wallet:eip712-schema:v1";
        let mut transcript = Vec::new();
        transcript.extend_from_slice(DOMAIN);
        append_length_prefixed(&mut transcript, primary_type.as_bytes())?;
        for name in self.definitions.keys() {
            append_length_prefixed(&mut transcript, name.as_bytes())?;
            append_length_prefixed(&mut transcript, self.encode_declaration(name)?.as_bytes())?;
        }
        Ok(sha256(&transcript))
    }

    fn hash_struct(
        &self,
        name: &str,
        value: &Map<String, Value>,
    ) -> Result<Hash32, TypedDataError> {
        let definition = self
            .definitions
            .get(name)
            .ok_or(TypedDataError::UndefinedType)?;
        validate_struct_shape(definition, value)?;

        let mut encoded =
            Vec::with_capacity(definition.fields.len().saturating_add(1).saturating_mul(32));
        encoded.extend_from_slice(self.type_hash(name)?.as_bytes());
        for field in &definition.fields {
            let field_value = value.get(&field.name).ok_or(TypedDataError::MissingValue)?;
            encoded.extend_from_slice(&self.encode_value(&field.field_type, field_value)?);
        }
        Ok(keccak256(&encoded))
    }

    fn encode_value(
        &self,
        field_type: &SolidityType,
        value: &Value,
    ) -> Result<[u8; 32], TypedDataError> {
        self.encode_type_parts(&field_type.base, &field_type.arrays, value)
    }

    fn encode_type_parts(
        &self,
        base: &BaseType,
        arrays: &[ArrayDimension],
        value: &Value,
    ) -> Result<[u8; 32], TypedDataError> {
        if let Some((outer, inner)) = arrays.split_last() {
            let values = value.as_array().ok_or(TypedDataError::InvalidValue)?;
            if let ArrayDimension::Fixed(expected) = outer
                && values.len() != *expected
            {
                return Err(TypedDataError::InvalidValue);
            }
            let mut encoded = Vec::with_capacity(values.len().saturating_mul(32));
            for element in values {
                encoded.extend_from_slice(&self.encode_type_parts(base, inner, element)?);
            }
            return Ok(*keccak256(&encoded).as_bytes());
        }

        match base {
            BaseType::Address => encode_address(value),
            BaseType::Bool => encode_bool(value),
            BaseType::String => value
                .as_str()
                .map(|text| *keccak256(text.as_bytes()).as_bytes())
                .ok_or(TypedDataError::InvalidValue),
            BaseType::Bytes => value
                .as_str()
                .ok_or(TypedDataError::InvalidValue)
                .and_then(decode_hex_bytes)
                .map(|bytes| *keccak256(&bytes).as_bytes()),
            BaseType::BytesN(width) => encode_fixed_bytes(value, *width),
            BaseType::Int(bits) => encode_integer(value, *bits, true),
            BaseType::Uint(bits) => encode_integer(value, *bits, false),
            BaseType::Struct(name) => {
                let object = value.as_object().ok_or(TypedDataError::InvalidValue)?;
                Ok(*self.hash_struct(name, object)?.as_bytes())
            }
        }
    }

    fn domain_bindings(
        &self,
        domain: &Map<String, Value>,
        expected_chain_id: U256,
    ) -> Result<DomainBindings, TypedDataError> {
        let definition = self
            .definitions
            .get(DOMAIN_TYPE)
            .ok_or(TypedDataError::UndefinedType)?;

        let chain_field = definition
            .fields
            .iter()
            .find(|field| field.name == "chainId");
        let chain_id = match chain_field {
            Some(field)
                if field.field_type.base == BaseType::Uint(256)
                    && field.field_type.arrays.is_empty() =>
            {
                let value = domain.get("chainId").ok_or(TypedDataError::MissingValue)?;
                let encoded = encode_integer(value, 256, false)?;
                let parsed = U256::from_be_bytes(encoded);
                if parsed != expected_chain_id {
                    return Err(TypedDataError::ChainIdMismatch);
                }
                Some(parsed)
            }
            Some(_) => return Err(TypedDataError::InvalidDomainBindingType),
            None => None,
        };

        let contract_field = definition
            .fields
            .iter()
            .find(|field| field.name == "verifyingContract");
        let verifying_contract = match contract_field {
            Some(field)
                if field.field_type.base == BaseType::Address
                    && field.field_type.arrays.is_empty() =>
            {
                let value = domain
                    .get("verifyingContract")
                    .ok_or(TypedDataError::MissingValue)?;
                let address = parse_address(value)?;
                if address == Address20::default() {
                    None
                } else {
                    Some(address)
                }
            }
            Some(_) => return Err(TypedDataError::InvalidDomainBindingType),
            None => None,
        };

        Ok(DomainBindings {
            chain_id,
            verifying_contract,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VisitState {
    Visiting,
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StructDefinition {
    name: String,
    fields: Vec<FieldDefinition>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FieldDefinition {
    name: String,
    field_type: SolidityType,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SolidityType {
    base: BaseType,
    arrays: Vec<ArrayDimension>,
    canonical: String,
}

impl SolidityType {
    fn parse(source: &str, limits: Limits) -> Result<Self, TypedDataError> {
        let array_start = source.find('[').unwrap_or(source.len());
        let base_source = &source[..array_start];
        let base = BaseType::parse(base_source)?;
        let mut arrays = Vec::new();
        let mut suffix = &source[array_start..];
        while !suffix.is_empty() {
            if arrays.len() >= limits.array_dimensions || !suffix.starts_with('[') {
                return Err(if arrays.len() >= limits.array_dimensions {
                    TypedDataError::LimitExceeded(LimitKind::ArrayDimensions)
                } else {
                    TypedDataError::InvalidTypeDefinition
                });
            }
            let close = suffix
                .find(']')
                .ok_or(TypedDataError::InvalidTypeDefinition)?;
            let length = &suffix[1..close];
            let dimension = if length.is_empty() {
                ArrayDimension::Dynamic
            } else {
                if length.starts_with('0') || !length.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(TypedDataError::InvalidTypeDefinition);
                }
                let parsed = length
                    .parse::<usize>()
                    .map_err(|_| TypedDataError::InvalidTypeDefinition)?;
                if parsed == 0 || parsed > limits.array_elements {
                    return Err(TypedDataError::LimitExceeded(LimitKind::ArrayElements));
                }
                ArrayDimension::Fixed(parsed)
            };
            arrays.push(dimension);
            suffix = &suffix[close.saturating_add(1)..];
        }
        Ok(Self {
            base,
            arrays,
            canonical: source.to_owned(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArrayDimension {
    Dynamic,
    Fixed(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DomainBindings {
    chain_id: Option<U256>,
    verifying_contract: Option<Address20>,
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

fn is_primitive_name(name: &str) -> bool {
    BaseType::parse(name).is_ok_and(|base| !matches!(base, BaseType::Struct(_)))
}

fn is_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn validate_struct_shape(
    definition: &StructDefinition,
    value: &Map<String, Value>,
) -> Result<(), TypedDataError> {
    for field in &definition.fields {
        if !value.contains_key(&field.name) {
            return Err(TypedDataError::MissingValue);
        }
    }
    if value
        .keys()
        .any(|key| !definition.fields.iter().any(|field| field.name == *key))
    {
        return Err(TypedDataError::ExtraValue);
    }
    Ok(())
}

fn encode_bool(value: &Value) -> Result<[u8; 32], TypedDataError> {
    let boolean = value.as_bool().ok_or(TypedDataError::InvalidValue)?;
    let mut encoded = [0_u8; 32];
    encoded[31] = u8::from(boolean);
    Ok(encoded)
}

fn parse_address(value: &Value) -> Result<Address20, TypedDataError> {
    let text = value.as_str().ok_or(TypedDataError::InvalidValue)?;
    let bytes = decode_fixed_hex::<20>(text)?;
    Ok(Address20::new(bytes))
}

fn encode_address(value: &Value) -> Result<[u8; 32], TypedDataError> {
    let address = parse_address(value)?;
    let mut encoded = [0_u8; 32];
    encoded[12..].copy_from_slice(address.as_bytes());
    Ok(encoded)
}

fn encode_fixed_bytes(value: &Value, width: usize) -> Result<[u8; 32], TypedDataError> {
    let text = value.as_str().ok_or(TypedDataError::InvalidValue)?;
    let bytes = decode_hex_bytes(text)?;
    if bytes.len() != width {
        return Err(TypedDataError::InvalidValue);
    }
    let mut encoded = [0_u8; 32];
    encoded[..width].copy_from_slice(&bytes);
    Ok(encoded)
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], TypedDataError> {
    let decoded = decode_hex_bytes(value)?;
    decoded.try_into().map_err(|_| TypedDataError::InvalidValue)
}

fn decode_hex_bytes(value: &str) -> Result<Vec<u8>, TypedDataError> {
    let digits = value
        .strip_prefix("0x")
        .ok_or(TypedDataError::InvalidValue)?;
    if digits.len() % 2 != 0 {
        return Err(TypedDataError::InvalidValue);
    }
    let mut bytes = Vec::with_capacity(digits.len() / 2);
    for pair in digits.as_bytes().chunks_exact(2) {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn decode_hex_nibble(value: u8) -> Result<u8, TypedDataError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(TypedDataError::InvalidValue),
    }
}

fn encode_integer(value: &Value, bits: u16, signed: bool) -> Result<[u8; 32], TypedDataError> {
    let parsed = parse_integer_value(value, signed)?;
    let byte_width = usize::from(bits / 8);
    if signed {
        encode_signed_integer(parsed, byte_width)
    } else {
        if parsed.negative || !fits_unsigned(&parsed.magnitude, byte_width) {
            return Err(TypedDataError::InvalidValue);
        }
        Ok(parsed.magnitude)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedInteger {
    negative: bool,
    magnitude: [u8; 32],
}

fn parse_integer_value(value: &Value, signed: bool) -> Result<ParsedInteger, TypedDataError> {
    match value {
        Value::String(text) => parse_integer_text(text, signed),
        Value::Number(number) => parse_integer_number(number, signed),
        _ => Err(TypedDataError::InvalidValue),
    }
}

fn parse_integer_number(number: &Number, signed: bool) -> Result<ParsedInteger, TypedDataError> {
    if let Some(value) = number.as_u64() {
        if value > MAX_SAFE_JSON_INTEGER {
            return Err(TypedDataError::InvalidValue);
        }
        return Ok(ParsedInteger {
            negative: false,
            magnitude: magnitude_from_u64(value),
        });
    }
    if signed && let Some(value) = number.as_i64() {
        let magnitude = value.unsigned_abs();
        if magnitude > MAX_SAFE_JSON_INTEGER {
            return Err(TypedDataError::InvalidValue);
        }
        return Ok(ParsedInteger {
            negative: value.is_negative(),
            magnitude: magnitude_from_u64(magnitude),
        });
    }
    Err(TypedDataError::InvalidValue)
}

fn parse_integer_text(text: &str, signed: bool) -> Result<ParsedInteger, TypedDataError> {
    if let Some(hex) = text.strip_prefix("0x") {
        if hex.is_empty()
            || (hex.len() > 1 && hex.starts_with('0'))
            || hex.len() > 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(TypedDataError::InvalidValue);
        }
        let padded = if hex.len() % 2 == 0 {
            hex.to_owned()
        } else {
            let mut value = String::with_capacity(hex.len().saturating_add(1));
            value.push('0');
            value.push_str(hex);
            value
        };
        let bytes = decode_hex_bytes(&format!("0x{padded}"))?;
        let mut magnitude = [0_u8; 32];
        let start = 32_usize.saturating_sub(bytes.len());
        magnitude[start..].copy_from_slice(&bytes);
        return Ok(ParsedInteger {
            negative: false,
            magnitude,
        });
    }

    let (negative, digits) = if let Some(rest) = text.strip_prefix('-') {
        if !signed {
            return Err(TypedDataError::InvalidValue);
        }
        (true, rest)
    } else {
        (false, text)
    };
    if digits.is_empty()
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || (negative && digits == "0")
    {
        return Err(TypedDataError::InvalidValue);
    }
    Ok(ParsedInteger {
        negative,
        magnitude: parse_decimal_magnitude(digits)?,
    })
}

fn parse_decimal_magnitude(digits: &str) -> Result<[u8; 32], TypedDataError> {
    let mut value = [0_u8; 32];
    for digit in digits.bytes() {
        let mut carry = u16::from(digit - b'0');
        for byte in value.iter_mut().rev() {
            let product = u16::from(*byte)
                .checked_mul(10)
                .and_then(|current| current.checked_add(carry))
                .ok_or(TypedDataError::InvalidValue)?;
            *byte = u8::try_from(product & 0xff).map_err(|_| TypedDataError::InvalidValue)?;
            carry = product >> 8;
        }
        if carry != 0 {
            return Err(TypedDataError::InvalidValue);
        }
    }
    Ok(value)
}

fn magnitude_from_u64(value: u64) -> [u8; 32] {
    let mut magnitude = [0_u8; 32];
    magnitude[24..].copy_from_slice(&value.to_be_bytes());
    magnitude
}

fn fits_unsigned(value: &[u8; 32], byte_width: usize) -> bool {
    value[..32_usize.saturating_sub(byte_width)]
        .iter()
        .all(|byte| *byte == 0)
}

fn encode_signed_integer(
    value: ParsedInteger,
    byte_width: usize,
) -> Result<[u8; 32], TypedDataError> {
    if !fits_signed_magnitude(&value.magnitude, byte_width, value.negative) {
        return Err(TypedDataError::InvalidValue);
    }
    if !value.negative {
        return Ok(value.magnitude);
    }
    let mut encoded = value.magnitude.map(|byte| !byte);
    for byte in encoded.iter_mut().rev() {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
    Ok(encoded)
}

fn fits_signed_magnitude(value: &[u8; 32], byte_width: usize, negative: bool) -> bool {
    let start = 32_usize.saturating_sub(byte_width);
    if value[..start].iter().any(|byte| *byte != 0) {
        return false;
    }
    let leading = value[start];
    if negative {
        leading < 0x80
            || (leading == 0x80 && value[start.saturating_add(1)..].iter().all(|b| *b == 0))
    } else {
        leading < 0x80
    }
}

fn sha256(value: &[u8]) -> Hash32 {
    let digest: [u8; 32] = Sha256::digest(value).into();
    Hash32::new(digest)
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) -> Result<(), TypedDataError> {
    let length = u32::try_from(value.len()).map_err(|_| TypedDataError::InvalidTypeDefinition)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn keccak256(value: &[u8]) -> Hash32 {
    let digest: [u8; 32] = Keccak256::digest(value).into();
    Hash32::new(digest)
}
