use core::fmt;

/// Bounded resource whose configured ceiling was exceeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitKind {
    /// Exact source-document bytes.
    SourceBytes,
    /// Nested JSON object/array depth.
    Depth,
    /// Total JSON values.
    Values,
    /// UTF-8 bytes in one key or string value.
    StringBytes,
    /// Elements in one JSON array.
    ArrayElements,
    /// Entries in one JSON object.
    ObjectEntries,
    /// Declared struct types.
    Types,
    /// Fields in one struct type.
    Fields,
    /// Array suffixes in one Solidity type.
    ArrayDimensions,
}

/// Failure while validating or hashing an untrusted EIP-712 document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TypedDataError {
    /// The source is not one complete JSON value.
    InvalidJson,
    /// A JSON object repeats a key.
    DuplicateJsonKey,
    /// A configured resource ceiling was exceeded.
    LimitExceeded(LimitKind),
    /// The top-level typed-data envelope is incomplete or has unknown fields.
    InvalidEnvelope,
    /// A type or field declaration is malformed or non-canonical.
    InvalidTypeDefinition,
    /// One struct declares the same field name more than once.
    DuplicateField,
    /// A field refers to a struct that is not declared.
    UndefinedType,
    /// The declared struct dependency graph is cyclic.
    CyclicType,
    /// A declared type is not reachable from the domain or primary type.
    UnreachableType,
    /// A message/domain value has the wrong JSON kind, encoding, width, or range.
    InvalidValue,
    /// A declared field is absent from its value object.
    MissingValue,
    /// A value object includes a field absent from its declaration.
    ExtraValue,
    /// The configured expected chain ID is zero.
    InvalidExpectedChainId,
    /// A declared domain chain ID differs from the selected chain.
    ChainIdMismatch,
    /// A standard domain-binding field uses a non-standard Solidity type.
    InvalidDomainBindingType,
    /// Required chain/contract binding is absent or zero and no signed exception applies.
    SchemaExceptionRequired,
    /// The exception verifier returned an invalid all-zero schema identifier.
    InvalidSchemaIdentifier,
}

impl fmt::Display for TypedDataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidJson => "invalid JSON source",
            Self::DuplicateJsonKey => "duplicate JSON key",
            Self::LimitExceeded(_) => "typed-data resource limit exceeded",
            Self::InvalidEnvelope => "invalid typed-data envelope",
            Self::InvalidTypeDefinition => "invalid EIP-712 type definition",
            Self::DuplicateField => "duplicate EIP-712 field",
            Self::UndefinedType => "undefined EIP-712 struct type",
            Self::CyclicType => "cyclic EIP-712 type graph",
            Self::UnreachableType => "unreachable EIP-712 type",
            Self::InvalidValue => "invalid EIP-712 value",
            Self::MissingValue => "missing EIP-712 value",
            Self::ExtraValue => "unexpected EIP-712 value",
            Self::InvalidExpectedChainId => "expected chain ID must be nonzero",
            Self::ChainIdMismatch => "typed-data chain ID mismatch",
            Self::InvalidDomainBindingType => "invalid domain-binding type",
            Self::SchemaExceptionRequired => "signed schema exception required",
            Self::InvalidSchemaIdentifier => "invalid schema identifier",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for TypedDataError {}
