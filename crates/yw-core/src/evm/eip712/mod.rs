//! `eth_signTypedData_v4` (EIP-712) validation, hashing and schema recognition (spec/03 §8, D17).
//!
//! Port of `archive/spec-v2.4:crates/eip712/src/{lib.rs,error.rs,schema.rs}` onto
//! `yw_json::Value` (serde and `json.rs` removed). The hash core (`schema.rs:426-543`: encodeType,
//! typeHash, hashStruct, arrays, string/bytes) is unchanged. v3 changes (spec/03 §8.1): missing
//! chainId/verifyingContract no longer require a schema exception (T03/T10 instead); a chainId
//! mismatch is still rejected (T01); unreachable types are allowed; hex integers may have leading
//! zeros and uppercase digits; mixed-case addresses follow EIP-55 (§2.1); the source limit is
//! 131,072 bytes; the other `Limits::default` values stay.
#![deny(clippy::indexing_slicing)]

mod schema;

use core::fmt;

use sha3::{Digest, Keccak256};

pub use schema::{TdNode, TdValue};

use super::address::Address;
use super::amount::U256;
use super::chain::{ContractRole, builtin_chain};
use crate::hex::const_decode;

/// Maximum source bytes (spec/03 §8.1 #8).
pub const MAX_TYPED_DATA_SOURCE: usize = 131_072;

macro_rules! type_hashes {
    ($($name:ident = $hex:literal;)*) => {
        $(
            #[doc = concat!("EIP-712 typeHash `0x", $hex, "` (spec/09 §3.6).")]
            pub const $name: [u8; 32] = const_decode::<32>($hex);
        )*
    };
}

type_hashes! {
    TYPEHASH_DOMAIN_4 = "8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f";
    TYPEHASH_DOMAIN_PERMIT2 = "8cad95687ba82c2ce50e74f7b754645e5117c3a5bec8151c0726d5857980a866";
    TYPEHASH_EIP2612_PERMIT = "6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9";
    TYPEHASH_DAI_PERMIT = "ea2aa0a1be11a07ed86d755c93467f4f82362b452371d1ba94d1715123511acb";
    TYPEHASH_PERMIT_DETAILS = "65626cad6cb96493bf6f5ebea28756c966f023ab9e8a83a7101849d5573b3678";
    TYPEHASH_PERMIT_SINGLE = "f3841cd1ff0085026a6327b620b67997ce40f282c88a8e905a7a5626e310f3d0";
    TYPEHASH_PERMIT_BATCH = "af1b0d30d2cab0380e68f0689007e3254993c596f2fdd0aaa7f4d04f79440863";
    TYPEHASH_TOKEN_PERMISSIONS = "618358ac3db8dc274f0cd8829da7e234bd48cd73c4a740aede1adec9846d06a1";
    TYPEHASH_PERMIT_TRANSFER_FROM = "939c21a48a8dbe3a9a2404a1d46691e4d39f6583d6ec6b35714604c986d80106";
    TYPEHASH_PERMIT_BATCH_TRANSFER_FROM = "fcf35f5ac6a2c28868dc44c302166470266239195f02b0ee408334829333b766";
    TYPEHASH_SEAPORT_ORDER = "fa445660b7e21515a59617fcd68910b487aa5808b8abda3d78bc85df364b2c2f";
}

/// Resource ceiling that was exceeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitKind {
    /// Source bytes.
    SourceBytes,
    /// Nesting depth.
    Depth,
    /// Total JSON values.
    Values,
    /// Bytes of one key or string.
    StringBytes,
    /// Elements of one array.
    ArrayElements,
    /// Entries of one object.
    ObjectEntries,
    /// Declared struct types.
    Types,
    /// Fields of one struct.
    Fields,
    /// Array suffixes of one type.
    ArrayDimensions,
}

/// Typed-data rejection. [`TypedDataError::ChainIdMismatch`] is T01; everything else is T02.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypedDataError {
    /// A resource ceiling was exceeded.
    LimitExceeded(LimitKind),
    /// The envelope is incomplete, has unknown keys, or primaryType is `EIP712Domain`.
    InvalidEnvelope,
    /// A type or field declaration is malformed.
    InvalidTypeDefinition,
    /// A struct declares a field twice.
    DuplicateField,
    /// A referenced struct is not declared.
    UndefinedType,
    /// The type graph is cyclic.
    CyclicType,
    /// A value has the wrong kind, encoding, width or range.
    InvalidValue,
    /// A declared field is missing.
    MissingValue,
    /// An undeclared field is present.
    ExtraValue,
    /// `domain.chainId` differs from the active chain (T01).
    ChainIdMismatch,
    /// `chainId`/`verifyingContract` declared with a non-standard type.
    InvalidDomainBindingType,
    /// Permit2/Seaport verifying contract with a schema outside the table, or Seaport `BulkOrder`.
    SchemaMismatch,
}

impl fmt::Display for TypedDataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LimitExceeded(_) => "typed-data resource limit exceeded",
            Self::InvalidEnvelope => "invalid typed-data envelope",
            Self::InvalidTypeDefinition => "invalid EIP-712 type definition",
            Self::DuplicateField => "duplicate EIP-712 field",
            Self::UndefinedType => "undefined EIP-712 struct type",
            Self::CyclicType => "cyclic EIP-712 type graph",
            Self::InvalidValue => "invalid EIP-712 value",
            Self::MissingValue => "missing EIP-712 value",
            Self::ExtraValue => "unexpected EIP-712 value",
            Self::ChainIdMismatch => "typed-data chain ID mismatch",
            Self::InvalidDomainBindingType => "invalid domain-binding type",
            Self::SchemaMismatch => "schema does not match the verifying contract",
        })
    }
}

impl std::error::Error for TypedDataError {}

/// Recognized schemas (spec/03 §8.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KnownSchema {
    /// EIP-2612 `Permit`.
    Eip2612Permit,
    /// DAI `Permit`.
    DaiPermit,
    /// Permit2 `PermitSingle`.
    Permit2Single,
    /// Permit2 `PermitBatch`.
    Permit2Batch,
    /// Permit2 `PermitTransferFrom`.
    Permit2Transfer,
    /// Permit2 `PermitBatchTransferFrom`.
    Permit2BatchTransfer,
    /// Permit2 `PermitWitnessTransferFrom` with a witness struct type.
    Permit2WitnessTransfer {
        /// Witness struct type name.
        witness_type: String,
    },
    /// Permit2 `PermitBatchWitnessTransferFrom` with a witness struct type.
    Permit2BatchWitnessTransfer {
        /// Witness struct type name.
        witness_type: String,
    },
    /// Seaport `OrderComponents`.
    SeaportOrder,
}

impl KnownSchema {
    /// The `schema_id` string.
    #[must_use]
    pub const fn schema_id(&self) -> &'static str {
        match self {
            Self::Eip2612Permit => "eip2612-permit",
            Self::DaiPermit => "dai-permit",
            Self::Permit2Single => "permit2-permit-single",
            Self::Permit2Batch => "permit2-permit-batch",
            Self::Permit2Transfer => "permit2-transfer",
            Self::Permit2BatchTransfer => "permit2-batch-transfer",
            Self::Permit2WitnessTransfer { .. } => "permit2-witness-transfer",
            Self::Permit2BatchWitnessTransfer { .. } => "permit2-batch-witness-transfer",
            Self::SeaportOrder => "seaport-order",
        }
    }

    /// Whether this is a Permit2 schema.
    #[must_use]
    pub const fn is_permit2(&self) -> bool {
        matches!(
            self,
            Self::Permit2Single
                | Self::Permit2Batch
                | Self::Permit2Transfer
                | Self::Permit2BatchTransfer
                | Self::Permit2WitnessTransfer { .. }
                | Self::Permit2BatchWitnessTransfer { .. }
        )
    }
}

/// The standard domain fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TdDomain {
    /// `name`.
    pub name: Option<String>,
    /// `version`.
    pub version: Option<String>,
    /// `chainId` (`None` → T03).
    pub chain_id: Option<U256>,
    /// `verifyingContract` (`None` when absent or zero → T10).
    pub verifying_contract: Option<Address>,
    /// `salt`.
    pub salt: Option<[u8; 32]>,
    /// The domain value tree (all fields, display).
    pub tree: TdNode,
}

/// A validated typed-data request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedTypedData {
    /// Domain.
    pub domain: TdDomain,
    /// Primary type name.
    pub primary_type: String,
    /// Recognized schema.
    pub schema: Option<KnownSchema>,
    /// `0x19 0x01 ‖ domainSeparator ‖ hashStruct(message)`.
    pub preimage: [u8; 66],
    /// The message value tree.
    pub root: TdNode,
}

impl DecodedTypedData {
    /// `domainSeparator`.
    #[must_use]
    pub fn domain_separator(&self) -> [u8; 32] {
        let mut out = [0_u8; 32];
        if let Some(bytes) = self.preimage.get(2..34) {
            out.copy_from_slice(bytes);
        }
        out
    }

    /// `hashStruct(message)`.
    #[must_use]
    pub fn message_hash(&self) -> [u8; 32] {
        let mut out = [0_u8; 32];
        if let Some(bytes) = self.preimage.get(34..66) {
            out.copy_from_slice(bytes);
        }
        out
    }
}

/// `keccak256(preimage)`.
#[must_use]
pub fn eip712_digest(typed: &DecodedTypedData) -> [u8; 32] {
    Keccak256::digest(typed.preimage).into()
}

/// Validates, hashes and classifies a typed-data document (spec/03 §8.1–§8.2). `src` is the exact
/// source bytes (size bound), `value` its yw-json parse, `chain_id` the active chain.
///
/// # Errors
///
/// [`TypedDataError::ChainIdMismatch`] (T01) or any other variant (T02).
pub fn validate_typed_data_v4(
    src: &[u8],
    value: &yw_json::Value,
    chain_id: u64,
) -> Result<DecodedTypedData, TypedDataError> {
    if src.len() > MAX_TYPED_DATA_SOURCE {
        return Err(TypedDataError::LimitExceeded(LimitKind::SourceBytes));
    }
    schema::check_value_limits(value)?;
    let envelope = schema::Envelope::parse(value)?;
    let types = schema::Schema::parse(envelope.types)?;
    types.validate_graph(envelope.primary_type)?;
    let (domain_separator, domain_tree) =
        types.hash_struct_tree(schema::DOMAIN_TYPE, envelope.domain, 0)?;
    let (message_hash, root) =
        types.hash_struct_tree(envelope.primary_type, envelope.message, 0)?;
    let domain = types.domain(envelope.domain, domain_tree, chain_id)?;
    let schema = recognize(&types, envelope.primary_type, &domain, chain_id)?;
    let mut preimage = [0_u8; 66];
    let (prefix, rest) = preimage.split_at_mut(2);
    prefix.copy_from_slice(&[0x19, 0x01]);
    let (separator, message) = rest.split_at_mut(32);
    separator.copy_from_slice(&domain_separator);
    message.copy_from_slice(&message_hash);
    Ok(DecodedTypedData {
        domain,
        primary_type: envelope.primary_type.to_owned(),
        schema,
        preimage,
        root,
    })
}

fn recognize(
    types: &schema::Schema,
    primary: &str,
    domain: &TdDomain,
    chain_id: u64,
) -> Result<Option<KnownSchema>, TypedDataError> {
    let chain = builtin_chain(chain_id);
    let role = domain.verifying_contract.and_then(|address| {
        chain
            .as_ref()
            .and_then(|chain| chain.contract(&address))
            .map(|contract| contract.role)
    });
    let primary_hash = types.type_hash(primary)?;
    let domain_hash = types.type_hash(schema::DOMAIN_TYPE)?;

    let permit2 = permit2_schema(types, primary, primary_hash)?;
    let permit2_domain = domain_hash == TYPEHASH_DOMAIN_PERMIT2
        && domain.name.as_deref() == Some("Permit2")
        && domain.chain_id.is_some();
    if role == Some(ContractRole::Permit2) {
        return match permit2 {
            Some(schema) if permit2_domain => Ok(Some(schema)),
            _ => Err(TypedDataError::SchemaMismatch),
        };
    }
    if permit2.is_some() {
        return Ok(None);
    }

    let seaport_role = matches!(
        role,
        Some(ContractRole::Seaport15 | ContractRole::Seaport16)
    );
    let seaport_schema = primary == "OrderComponents" && primary_hash == TYPEHASH_SEAPORT_ORDER;
    if seaport_role {
        let version_ok = matches!(
            (role, domain.version.as_deref()),
            (Some(ContractRole::Seaport16), Some("1.6"))
                | (Some(ContractRole::Seaport15), Some("1.5"))
        );
        let domain_ok = domain_hash == TYPEHASH_DOMAIN_4
            && domain.name.as_deref() == Some("Seaport")
            && version_ok;
        return if seaport_schema && domain_ok {
            Ok(Some(KnownSchema::SeaportOrder))
        } else {
            Err(TypedDataError::SchemaMismatch)
        };
    }
    if seaport_schema {
        return Ok(None);
    }

    if primary == "Permit" {
        if primary_hash == TYPEHASH_EIP2612_PERMIT && domain.verifying_contract.is_some() {
            return Ok(Some(KnownSchema::Eip2612Permit));
        }
        if primary_hash == TYPEHASH_DAI_PERMIT {
            return Ok(Some(KnownSchema::DaiPermit));
        }
    }
    Ok(None)
}

fn permit2_schema(
    types: &schema::Schema,
    primary: &str,
    primary_hash: [u8; 32],
) -> Result<Option<KnownSchema>, TypedDataError> {
    Ok(match primary {
        "PermitSingle" if primary_hash == TYPEHASH_PERMIT_SINGLE => {
            Some(KnownSchema::Permit2Single)
        }
        "PermitBatch" if primary_hash == TYPEHASH_PERMIT_BATCH => Some(KnownSchema::Permit2Batch),
        "PermitTransferFrom" if primary_hash == TYPEHASH_PERMIT_TRANSFER_FROM => {
            Some(KnownSchema::Permit2Transfer)
        }
        "PermitBatchTransferFrom" if primary_hash == TYPEHASH_PERMIT_BATCH_TRANSFER_FROM => {
            Some(KnownSchema::Permit2BatchTransfer)
        }
        "PermitWitnessTransferFrom" => types
            .witness_type(primary, false)?
            .map(|witness_type| KnownSchema::Permit2WitnessTransfer { witness_type }),
        "PermitBatchWitnessTransferFrom" => types
            .witness_type(primary, true)?
            .map(|witness_type| KnownSchema::Permit2BatchWitnessTransfer { witness_type }),
        _ => None,
    })
}
