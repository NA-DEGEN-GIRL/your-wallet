//! `eth_signTypedData_v4` (EIP-712) validation, hashing and schema recognition (spec/03 §8, D17).
//!
//! Port of `archive/spec-v2.4:crates/eip712/src/{lib.rs,error.rs,schema.rs}` onto
//! `yw_json::Value` (serde and `json.rs` removed). The hash core (`schema.rs:426-543`: encodeType,
//! typeHash, hashStruct, arrays, string/bytes) is unchanged. v3 changes (spec/03 §8.1): missing
//! chainId/verifyingContract no longer require a schema exception (T03/T10 instead); a chainId
//! mismatch is still rejected (T01); unreachable types are allowed; hex integers may have leading
//! zeros and uppercase digits; mixed-case addresses follow EIP-55 (§2.1); the source limit is
//! 131,072 bytes; the other `Limits::default` values stay. Added in v3: `EIP712Domain` may only
//! declare the five standard fields with their standard types; identifiers ≤ 256 bytes, type
//! strings ≤ 512 bytes, ≤ 1,024 fields over all types, and each `typeHash` is computed once per
//! request with ≤ 262,144 `encodeType` bytes in total (validation cost guard).
#![deny(clippy::indexing_slicing)]

mod schema;

use core::fmt;

use sha3::{Digest, Keccak256};

pub use schema::{TdNode, TdValue};

use super::address::Address;
use super::amount::U256;
use super::chain::{ContractRole, TokenRole, builtin_chain};
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

/// The EIP-712 chain id of Hyperliquid L1 actions (SDK `l1_payload`: domain `Exchange` v1).
pub const HL_L1_CHAIN_ID: u64 = 1337;
/// `encodeType` of the Hyperliquid phantom agent (SDK `l1_payload`).
pub const HL_AGENT_TYPE: &str = "Agent(string source,bytes32 connectionId)";
/// `encodeType` of `approveAgent` (SDK `sign_agent`).
pub const HL_APPROVE_AGENT_TYPE: &str = "HyperliquidTransaction:ApproveAgent(string hyperliquidChain,address agentAddress,string agentName,uint64 nonce)";
/// `encodeType` of `approveBuilderFee` (SDK `sign_approve_builder_fee`).
pub const HL_APPROVE_BUILDER_FEE_TYPE: &str = "HyperliquidTransaction:ApproveBuilderFee(string hyperliquidChain,string maxFeeRate,address builder,uint64 nonce)";

/// A recognized Hyperliquid user-signed action (`HyperliquidSignTransaction` domain).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HlUserAction {
    /// One of the transfers this wallet also builds (spec/11 §5).
    Transfer(crate::hypercore::HcKind),
    /// `approveAgent`: delegates trading to an API wallet.
    ApproveAgent,
    /// `approveBuilderFee`.
    ApproveBuilderFee,
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
    /// `EIP712Domain` declares a field other than name/version/chainId/verifyingContract/salt,
    /// or name/version/salt with a non-standard type (v3, spec/03 §8.1 #9).
    NonStandardDomain,
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
            Self::NonStandardDomain => "non-standard EIP-712 domain field",
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
    /// A Hyperliquid user-signed action (spec/11 §7).
    HyperliquidUser(HlUserAction),
    /// A Hyperliquid L1 action signature (phantom agent, chainId 1337, spec/11 §7).
    HyperliquidL1Agent,
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
            Self::HyperliquidUser(_) => "hyperliquid-user-action",
            Self::HyperliquidL1Agent => "hyperliquid-l1-agent",
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
    types.check_domain_fields()?;
    let (domain_separator, domain_tree) =
        types.hash_struct_tree(schema::DOMAIN_TYPE, envelope.domain, 0)?;
    let (message_hash, root) =
        types.hash_struct_tree(envelope.primary_type, envelope.message, 0)?;
    // A Hyperliquid L1 action is signed at chainId 1337 whatever the wallet's chain (SDK
    // `l1_payload`); only the exact phantom-agent schema gets that exception (spec/11 §7).
    let hl_l1 = envelope.primary_type == "Agent"
        && envelope.domain.get("name").and_then(yw_json::Value::as_str) == Some("Exchange")
        && envelope
            .domain
            .get("chainId")
            .and_then(yw_json::Value::as_number)
            .and_then(yw_json::Number::as_u64)
            == Some(HL_L1_CHAIN_ID);
    let expected = if hl_l1 { HL_L1_CHAIN_ID } else { chain_id };
    let domain = types.domain(envelope.domain, domain_tree, expected)?;
    let schema = recognize(&types, envelope.primary_type, &domain, chain_id)?;
    if expected != chain_id && schema != Some(KnownSchema::HyperliquidL1Agent) {
        return Err(TypedDataError::ChainIdMismatch);
    }
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
    if let Some(schema) = hyperliquid_schema(primary, primary_hash, domain_hash, domain) {
        return Ok(Some(schema));
    }

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
        // The DAI layout is recognized only at the chain's registry DAI (spec/03 §8.2): its
        // `allowed=false` reads as a harmless revocation (T15), which an unknown contract must
        // not borrow.
        let registry_dai = domain.verifying_contract.is_some_and(|address| {
            chain
                .as_ref()
                .and_then(|chain| chain.token(&address))
                .is_some_and(|token| token.role == TokenRole::Dai)
        });
        if primary_hash == TYPEHASH_DAI_PERMIT && registry_dai {
            return Ok(Some(KnownSchema::DaiPermit));
        }
    }
    Ok(None)
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

/// Hyperliquid schemas (spec/11 §7): the standard 4-field domain with a zero verifying contract,
/// and a primary type whose `typeHash` equals the SDK's exactly.
fn hyperliquid_schema(
    primary: &str,
    primary_hash: [u8; 32],
    domain_hash: [u8; 32],
    domain: &TdDomain,
) -> Option<KnownSchema> {
    if domain_hash != TYPEHASH_DOMAIN_4 || domain.verifying_contract.is_some() {
        return None;
    }
    match (domain.name.as_deref(), domain.version.as_deref()) {
        (Some(crate::hypercore::DOMAIN_NAME), Some(crate::hypercore::DOMAIN_VERSION)) => {
            let action = if let Some(kind) = crate::hypercore::HcKind::from_primary_type(primary)
            {
                (primary_hash == kind.type_hash()).then_some(HlUserAction::Transfer(kind))?
            } else if primary_hash == keccak(HL_APPROVE_AGENT_TYPE.as_bytes()) {
                HlUserAction::ApproveAgent
            } else if primary_hash == keccak(HL_APPROVE_BUILDER_FEE_TYPE.as_bytes()) {
                HlUserAction::ApproveBuilderFee
            } else {
                return None;
            };
            Some(KnownSchema::HyperliquidUser(action))
        }
        (Some("Exchange"), Some("1"))
            if primary == "Agent"
                && primary_hash == keccak(HL_AGENT_TYPE.as_bytes())
                && domain.chain_id == Some(U256::from_u64(HL_L1_CHAIN_ID)) =>
        {
            Some(KnownSchema::HyperliquidL1Agent)
        }
        _ => None,
    }
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

#[cfg(test)]
mod tests {
    use yw_json::Limits;

    use super::schema::{Envelope, MAX_ENCODE_TYPE_BYTES, MAX_IDENTIFIER_BYTES, Schema};
    use super::{LimitKind, TypedDataError, validate_typed_data_v4};

    /// A field name of exactly [`MAX_IDENTIFIER_BYTES`].
    fn long_name(index: usize) -> String {
        format!("f{index:03}{}", "x".repeat(MAX_IDENTIFIER_BYTES - 4))
    }

    /// `Big` declares `fields` long-named fields (a large `encodeType`); `Item` reaches it through
    /// an always-empty `Big[]`, and the message is an array of `elements` small `Item`s. Before
    /// the cache every element rebuilt `Item`'s whole `encodeType` (C8).
    fn wide_document(fields: usize, elements: usize) -> String {
        let big = (0..fields)
            .map(|index| format!(r#"{{"name":"{}","type":"uint256"}}"#, long_name(index)))
            .collect::<Vec<_>>()
            .join(",");
        let items = vec![r#"{"a":1,"pad":[]}"#; elements].join(",");
        format!(
            r#"{{"types":{{"EIP712Domain":[{{"name":"chainId","type":"uint256"}}],"Big":[{big}],"Item":[{{"name":"a","type":"uint8"}},{{"name":"pad","type":"Big[]"}}],"Msg":[{{"name":"items","type":"Item[]"}}]}},"primaryType":"Msg","domain":{{"chainId":1}},"message":{{"items":[{items}]}}}}"#
        )
    }

    #[test]
    fn type_hashes_are_computed_once_per_type() {
        // At the dApp request limits (yw-json `Limits::REQUEST`: 4,096 items, 8,192 nodes).
        let source = wide_document(120, 1_200);
        assert!(source.len() > 50_000, "{}", source.len());
        let value = yw_json::parse(source.as_bytes(), &Limits::REQUEST).unwrap();
        let envelope = Envelope::parse(&value).unwrap();
        let types = Schema::parse(envelope.types).unwrap();
        types.validate_graph(envelope.primary_type).unwrap();
        let (_, tree) = types
            .hash_struct_tree(envelope.primary_type, envelope.message, 0)
            .unwrap();
        // 1,201 struct instances, 2 encodeType computations (Msg, Item) — bounded by the number
        // of declared types, not by the number of values.
        assert_eq!(types.encodings(), 2);
        let items = tree.field("items").and_then(super::TdNode::elements);
        assert_eq!(items.map(<[_]>::len), Some(1_200));
        // The whole request validates, and repeating it stays cheap (perf guard: a regression
        // to per-instance encoding makes this loop take tens of seconds in a debug build).
        for _ in 0..20 {
            assert!(validate_typed_data_v4(source.as_bytes(), &value, 1).is_ok());
        }
    }

    #[test]
    fn encode_type_budget_is_enforced() {
        // 12 instantiated types each reaching a ~27 KB declaration: > 262,144 encodeType bytes.
        let big = (0..100)
            .map(|index| format!(r#"{{"name":"{}","type":"uint256"}}"#, long_name(index)))
            .collect::<Vec<_>>()
            .join(",");
        let holders = (0..12)
            .map(|index| format!(r#"{{"name":"t{index}","type":"T{index}"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let referrers = (0..12)
            .map(|index| format!(r#""T{index}":[{{"name":"pad","type":"Big[]"}}]"#))
            .collect::<Vec<_>>()
            .join(",");
        let message = (0..12)
            .map(|index| format!(r#""t{index}":{{"pad":[]}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let source = format!(
            r#"{{"types":{{"EIP712Domain":[],"Big":[{big}],{referrers},"Holder":[{holders}]}},"primaryType":"Holder","domain":{{}},"message":{{{message}}}}}"#
        );
        let value = yw_json::parse(source.as_bytes(), &Limits::REQUEST).unwrap();
        assert_eq!(
            validate_typed_data_v4(source.as_bytes(), &value, 1),
            Err(TypedDataError::LimitExceeded(LimitKind::Types))
        );
        const { assert!(MAX_ENCODE_TYPE_BYTES < 12 * 100 * MAX_IDENTIFIER_BYTES) };
    }
}
