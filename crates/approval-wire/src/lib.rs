//! Canonical, label-free protocol shared by the authorization TCB and the
//! one-shot native approval frontend.
//!
//! Presentation labels deliberately do not exist in this crate. The wire
//! carries only stable semantic tags, exact validated values, and an explicit
//! security-critical bit. The approval frontend is the sole owner of labels.
//!
//! The bootstrap codec fixes frame sizes and order; decoding it is not parent
//! authentication. The Windows child separately validates the live process and
//! PID/session correlation, requires case-preserving exact normalized path-string
//! equality between its image path and a separately held file path, checks the
//! held path's executable suffix and version metadata, and performs held-handle-
//! backed Authenticode and SHA-256 policy checks. Those checks do not prove that the live
//! process was mapped from the exact held file object, nor do pipe PID/session
//! queries create an exact endpoint/process-object capability. The fixed
//! response echoes the request digest and one-shot Approval request nonce, but
//! not either bootstrap nonce, so replay resistance also depends on the private
//! one-shot endpoint and a fresh one-shot Approval request nonce. There are zero
//! production orchestration callers composing the launcher, verified response,
//! and signing, and there is no positive signed-handshake E2E.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use core::fmt;
use sha2::{Digest as _, Sha256};

/// Maximum encoded approval request size.
pub const MAX_REQUEST_BYTES: usize = 32_768;
/// Maximum number of distinct semantic fields in one display.
pub const MAX_FIELDS: usize = 64;
/// Maximum anti-phishing phrase length in UTF-8 bytes.
pub const MAX_PHRASE_BYTES: usize = 64;
/// Maximum relative approval lifetime.
pub const MAX_EXPIRY_MILLISECONDS: u32 = 120_000;
/// Fixed encoded response size.
pub const RESPONSE_BYTES: usize = 75;
/// Exact byte length of the Approval parent bootstrap hello.
pub const PARENT_HELLO_BYTES: usize = 62;
/// Exact byte length of the Approval child bootstrap hello.
pub const CHILD_HELLO_BYTES: usize = 106;
/// Exact byte length before the canonical request in a parent-finish frame.
pub const PARENT_FINISH_HEADER_BYTES: usize = 110;
/// Maximum parent-finish frame, including one maximum-size approval request.
pub const MAX_PARENT_FINISH_BYTES: usize = PARENT_FINISH_HEADER_BYTES + MAX_REQUEST_BYTES;

const REQUEST_MAGIC: &[u8; 8] = b"YWAPPR02";
const RESPONSE_MAGIC: &[u8; 8] = b"YWAPRS02";
const DISPLAY_MAGIC: &[u8; 8] = b"YWAPDS02";
const VERSION: u16 = 2;
const PARENT_HELLO_MAGIC: &[u8; 8] = b"YWAPPH01";
const CHILD_HELLO_MAGIC: &[u8; 8] = b"YWAPCH01";
const PARENT_FINISH_MAGIC: &[u8; 8] = b"YWAPPF01";
const BOOTSTRAP_VERSION: u16 = 1;
const CHILD_HELLO_TRANSCRIPT_DOMAIN: &[u8] = b"your-wallet/approval-bootstrap-child/v1\0";

/// Approval-wire validation or decoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    /// Framing, tags, ordering, shape, or a required invariant is invalid.
    Malformed,
    /// Text is empty, over its semantic bound, padded, or visually unsafe.
    InvalidText,
    /// The encoded request exceeds its fixed aggregate bound.
    TooLarge,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => formatter.write_str("malformed approval wire value"),
            Self::InvalidText => formatter.write_str("invalid approval display text"),
            Self::TooLarge => formatter.write_str("approval wire value exceeds its bound"),
        }
    }
}

impl std::error::Error for WireError {}

/// Fixed parent identity and nonce for one Approval bootstrap exchange.
///
/// The numeric handles name only the two non-inheritable proof objects already
/// injected into the suspended child. Decoding this value does not itself
/// authenticate either object; the child-side Windows boundary must validate
/// their types and attributes, correlate the process and pipe PID/session, and
/// apply policy to the separately held image file. The current path correlation
/// and held-file checks do not prove the live mapped exact file object.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ApprovalParentHello {
    process_id: u32,
    process_handle: u64,
    image_handle: u64,
    parent_nonce: [u8; 32],
}

impl ApprovalParentHello {
    /// Constructs one bounded parent hello.
    pub fn new(
        process_id: u32,
        process_handle: u64,
        image_handle: u64,
        parent_nonce: [u8; 32],
    ) -> Result<Self, WireError> {
        if process_id == 0
            || process_handle == 0
            || image_handle == 0
            || process_handle == image_handle
            || all_zero(&parent_nonce)
        {
            return Err(WireError::Malformed);
        }
        Ok(Self {
            process_id,
            process_handle,
            image_handle,
            parent_nonce,
        })
    }

    /// Parent process identifier bound into this exchange.
    #[must_use]
    pub const fn process_id(self) -> u32 {
        self.process_id
    }

    /// Child-local value naming the injected parent process handle.
    #[must_use]
    pub const fn process_handle(self) -> u64 {
        self.process_handle
    }

    /// Child-local value naming the injected parent image-file handle.
    #[must_use]
    pub const fn image_handle(self) -> u64 {
        self.image_handle
    }

    /// Fresh parent nonce for this one bootstrap exchange.
    #[must_use]
    pub const fn parent_nonce(self) -> [u8; 32] {
        self.parent_nonce
    }
}

impl fmt::Debug for ApprovalParentHello {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApprovalParentHello([REDACTED HANDLES AND NONCE])")
    }
}

/// Fresh child nonce accepted only through one parent-bound child hello.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ApprovalChildHello {
    child_nonce: [u8; 32],
}

impl ApprovalChildHello {
    /// Constructs the child half of one bootstrap exchange.
    pub fn new(child_nonce: [u8; 32]) -> Result<Self, WireError> {
        if all_zero(&child_nonce) {
            return Err(WireError::Malformed);
        }
        Ok(Self { child_nonce })
    }

    /// Fresh child nonce for this one bootstrap exchange.
    #[must_use]
    pub const fn child_nonce(self) -> [u8; 32] {
        self.child_nonce
    }
}

impl fmt::Debug for ApprovalChildHello {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApprovalChildHello([REDACTED NONCE])")
    }
}

/// Whether confirmation requires a continuous trusted-input hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RiskLevel {
    /// No elevated warning is present.
    Standard,
    /// At least one elevated warning requires a continuous hold.
    High,
}

impl RiskLevel {
    const fn tag(self) -> u8 {
        match self {
            Self::Standard => 0,
            Self::High => 1,
        }
    }

    const fn from_tag(tag: u8) -> Result<Self, WireError> {
        match tag {
            0 => Ok(Self::Standard),
            1 => Ok(Self::High),
            _ => Err(WireError::Malformed),
        }
    }
}

/// Fixed operation kinds rendered by the native frontend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    /// EIP-155 legacy transaction.
    LegacyEip155,
    /// EIP-2930 access-list transaction.
    AccessListEip2930,
    /// EIP-1559 dynamic-fee transaction.
    DynamicFeeEip1559,
    /// EIP-191 personal message.
    PersonalMessage,
}

impl OperationKind {
    /// Exact value carried for the operation-kind semantic.
    #[must_use]
    pub const fn value(self) -> &'static str {
        match self {
            Self::LegacyEip155 => "Legacy EIP-155 transaction",
            Self::AccessListEip2930 => "EIP-2930 access-list transaction",
            Self::DynamicFeeEip1559 => "EIP-1559 dynamic-fee transaction",
            Self::PersonalMessage => "EIP-191 personal message",
        }
    }

    fn from_value(value: &str) -> Result<Self, WireError> {
        match value {
            "Legacy EIP-155 transaction" => Ok(Self::LegacyEip155),
            "EIP-2930 access-list transaction" => Ok(Self::AccessListEip2930),
            "EIP-1559 dynamic-fee transaction" => Ok(Self::DynamicFeeEip1559),
            "EIP-191 personal message" => Ok(Self::PersonalMessage),
            _ => Err(WireError::Malformed),
        }
    }
}

/// Fixed simulation states rendered by the native frontend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulationStatus {
    /// No simulation was performed.
    NotPerformed,
    /// A simulation result and its exact provenance digests are present.
    Performed,
}

impl SimulationStatus {
    /// Exact value carried for the simulation-status semantic.
    #[must_use]
    pub const fn value(self) -> &'static str {
        match self {
            Self::NotPerformed => "Not performed",
            Self::Performed => "Performed",
        }
    }

    fn from_value(value: &str) -> Result<Self, WireError> {
        match value {
            "Not performed" => Ok(Self::NotPerformed),
            "Performed" => Ok(Self::Performed),
            _ => Err(WireError::Malformed),
        }
    }
}

/// Stable semantic field tags. Labels are intentionally frontend-only.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum FieldSemantic {
    /// Browser-reported top-level origin.
    Origin = 1,
    /// Explicit origin provenance limitation.
    OriginProvenance = 2,
    /// Signing account.
    Account = 3,
    /// Registry-owned network name.
    NetworkName = 4,
    /// Exact EVM chain identifier.
    ChainId = 5,
    /// Pinned genesis hash.
    GenesisHash = 6,
    /// Exact rule-set revision digest.
    RulesetRevision = 7,
    /// Fixed operation kind.
    OperationKind = 8,
    /// Exact transaction envelope number.
    EnvelopeType = 9,
    /// Exact account nonce.
    Nonce = 10,
    /// Transaction recipient or contract-creation marker.
    Target = 11,
    /// Native value in exact base units.
    NativeValue = 12,
    /// Exact gas limit.
    GasLimit = 13,
    /// Legacy/type-1 gas price.
    GasPrice = 14,
    /// Type-2 maximum priority fee per gas.
    MaxPriorityFeePerGas = 15,
    /// Type-2 maximum fee per gas.
    MaxFeePerGas = 16,
    /// Exact maximum total network fee.
    MaximumNetworkFee = 17,
    /// Complete calldata bytes.
    Calldata = 18,
    /// Keccak-256 of the complete calldata bytes.
    CalldataKeccak256 = 19,
    /// Complete canonical access-list presentation.
    AccessList = 20,
    /// Complete personal-message bytes.
    PersonalMessageBytes = 21,
    /// Whether simulation was performed.
    SimulationStatus = 22,
    /// Simulation engine identifier.
    SimulationEngine = 23,
    /// Digest of the canonical simulation result.
    SimulationResultDigest = 24,
    /// Digest of the simulation RPC/block inputs.
    SimulationInputDigest = 25,
    /// Browser-origin provenance warning.
    OriginWarning = 26,
    /// Personal-signature replay/interpretation warning.
    PersonalMessageWarning = 27,
    /// No-simulation warning.
    NoSimulationWarning = 28,
    /// Unknown-calldata warning.
    UnknownCalldataWarning = 29,
    /// Incomplete protocol/finality coverage warning.
    ProtocolCoverageWarning = 30,
    /// Digest of canonical RPC observations used to prepare the operation.
    RpcObservationsDigest = 31,
}

impl FieldSemantic {
    /// Stable one-byte wire tag.
    #[must_use]
    pub const fn wire_tag(self) -> u8 {
        self as u8
    }

    /// Decodes a stable one-byte tag.
    pub const fn from_wire_tag(tag: u8) -> Result<Self, WireError> {
        match tag {
            1 => Ok(Self::Origin),
            2 => Ok(Self::OriginProvenance),
            3 => Ok(Self::Account),
            4 => Ok(Self::NetworkName),
            5 => Ok(Self::ChainId),
            6 => Ok(Self::GenesisHash),
            7 => Ok(Self::RulesetRevision),
            8 => Ok(Self::OperationKind),
            9 => Ok(Self::EnvelopeType),
            10 => Ok(Self::Nonce),
            11 => Ok(Self::Target),
            12 => Ok(Self::NativeValue),
            13 => Ok(Self::GasLimit),
            14 => Ok(Self::GasPrice),
            15 => Ok(Self::MaxPriorityFeePerGas),
            16 => Ok(Self::MaxFeePerGas),
            17 => Ok(Self::MaximumNetworkFee),
            18 => Ok(Self::Calldata),
            19 => Ok(Self::CalldataKeccak256),
            20 => Ok(Self::AccessList),
            21 => Ok(Self::PersonalMessageBytes),
            22 => Ok(Self::SimulationStatus),
            23 => Ok(Self::SimulationEngine),
            24 => Ok(Self::SimulationResultDigest),
            25 => Ok(Self::SimulationInputDigest),
            26 => Ok(Self::OriginWarning),
            27 => Ok(Self::PersonalMessageWarning),
            28 => Ok(Self::NoSimulationWarning),
            29 => Ok(Self::UnknownCalldataWarning),
            30 => Ok(Self::ProtocolCoverageWarning),
            31 => Ok(Self::RpcObservationsDigest),
            _ => Err(WireError::Malformed),
        }
    }

    const fn bit(self) -> u64 {
        1_u64 << (self as u8 - 1)
    }

    const fn maximum_value_bytes(self) -> usize {
        match self {
            Self::NetworkName
            | Self::OriginProvenance
            | Self::OperationKind
            | Self::SimulationStatus
            | Self::SimulationEngine => 512,
            Self::Account
            | Self::Target
            | Self::ChainId
            | Self::EnvelopeType
            | Self::Nonce
            | Self::NativeValue
            | Self::GasLimit
            | Self::GasPrice
            | Self::MaxPriorityFeePerGas
            | Self::MaxFeePerGas
            | Self::MaximumNetworkFee
            | Self::GenesisHash
            | Self::RulesetRevision
            | Self::CalldataKeccak256
            | Self::SimulationResultDigest
            | Self::SimulationInputDigest
            | Self::RpcObservationsDigest => 160,
            Self::Calldata | Self::AccessList | Self::PersonalMessageBytes => 16_384,
            Self::Origin
            | Self::OriginWarning
            | Self::PersonalMessageWarning
            | Self::NoSimulationWarning
            | Self::UnknownCalldataWarning
            | Self::ProtocolCoverageWarning => 2_048,
        }
    }

    const fn expected_security_critical(self) -> bool {
        !matches!(self, Self::SimulationEngine)
    }
}

/// One exact, label-free display value.
#[derive(Clone, Eq, PartialEq)]
pub struct DisplayField {
    semantic: FieldSemantic,
    value: String,
    security_critical: bool,
}

impl core::fmt::Debug for DisplayField {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DisplayField")
            .field("semantic", &self.semantic)
            .field("value", &"[REDACTED]")
            .field("value_bytes", &self.value.len())
            .field("security_critical", &self.security_critical)
            .finish()
    }
}

impl DisplayField {
    /// Creates one bounded, spoof-resistant semantic value.
    pub fn new(
        semantic: FieldSemantic,
        value: impl Into<String>,
        security_critical: bool,
    ) -> Result<Self, WireError> {
        let value = value.into();
        validate_text(&value, semantic.maximum_value_bytes())?;
        if security_critical != semantic.expected_security_critical() {
            return Err(WireError::Malformed);
        }
        Ok(Self {
            semantic,
            value,
            security_critical,
        })
    }

    /// Semantic tag used by the frontend to select its own label.
    #[must_use]
    pub const fn semantic(&self) -> FieldSemantic {
        self.semantic
    }

    /// Exact plain-text value. It must never be interpreted as markup.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Whether omission or truncation changes the security decision.
    #[must_use]
    pub const fn security_critical(&self) -> bool {
        self.security_critical
    }
}

/// Complete canonical display model bound into an approval digest.
#[derive(Clone, Eq, PartialEq)]
pub struct ApprovalDisplay {
    risk: RiskLevel,
    fields: Vec<DisplayField>,
}

impl core::fmt::Debug for ApprovalDisplay {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ApprovalDisplay")
            .field("risk", &self.risk)
            .field("fields", &"[REDACTED]")
            .field("field_count", &self.fields.len())
            .finish()
    }
}

impl ApprovalDisplay {
    /// Validates and canonicalizes a complete operation display.
    pub fn new(risk: RiskLevel, mut fields: Vec<DisplayField>) -> Result<Self, WireError> {
        fields.sort_unstable_by_key(|field| field.semantic);
        let display = Self { risk, fields };
        display.validate()?;
        Ok(display)
    }

    /// Risk level enforced by the one-shot native interaction.
    #[must_use]
    pub const fn risk(&self) -> RiskLevel {
        self.risk
    }

    /// Canonically ordered exact fields.
    #[must_use]
    pub fn fields(&self) -> &[DisplayField] {
        &self.fields
    }

    /// Returns a field by semantic tag.
    #[must_use]
    pub fn field(&self, semantic: FieldSemantic) -> Option<&DisplayField> {
        self.fields
            .binary_search_by_key(&semantic, |field| field.semantic)
            .ok()
            .and_then(|index| self.fields.get(index))
    }

    /// Stable label-free bytes used by the approval digest.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(encoded_display_size(self));
        bytes.extend_from_slice(DISPLAY_MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.push(self.risk.tag());
        bytes.push(u8::try_from(self.fields.len()).unwrap_or(u8::MAX));
        encode_fields(&mut bytes, &self.fields);
        bytes
    }

    fn validate(&self) -> Result<(), WireError> {
        if self.fields.is_empty() || self.fields.len() > MAX_FIELDS {
            return Err(WireError::Malformed);
        }
        let mut seen = 0_u64;
        let mut previous = None;
        for field in &self.fields {
            if previous.is_some_and(|semantic| semantic >= field.semantic) {
                return Err(WireError::Malformed);
            }
            previous = Some(field.semantic);
            let bit = field.semantic.bit();
            if seen & bit != 0
                || field.security_critical != field.semantic.expected_security_critical()
            {
                return Err(WireError::Malformed);
            }
            validate_text(&field.value, field.semantic.maximum_value_bytes())?;
            seen |= bit;
        }

        require(
            seen,
            &[
                FieldSemantic::Origin,
                FieldSemantic::OriginProvenance,
                FieldSemantic::Account,
                FieldSemantic::NetworkName,
                FieldSemantic::ChainId,
                FieldSemantic::GenesisHash,
                FieldSemantic::RulesetRevision,
                FieldSemantic::RpcObservationsDigest,
                FieldSemantic::OperationKind,
                FieldSemantic::SimulationStatus,
                FieldSemantic::OriginWarning,
            ],
        )?;
        let operation = OperationKind::from_value(self.value(FieldSemantic::OperationKind)?)?;
        self.validate_operation(seen, operation)?;
        self.validate_simulation(seen)?;
        self.validate_risk(seen)
    }

    fn validate_operation(&self, seen: u64, operation: OperationKind) -> Result<(), WireError> {
        const TRANSACTION_BASE: &[FieldSemantic] = &[
            FieldSemantic::EnvelopeType,
            FieldSemantic::Nonce,
            FieldSemantic::Target,
            FieldSemantic::NativeValue,
            FieldSemantic::GasLimit,
            FieldSemantic::MaximumNetworkFee,
            FieldSemantic::Calldata,
            FieldSemantic::CalldataKeccak256,
        ];
        match operation {
            OperationKind::LegacyEip155 => {
                require(seen, TRANSACTION_BASE)?;
                require(seen, &[FieldSemantic::GasPrice])?;
                forbid(
                    seen,
                    &[
                        FieldSemantic::MaxPriorityFeePerGas,
                        FieldSemantic::MaxFeePerGas,
                        FieldSemantic::AccessList,
                        FieldSemantic::PersonalMessageBytes,
                        FieldSemantic::PersonalMessageWarning,
                    ],
                )?;
                require_value(self, FieldSemantic::EnvelopeType, "0")
            }
            OperationKind::AccessListEip2930 => {
                require(seen, TRANSACTION_BASE)?;
                require(seen, &[FieldSemantic::GasPrice, FieldSemantic::AccessList])?;
                forbid(
                    seen,
                    &[
                        FieldSemantic::MaxPriorityFeePerGas,
                        FieldSemantic::MaxFeePerGas,
                        FieldSemantic::PersonalMessageBytes,
                        FieldSemantic::PersonalMessageWarning,
                    ],
                )?;
                require_value(self, FieldSemantic::EnvelopeType, "1")
            }
            OperationKind::DynamicFeeEip1559 => {
                require(seen, TRANSACTION_BASE)?;
                require(
                    seen,
                    &[
                        FieldSemantic::MaxPriorityFeePerGas,
                        FieldSemantic::MaxFeePerGas,
                        FieldSemantic::AccessList,
                    ],
                )?;
                forbid(
                    seen,
                    &[
                        FieldSemantic::GasPrice,
                        FieldSemantic::PersonalMessageBytes,
                        FieldSemantic::PersonalMessageWarning,
                    ],
                )?;
                require_value(self, FieldSemantic::EnvelopeType, "2")
            }
            OperationKind::PersonalMessage => {
                require(
                    seen,
                    &[
                        FieldSemantic::PersonalMessageBytes,
                        FieldSemantic::PersonalMessageWarning,
                    ],
                )?;
                forbid(
                    seen,
                    &[
                        FieldSemantic::EnvelopeType,
                        FieldSemantic::Nonce,
                        FieldSemantic::Target,
                        FieldSemantic::NativeValue,
                        FieldSemantic::GasLimit,
                        FieldSemantic::GasPrice,
                        FieldSemantic::MaxPriorityFeePerGas,
                        FieldSemantic::MaxFeePerGas,
                        FieldSemantic::MaximumNetworkFee,
                        FieldSemantic::Calldata,
                        FieldSemantic::CalldataKeccak256,
                        FieldSemantic::AccessList,
                        FieldSemantic::UnknownCalldataWarning,
                    ],
                )
            }
        }
    }

    fn validate_simulation(&self, seen: u64) -> Result<(), WireError> {
        match SimulationStatus::from_value(self.value(FieldSemantic::SimulationStatus)?)? {
            SimulationStatus::NotPerformed => {
                require(seen, &[FieldSemantic::NoSimulationWarning])?;
                forbid(
                    seen,
                    &[
                        FieldSemantic::SimulationEngine,
                        FieldSemantic::SimulationResultDigest,
                        FieldSemantic::SimulationInputDigest,
                    ],
                )
            }
            SimulationStatus::Performed => {
                require(
                    seen,
                    &[
                        FieldSemantic::SimulationEngine,
                        FieldSemantic::SimulationResultDigest,
                        FieldSemantic::SimulationInputDigest,
                    ],
                )?;
                forbid(seen, &[FieldSemantic::NoSimulationWarning])
            }
        }
    }

    fn validate_risk(&self, seen: u64) -> Result<(), WireError> {
        let elevated = [
            FieldSemantic::PersonalMessageWarning,
            FieldSemantic::NoSimulationWarning,
            FieldSemantic::UnknownCalldataWarning,
            FieldSemantic::ProtocolCoverageWarning,
        ]
        .iter()
        .any(|semantic| seen & semantic.bit() != 0);
        if (self.risk == RiskLevel::High) == elevated {
            Ok(())
        } else {
            Err(WireError::Malformed)
        }
    }

    fn value(&self, semantic: FieldSemantic) -> Result<&str, WireError> {
        self.field(semantic)
            .map(DisplayField::value)
            .ok_or(WireError::Malformed)
    }
}

/// Complete one-shot request sent over the inherited private helper channel.
#[derive(Clone, Eq, PartialEq)]
pub struct ApprovalRequest {
    digest: [u8; 32],
    approval_nonce: [u8; 32],
    expires_after_milliseconds: u32,
    anti_phishing_phrase: String,
    display: ApprovalDisplay,
}

impl core::fmt::Debug for ApprovalRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ApprovalRequest")
            .field("digest", &"[SHA-256]")
            .field("approval_nonce", &"[NONCE]")
            .field(
                "expires_after_milliseconds",
                &self.expires_after_milliseconds,
            )
            .field("anti_phishing_phrase", &"[REDACTED]")
            .field("display", &"[CANONICAL DISPLAY REDACTED]")
            .finish()
    }
}

impl ApprovalRequest {
    /// Creates an exact bounded request.
    pub fn new(
        digest: [u8; 32],
        approval_nonce: [u8; 32],
        expires_after_milliseconds: u32,
        anti_phishing_phrase: impl Into<String>,
        display: ApprovalDisplay,
    ) -> Result<Self, WireError> {
        let anti_phishing_phrase = anti_phishing_phrase.into();
        if all_zero(&digest)
            || all_zero(&approval_nonce)
            || !(1..=MAX_EXPIRY_MILLISECONDS).contains(&expires_after_milliseconds)
        {
            return Err(WireError::Malformed);
        }
        validate_text(&anti_phishing_phrase, MAX_PHRASE_BYTES)?;
        display.validate()?;
        let request = Self {
            digest,
            approval_nonce,
            expires_after_milliseconds,
            anti_phishing_phrase,
            display,
        };
        if encoded_request_size(&request) > MAX_REQUEST_BYTES {
            return Err(WireError::TooLarge);
        }
        Ok(request)
    }

    /// Exact authorization digest echoed by the response.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Exact one-shot challenge nonce echoed by the response.
    #[must_use]
    pub const fn approval_nonce(&self) -> &[u8; 32] {
        &self.approval_nonce
    }

    /// Exact bounded relative UI lifetime in milliseconds.
    #[must_use]
    pub const fn expires_after_milliseconds(&self) -> u32 {
        self.expires_after_milliseconds
    }

    /// Locally selected anti-phishing phrase.
    #[must_use]
    pub fn anti_phishing_phrase(&self) -> &str {
        &self.anti_phishing_phrase
    }

    /// Canonical label-free display.
    #[must_use]
    pub const fn display(&self) -> &ApprovalDisplay {
        &self.display
    }
}

/// One-shot approval result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    /// Approve the exact digest and nonce once.
    Approve,
    /// Reject the exact digest and nonce.
    Reject,
}

impl Decision {
    const fn tag(self) -> u8 {
        match self {
            Self::Reject => 0,
            Self::Approve => 1,
        }
    }

    const fn from_tag(tag: u8) -> Result<Self, WireError> {
        match tag {
            0 => Ok(Self::Reject),
            1 => Ok(Self::Approve),
            _ => Err(WireError::Malformed),
        }
    }
}

/// Fixed response echoed to the Key Agent for exact binding.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ApprovalResponse {
    decision: Decision,
    digest: [u8; 32],
    approval_nonce: [u8; 32],
}

impl core::fmt::Debug for ApprovalResponse {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ApprovalResponse")
            .field("decision", &self.decision)
            .field("digest", &"[REDACTED]")
            .field("approval_nonce", &"[REDACTED]")
            .finish()
    }
}

impl ApprovalResponse {
    /// Creates a response bound to a validated request.
    #[must_use]
    pub const fn for_request(decision: Decision, request: &ApprovalRequest) -> Self {
        Self {
            decision,
            digest: request.digest,
            approval_nonce: request.approval_nonce,
        }
    }

    /// User decision.
    #[must_use]
    pub const fn decision(self) -> Decision {
        self.decision
    }

    /// Exact request digest.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Exact request nonce.
    #[must_use]
    pub const fn approval_nonce(&self) -> &[u8; 32] {
        &self.approval_nonce
    }
}

/// Encodes one validated request in the only accepted v2 format.
#[must_use]
pub fn encode_request(request: &ApprovalRequest) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(encoded_request_size(request));
    bytes.extend_from_slice(REQUEST_MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&request.digest);
    bytes.extend_from_slice(&request.approval_nonce);
    bytes.extend_from_slice(&request.expires_after_milliseconds.to_be_bytes());
    bytes.push(request.display.risk.tag());
    encode_text(&mut bytes, &request.anti_phishing_phrase);
    bytes.push(u8::try_from(request.display.fields.len()).unwrap_or(u8::MAX));
    encode_fields(&mut bytes, &request.display.fields);
    bytes
}

/// Domain-separated SHA-256 of the complete canonical approval request.
///
/// This binds the digest/nonce, relative lifetime, anti-phishing phrase, risk,
/// and every exact display semantic/value. Authorization must compare this
/// value with the Key Agent's internally built request before accepting a UI
/// response.
#[must_use]
pub fn request_hash(request: &ApprovalRequest) -> [u8; 32] {
    const DOMAIN: &[u8] = b"your-wallet/approval-request-hash/v2";
    let encoded = encode_request(request);
    let mut digest = Sha256::new();
    digest.update(
        u32::try_from(DOMAIN.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    digest.update(DOMAIN);
    digest.update(
        u32::try_from(encoded.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    digest.update(encoded);
    digest.finalize().into()
}

/// Decodes and validates one complete v2 request with no trailing bytes.
pub fn decode_request(bytes: &[u8]) -> Result<ApprovalRequest, WireError> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(WireError::TooLarge);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(8)? != REQUEST_MAGIC || cursor.u16()? != VERSION {
        return Err(WireError::Malformed);
    }
    let digest = cursor.array()?;
    let approval_nonce = cursor.array()?;
    let expires_after_milliseconds = cursor.u32()?;
    let risk = RiskLevel::from_tag(cursor.u8()?)?;
    let anti_phishing_phrase = cursor.text(MAX_PHRASE_BYTES)?;
    let field_count = usize::from(cursor.u8()?);
    if field_count == 0 || field_count > MAX_FIELDS {
        return Err(WireError::Malformed);
    }
    let mut fields = Vec::with_capacity(field_count);
    let mut previous = None;
    for _ in 0..field_count {
        let semantic = FieldSemantic::from_wire_tag(cursor.u8()?)?;
        if previous.is_some_and(|value| value >= semantic) {
            return Err(WireError::Malformed);
        }
        previous = Some(semantic);
        let security_critical = match cursor.u8()? {
            0 => false,
            1 => true,
            _ => return Err(WireError::Malformed),
        };
        let value = cursor.text(semantic.maximum_value_bytes())?;
        fields.push(DisplayField::new(semantic, value, security_critical)?);
    }
    if !cursor.is_empty() {
        return Err(WireError::Malformed);
    }
    ApprovalRequest::new(
        digest,
        approval_nonce,
        expires_after_milliseconds,
        anti_phishing_phrase,
        ApprovalDisplay::new(risk, fields)?,
    )
}

/// Encodes the fixed v2 response.
#[must_use]
pub fn encode_response(response: ApprovalResponse) -> [u8; RESPONSE_BYTES] {
    let mut bytes = [0_u8; RESPONSE_BYTES];
    bytes[..8].copy_from_slice(RESPONSE_MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[10] = response.decision.tag();
    bytes[11..43].copy_from_slice(&response.digest);
    bytes[43..75].copy_from_slice(&response.approval_nonce);
    bytes
}

/// Decodes the fixed v2 response with no alternate or trailing shape.
pub fn decode_response(bytes: &[u8]) -> Result<ApprovalResponse, WireError> {
    if bytes.len() != RESPONSE_BYTES
        || bytes.get(..8) != Some(RESPONSE_MAGIC)
        || bytes.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
    {
        return Err(WireError::Malformed);
    }
    let decision = Decision::from_tag(bytes[10])?;
    let digest = bytes[11..43].try_into().map_err(|_| WireError::Malformed)?;
    let approval_nonce = bytes[43..75].try_into().map_err(|_| WireError::Malformed)?;
    if all_zero(&digest) || all_zero(&approval_nonce) {
        return Err(WireError::Malformed);
    }
    Ok(ApprovalResponse {
        decision,
        digest,
        approval_nonce,
    })
}

/// Encodes one exact Approval parent bootstrap hello.
#[must_use]
pub fn encode_parent_hello(hello: &ApprovalParentHello) -> [u8; PARENT_HELLO_BYTES] {
    let mut bytes = [0_u8; PARENT_HELLO_BYTES];
    bytes[..8].copy_from_slice(PARENT_HELLO_MAGIC);
    bytes[8..10].copy_from_slice(&BOOTSTRAP_VERSION.to_be_bytes());
    bytes[10..14].copy_from_slice(&hello.process_id.to_be_bytes());
    bytes[14..22].copy_from_slice(&hello.process_handle.to_be_bytes());
    bytes[22..30].copy_from_slice(&hello.image_handle.to_be_bytes());
    bytes[30..62].copy_from_slice(&hello.parent_nonce);
    bytes
}

/// Decodes one complete Approval parent bootstrap hello with no trailing bytes.
pub fn decode_parent_hello(bytes: &[u8]) -> Result<ApprovalParentHello, WireError> {
    if bytes.len() != PARENT_HELLO_BYTES {
        return Err(WireError::Malformed);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(8)? != PARENT_HELLO_MAGIC || cursor.u16()? != BOOTSTRAP_VERSION {
        return Err(WireError::Malformed);
    }
    let hello =
        ApprovalParentHello::new(cursor.u32()?, cursor.u64()?, cursor.u64()?, cursor.array()?)?;
    if !cursor.is_empty() {
        return Err(WireError::Malformed);
    }
    Ok(hello)
}

/// Encodes one child hello bound to the exact parent hello and child nonce.
#[must_use]
pub fn encode_child_hello(
    parent: &ApprovalParentHello,
    child: &ApprovalChildHello,
) -> [u8; CHILD_HELLO_BYTES] {
    let mut bytes = [0_u8; CHILD_HELLO_BYTES];
    bytes[..8].copy_from_slice(CHILD_HELLO_MAGIC);
    bytes[8..10].copy_from_slice(&BOOTSTRAP_VERSION.to_be_bytes());
    bytes[10..42].copy_from_slice(&parent.parent_nonce);
    bytes[42..74].copy_from_slice(&child.child_nonce);
    bytes[74..106].copy_from_slice(&child_hello_transcript(parent, &child.child_nonce));
    bytes
}

/// Decodes one complete child hello only for the supplied parent hello.
pub fn decode_child_hello(
    parent: &ApprovalParentHello,
    bytes: &[u8],
) -> Result<ApprovalChildHello, WireError> {
    if bytes.len() != CHILD_HELLO_BYTES {
        return Err(WireError::Malformed);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(8)? != CHILD_HELLO_MAGIC || cursor.u16()? != BOOTSTRAP_VERSION {
        return Err(WireError::Malformed);
    }
    let echoed_parent_nonce: [u8; 32] = cursor.array()?;
    let child_nonce: [u8; 32] = cursor.array()?;
    let transcript: [u8; 32] = cursor.array()?;
    if !cursor.is_empty()
        || echoed_parent_nonce != parent.parent_nonce
        || transcript != child_hello_transcript(parent, &child_nonce)
    {
        return Err(WireError::Malformed);
    }
    ApprovalChildHello::new(child_nonce)
}

/// Encodes the exact parent finish that commits one canonical approval request.
#[must_use]
pub fn encode_parent_finish(
    parent: &ApprovalParentHello,
    child: &ApprovalChildHello,
    request: &ApprovalRequest,
) -> Vec<u8> {
    let request_bytes = encode_request(request);
    let mut bytes = Vec::with_capacity(PARENT_FINISH_HEADER_BYTES + request_bytes.len());
    bytes.extend_from_slice(PARENT_FINISH_MAGIC);
    bytes.extend_from_slice(&BOOTSTRAP_VERSION.to_be_bytes());
    bytes.extend_from_slice(&parent.parent_nonce);
    bytes.extend_from_slice(&child.child_nonce);
    bytes.extend_from_slice(&request_hash(request));
    bytes.extend_from_slice(
        &u32::try_from(request_bytes.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&request_bytes);
    bytes
}

/// Decodes one exact parent finish for the supplied parent and child hellos.
pub fn decode_parent_finish(
    parent: &ApprovalParentHello,
    child: &ApprovalChildHello,
    bytes: &[u8],
) -> Result<ApprovalRequest, WireError> {
    if bytes.len() > MAX_PARENT_FINISH_BYTES {
        return Err(WireError::TooLarge);
    }
    if bytes.len() < PARENT_FINISH_HEADER_BYTES {
        return Err(WireError::Malformed);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(8)? != PARENT_FINISH_MAGIC || cursor.u16()? != BOOTSTRAP_VERSION {
        return Err(WireError::Malformed);
    }
    let encoded_parent_nonce: [u8; 32] = cursor.array()?;
    let encoded_child_nonce: [u8; 32] = cursor.array()?;
    let encoded_request_hash: [u8; 32] = cursor.array()?;
    let request_length = usize::try_from(cursor.u32()?).map_err(|_| WireError::Malformed)?;
    if request_length > MAX_REQUEST_BYTES {
        return Err(WireError::TooLarge);
    }
    let request_bytes = cursor.take(request_length)?;
    if !cursor.is_empty()
        || encoded_parent_nonce != parent.parent_nonce
        || encoded_child_nonce != child.child_nonce
    {
        return Err(WireError::Malformed);
    }
    let request = decode_request(request_bytes)?;
    if encoded_request_hash != request_hash(&request)
        || encode_request(&request).as_slice() != request_bytes
    {
        return Err(WireError::Malformed);
    }
    Ok(request)
}

fn child_hello_transcript(parent: &ApprovalParentHello, child_nonce: &[u8; 32]) -> [u8; 32] {
    let parent_bytes = encode_parent_hello(parent);
    let mut transcript = Sha256::new();
    transcript.update(CHILD_HELLO_TRANSCRIPT_DOMAIN);
    transcript.update(parent_bytes);
    transcript.update(child_nonce);
    transcript.finalize().into()
}

fn require(seen: u64, semantics: &[FieldSemantic]) -> Result<(), WireError> {
    if semantics.iter().all(|semantic| seen & semantic.bit() != 0) {
        Ok(())
    } else {
        Err(WireError::Malformed)
    }
}

fn forbid(seen: u64, semantics: &[FieldSemantic]) -> Result<(), WireError> {
    if semantics.iter().all(|semantic| seen & semantic.bit() == 0) {
        Ok(())
    } else {
        Err(WireError::Malformed)
    }
}

fn require_value(
    display: &ApprovalDisplay,
    semantic: FieldSemantic,
    expected: &str,
) -> Result<(), WireError> {
    if display.value(semantic)? == expected {
        Ok(())
    } else {
        Err(WireError::Malformed)
    }
}

fn encode_fields(bytes: &mut Vec<u8>, fields: &[DisplayField]) {
    for field in fields {
        bytes.push(field.semantic.wire_tag());
        bytes.push(u8::from(field.security_critical));
        encode_text(bytes, &field.value);
    }
}

fn encode_text(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn encoded_display_size(display: &ApprovalDisplay) -> usize {
    display.fields.iter().fold(12_usize, |size, field| {
        size.saturating_add(1 + 1 + 2 + field.value.len())
    })
}

fn encoded_request_size(request: &ApprovalRequest) -> usize {
    request.display.fields.iter().fold(
        8 + 2 + 32 + 32 + 4 + 1 + 2 + request.anti_phishing_phrase.len() + 1,
        |size, field| size.saturating_add(1 + 1 + 2 + field.value.len()),
    )
}

fn validate_text(text: &str, maximum: usize) -> Result<(), WireError> {
    if text.is_empty()
        || text.len() > maximum
        || text.trim() != text
        || text.chars().any(is_forbidden_display_character)
    {
        return Err(WireError::InvalidText);
    }
    Ok(())
}

fn is_forbidden_display_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00AD}'
                | '\u{034F}'
                | '\u{061C}'
                | '\u{115F}'
                | '\u{1160}'
                | '\u{17B4}'..='\u{17B5}'
                | '\u{180B}'..='\u{180F}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{3164}'
                | '\u{FE00}'..='\u{FE0F}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0000}'..='\u{E0FFF}'
        )
}

fn all_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[derive(Clone, Copy)]
struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], WireError> {
        if self.remaining.len() < count {
            return Err(WireError::Malformed);
        }
        let (value, remaining) = self.remaining.split_at(count);
        self.remaining = remaining;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        self.take(N)?.try_into().map_err(|_| WireError::Malformed)
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        self.take(1)?.first().copied().ok_or(WireError::Malformed)
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn text(&mut self, maximum: usize) -> Result<String, WireError> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > maximum {
            return Err(WireError::InvalidText);
        }
        let text = std::str::from_utf8(self.take(length)?).map_err(|_| WireError::InvalidText)?;
        validate_text(text, maximum)?;
        Ok(text.to_owned())
    }

    const fn is_empty(self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::{
        ApprovalChildHello, ApprovalDisplay, ApprovalParentHello, ApprovalRequest,
        ApprovalResponse, CHILD_HELLO_BYTES, CHILD_HELLO_MAGIC, Decision, DisplayField,
        FieldSemantic, MAX_PARENT_FINISH_BYTES, MAX_REQUEST_BYTES, OperationKind,
        PARENT_FINISH_HEADER_BYTES, PARENT_FINISH_MAGIC, PARENT_HELLO_BYTES, PARENT_HELLO_MAGIC,
        RiskLevel, SimulationStatus, WireError, decode_child_hello, decode_parent_finish,
        decode_parent_hello, decode_request, decode_response, encode_child_hello,
        encode_parent_finish, encode_parent_hello, encode_request, encode_response, request_hash,
    };

    fn field(semantic: FieldSemantic, value: &str) -> Result<DisplayField, WireError> {
        DisplayField::new(semantic, value, semantic != FieldSemantic::SimulationEngine)
    }

    fn personal_display() -> Result<ApprovalDisplay, WireError> {
        ApprovalDisplay::new(
            RiskLevel::High,
            vec![
                field(FieldSemantic::Origin, "https://example.test")?,
                field(
                    FieldSemantic::OriginProvenance,
                    "Browser-reported; not independently verified",
                )?,
                field(
                    FieldSemantic::Account,
                    "0x1111111111111111111111111111111111111111",
                )?,
                field(FieldSemantic::NetworkName, "Ethereum")?,
                field(FieldSemantic::ChainId, "1")?,
                field(
                    FieldSemantic::GenesisHash,
                    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )?,
                field(
                    FieldSemantic::RulesetRevision,
                    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )?,
                field(
                    FieldSemantic::RpcObservationsDigest,
                    "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                )?,
                field(
                    FieldSemantic::OperationKind,
                    OperationKind::PersonalMessage.value(),
                )?,
                field(FieldSemantic::PersonalMessageBytes, "0x0102")?,
                field(
                    FieldSemantic::SimulationStatus,
                    SimulationStatus::NotPerformed.value(),
                )?,
                field(
                    FieldSemantic::OriginWarning,
                    "Browser origin is not independently attested.",
                )?,
                field(
                    FieldSemantic::PersonalMessageWarning,
                    "Personal signatures can be reused by protocols.",
                )?,
                field(
                    FieldSemantic::NoSimulationWarning,
                    "No simulation was performed.",
                )?,
            ],
        )
    }

    fn request() -> Result<ApprovalRequest, WireError> {
        ApprovalRequest::new([7; 32], [9; 32], 120_000, "blue comet", personal_display()?)
    }

    fn parent_hello() -> Result<ApprovalParentHello, WireError> {
        ApprovalParentHello::new(42, 0x100, 0x104, [0x11; 32])
    }

    fn child_hello() -> Result<ApprovalChildHello, WireError> {
        ApprovalChildHello::new([0x22; 32])
    }

    #[test]
    fn bootstrap_round_trip_sizes_accessors_and_debug_are_exact() -> Result<(), WireError> {
        assert_eq!(PARENT_HELLO_BYTES, 62);
        assert_eq!(CHILD_HELLO_BYTES, 106);
        assert_eq!(PARENT_FINISH_HEADER_BYTES, 110);
        assert_eq!(MAX_PARENT_FINISH_BYTES, 110 + MAX_REQUEST_BYTES);

        let parent = parent_hello()?;
        assert_eq!(parent.process_id(), 42);
        assert_eq!(parent.process_handle(), 0x100);
        assert_eq!(parent.image_handle(), 0x104);
        assert_eq!(parent.parent_nonce(), [0x11; 32]);
        let parent_bytes = encode_parent_hello(&parent);
        assert_eq!(decode_parent_hello(&parent_bytes)?, parent);

        let child = child_hello()?;
        assert_eq!(child.child_nonce(), [0x22; 32]);
        let child_bytes = encode_child_hello(&parent, &child);
        assert_eq!(decode_child_hello(&parent, &child_bytes)?, child);

        let request = request()?;
        let finish = encode_parent_finish(&parent, &child, &request);
        assert_eq!(
            finish.len(),
            PARENT_FINISH_HEADER_BYTES + encode_request(&request).len()
        );
        assert_eq!(decode_parent_finish(&parent, &child, &finish)?, request);

        assert_eq!(
            format!("{parent:?}"),
            "ApprovalParentHello([REDACTED HANDLES AND NONCE])"
        );
        assert_eq!(format!("{child:?}"), "ApprovalChildHello([REDACTED NONCE])");
        Ok(())
    }

    #[test]
    fn bootstrap_constructors_and_parent_decode_reject_reserved_values() -> Result<(), WireError> {
        assert_eq!(
            ApprovalParentHello::new(0, 0x100, 0x104, [1; 32]),
            Err(WireError::Malformed)
        );
        assert_eq!(
            ApprovalParentHello::new(42, 0, 0x104, [1; 32]),
            Err(WireError::Malformed)
        );
        assert_eq!(
            ApprovalParentHello::new(42, 0x100, 0, [1; 32]),
            Err(WireError::Malformed)
        );
        assert_eq!(
            ApprovalParentHello::new(42, 0x100, 0x100, [1; 32]),
            Err(WireError::Malformed)
        );
        assert_eq!(
            ApprovalParentHello::new(42, 0x100, 0x104, [0; 32]),
            Err(WireError::Malformed)
        );
        assert_eq!(ApprovalChildHello::new([0; 32]), Err(WireError::Malformed));

        let encoded = encode_parent_hello(&parent_hello()?);
        for range in [10..14, 14..22, 22..30, 30..62] {
            let mut changed = encoded;
            changed[range].fill(0);
            assert_eq!(decode_parent_hello(&changed), Err(WireError::Malformed));
        }
        let mut equal_handles = encoded;
        let process_handle: [u8; 8] = encoded[14..22]
            .try_into()
            .map_err(|_| WireError::Malformed)?;
        equal_handles[22..30].copy_from_slice(&process_handle);
        assert_eq!(
            decode_parent_hello(&equal_handles),
            Err(WireError::Malformed)
        );
        Ok(())
    }

    #[test]
    fn parent_hello_rejects_wrong_frame_shape_without_aliasing_fields() -> Result<(), WireError> {
        let parent = parent_hello()?;
        let encoded = encode_parent_hello(&parent);
        for length in 0..PARENT_HELLO_BYTES {
            assert_eq!(
                decode_parent_hello(&encoded[..length]),
                Err(WireError::Malformed)
            );
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert_eq!(decode_parent_hello(&trailing), Err(WireError::Malformed));

        for index in 0..10 {
            let mut changed = encoded;
            changed[index] ^= 1;
            assert_eq!(decode_parent_hello(&changed), Err(WireError::Malformed));
        }
        for index in [13, 21, 29, 61] {
            let mut changed = encoded;
            changed[index] ^= 1;
            assert_ne!(decode_parent_hello(&changed)?, parent);
        }
        Ok(())
    }

    #[test]
    fn child_hello_rejects_every_single_byte_substitution_and_wrong_parent() -> Result<(), WireError>
    {
        let parent = parent_hello()?;
        let child = child_hello()?;
        let encoded = encode_child_hello(&parent, &child);
        for index in 0..CHILD_HELLO_BYTES {
            let mut changed = encoded;
            changed[index] ^= 1;
            assert_eq!(
                decode_child_hello(&parent, &changed),
                Err(WireError::Malformed),
                "substitution at byte {index} was accepted"
            );
        }

        let changed_parent = ApprovalParentHello::new(
            parent.process_id() + 1,
            parent.process_handle(),
            parent.image_handle(),
            parent.parent_nonce(),
        )?;
        assert_eq!(
            decode_child_hello(&changed_parent, &encoded),
            Err(WireError::Malformed)
        );
        Ok(())
    }

    #[test]
    fn child_hello_rejects_every_truncation_and_trailing_data() -> Result<(), WireError> {
        let parent = parent_hello()?;
        let encoded = encode_child_hello(&parent, &child_hello()?);
        for length in 0..CHILD_HELLO_BYTES {
            assert_eq!(
                decode_child_hello(&parent, &encoded[..length]),
                Err(WireError::Malformed)
            );
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert_eq!(
            decode_child_hello(&parent, &trailing),
            Err(WireError::Malformed)
        );
        Ok(())
    }

    #[test]
    fn parent_finish_rejects_every_single_byte_substitution() -> Result<(), WireError> {
        let parent = parent_hello()?;
        let child = child_hello()?;
        let encoded = encode_parent_finish(&parent, &child, &request()?);
        for index in 0..encoded.len() {
            let mut changed = encoded.clone();
            changed[index] ^= 1;
            assert!(
                decode_parent_finish(&parent, &child, &changed).is_err(),
                "substitution at byte {index} was accepted"
            );
        }
        Ok(())
    }

    #[test]
    fn parent_finish_rejects_nonce_hash_length_truncation_and_trailing() -> Result<(), WireError> {
        let parent = parent_hello()?;
        let child = child_hello()?;
        let encoded = encode_parent_finish(&parent, &child, &request()?);
        for length in 0..encoded.len() {
            assert!(decode_parent_finish(&parent, &child, &encoded[..length]).is_err());
        }

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_parent_finish(&parent, &child, &trailing),
            Err(WireError::Malformed)
        );

        let other_parent = ApprovalParentHello::new(
            parent.process_id(),
            parent.process_handle(),
            parent.image_handle(),
            [0x33; 32],
        )?;
        assert_eq!(
            decode_parent_finish(&other_parent, &child, &encoded),
            Err(WireError::Malformed)
        );
        let other_child = ApprovalChildHello::new([0x44; 32])?;
        assert_eq!(
            decode_parent_finish(&parent, &other_child, &encoded),
            Err(WireError::Malformed)
        );

        let mut oversized = vec![0_u8; MAX_PARENT_FINISH_BYTES + 1];
        oversized[..8].copy_from_slice(PARENT_FINISH_MAGIC);
        assert_eq!(
            decode_parent_finish(&parent, &child, &oversized),
            Err(WireError::TooLarge)
        );
        Ok(())
    }

    #[test]
    fn bootstrap_frame_types_and_magics_cannot_cross() -> Result<(), WireError> {
        let parent = parent_hello()?;
        let child = child_hello()?;
        let parent_bytes = encode_parent_hello(&parent);
        let child_bytes = encode_child_hello(&parent, &child);
        let finish_bytes = encode_parent_finish(&parent, &child, &request()?);

        assert_eq!(
            decode_child_hello(&parent, &parent_bytes),
            Err(WireError::Malformed)
        );
        assert_eq!(decode_parent_hello(&child_bytes), Err(WireError::Malformed));
        assert_eq!(
            decode_parent_finish(&parent, &child, &child_bytes),
            Err(WireError::Malformed)
        );

        let mut parent_with_child_magic = parent_bytes;
        parent_with_child_magic[..8].copy_from_slice(CHILD_HELLO_MAGIC);
        assert_eq!(
            decode_parent_hello(&parent_with_child_magic),
            Err(WireError::Malformed)
        );
        let mut child_with_parent_magic = child_bytes;
        child_with_parent_magic[..8].copy_from_slice(PARENT_HELLO_MAGIC);
        assert_eq!(
            decode_child_hello(&parent, &child_with_parent_magic),
            Err(WireError::Malformed)
        );
        let mut finish_with_parent_magic = finish_bytes;
        finish_with_parent_magic[..8].copy_from_slice(PARENT_HELLO_MAGIC);
        assert_eq!(
            decode_parent_finish(&parent, &child, &finish_with_parent_magic),
            Err(WireError::Malformed)
        );
        Ok(())
    }

    #[test]
    fn request_round_trip_and_golden_digest() -> Result<(), WireError> {
        let bytes = encode_request(&request()?);
        assert_eq!(decode_request(&bytes)?, request()?);
        let digest = Sha256::digest(&bytes);
        assert_eq!(
            digest.as_slice(),
            &[
                83, 6, 200, 66, 244, 170, 164, 58, 25, 172, 48, 181, 31, 11, 236, 58, 121, 189, 92,
                4, 158, 249, 128, 53, 121, 210, 107, 201, 57, 173, 94, 215,
            ]
        );
        Ok(())
    }

    #[test]
    fn request_debug_redacts_phrase_challenge_and_display() -> Result<(), WireError> {
        let debug = format!("{:?}", request()?);
        assert!(!debug.contains("blue comet"));
        assert!(!debug.contains("example.test"));
        assert!(!debug.contains("[7, 7"));
        assert!(debug.contains("[REDACTED]"));
        Ok(())
    }

    #[test]
    fn display_and_response_debug_redact_security_values() -> Result<(), WireError> {
        let request = request()?;
        let display_debug = format!("{:?}", request.display());
        let field_debug = format!("{:?}", request.display().fields()[0]);
        let response_debug = format!(
            "{:?}",
            ApprovalResponse::for_request(Decision::Approve, &request)
        );

        assert!(display_debug.contains("field_count"));
        assert!(display_debug.contains("[REDACTED]"));
        assert!(field_debug.contains("Origin"));
        assert!(field_debug.contains("[REDACTED]"));
        assert!(!display_debug.contains("example.test"));
        assert!(!field_debug.contains("example.test"));
        assert!(!response_debug.contains("7, 7, 7"));
        assert!(!response_debug.contains("9, 9, 9"));
        assert!(response_debug.contains("[REDACTED]"));
        Ok(())
    }

    #[test]
    fn response_round_trip_is_fixed_and_exact() -> Result<(), WireError> {
        let request = request()?;
        let response = ApprovalResponse::for_request(Decision::Approve, &request);
        let bytes = encode_response(response);
        assert_eq!(decode_response(&bytes)?, response);
        assert_eq!(bytes.len(), 75);
        Ok(())
    }

    #[test]
    fn unknown_semantic_is_rejected() -> Result<(), WireError> {
        let mut bytes = encode_request(&request()?);
        let fields_offset = 8 + 2 + 32 + 32 + 4 + 1 + 2 + "blue comet".len() + 1;
        bytes[fields_offset] = 0xff;
        assert_eq!(decode_request(&bytes), Err(WireError::Malformed));
        Ok(())
    }

    #[test]
    fn duplicate_and_missing_semantics_are_rejected() -> Result<(), WireError> {
        let mut duplicate = personal_display()?.fields;
        duplicate.push(duplicate[0].clone());
        assert_eq!(
            ApprovalDisplay::new(RiskLevel::High, duplicate),
            Err(WireError::Malformed)
        );
        let mut missing = personal_display()?.fields;
        missing.retain(|field| field.semantic != FieldSemantic::Account);
        assert_eq!(
            ApprovalDisplay::new(RiskLevel::High, missing),
            Err(WireError::Malformed)
        );
        Ok(())
    }

    #[test]
    fn bounds_and_security_bit_changes_fail_closed() -> Result<(), WireError> {
        assert_eq!(
            DisplayField::new(FieldSemantic::Origin, "x".repeat(2_049), true),
            Err(WireError::InvalidText)
        );
        assert_eq!(
            DisplayField::new(FieldSemantic::Account, "0x1", false),
            Err(WireError::Malformed)
        );
        let mut bytes = encode_request(&request()?);
        let fields_offset = 8 + 2 + 32 + 32 + 4 + 1 + 2 + "blue comet".len() + 1;
        bytes[fields_offset + 1] ^= 1;
        assert_eq!(decode_request(&bytes), Err(WireError::Malformed));
        Ok(())
    }

    #[test]
    fn response_bit_changes_do_not_alias() -> Result<(), WireError> {
        let request = request()?;
        let response = ApprovalResponse::for_request(Decision::Approve, &request);
        let encoded = encode_response(response);
        for index in [10, 11, 42, 43, 74] {
            let mut changed = encoded;
            changed[index] ^= 1;
            assert_ne!(decode_response(&changed)?, response);
        }
        Ok(())
    }

    #[test]
    fn request_hash_binds_phrase_display_and_expiry() -> Result<(), WireError> {
        let original = request()?;
        let changed_phrase = ApprovalRequest::new(
            *original.digest(),
            *original.approval_nonce(),
            original.expires_after_milliseconds(),
            "red planet",
            original.display().clone(),
        )?;
        let changed_expiry = ApprovalRequest::new(
            *original.digest(),
            *original.approval_nonce(),
            original.expires_after_milliseconds() - 1,
            original.anti_phishing_phrase(),
            original.display().clone(),
        )?;
        let mut changed_fields = original.display().fields().to_vec();
        let account = changed_fields
            .iter_mut()
            .find(|field| field.semantic() == FieldSemantic::Account)
            .ok_or(WireError::Malformed)?;
        *account = field(
            FieldSemantic::Account,
            "0x2222222222222222222222222222222222222222",
        )?;
        let changed_display = ApprovalRequest::new(
            *original.digest(),
            *original.approval_nonce(),
            original.expires_after_milliseconds(),
            original.anti_phishing_phrase(),
            ApprovalDisplay::new(original.display().risk(), changed_fields)?,
        )?;
        assert_ne!(request_hash(&original), request_hash(&changed_phrase));
        assert_ne!(request_hash(&original), request_hash(&changed_expiry));
        assert_ne!(request_hash(&original), request_hash(&changed_display));
        Ok(())
    }
}
