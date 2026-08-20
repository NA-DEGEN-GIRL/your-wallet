use core::fmt;

/// Stable field identifiers safe to expose through provider errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorField {
    /// Transaction envelope type.
    EnvelopeType,
    /// EIP-155 chain ID.
    ChainId,
    /// Transaction nonce.
    Nonce,
    /// Gas limit.
    GasLimit,
    /// Legacy gas price.
    GasPrice,
    /// EIP-1559 priority fee.
    MaxPriorityFeePerGas,
    /// EIP-1559 total fee cap.
    MaxFeePerGas,
    /// Transaction target.
    Target,
    /// Calldata or personal message.
    Payload,
    /// EIP-2930 access list.
    AccessList,
    /// EIP-712 domain.
    TypedDataDomain,
    /// Browser document provenance.
    BrowserContext,
    /// Approval response.
    Approval,
    /// Nonce candidate state.
    NonceState,
    /// Durable record bytes.
    DurableRecord,
}

/// Stable internal error classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolErrorKind {
    /// A required field is absent.
    MissingField,
    /// Mutually exclusive fields were supplied together.
    ConflictingFields,
    /// The request uses an unsupported transaction envelope.
    UnsupportedEnvelope,
    /// The request's chain identity does not match the selected chain.
    ChainMismatch,
    /// A numerical invariant is false.
    InvalidNumericInvariant,
    /// A collection or payload exceeds a hard limit.
    BoundsExceeded,
    /// An access-list address or key is duplicated.
    DuplicateAccessListItem,
    /// Typed data lacks the required domain binding.
    MissingTypedDataBinding,
    /// The browser context is expired or malformed.
    InvalidBrowserContext,
    /// The user rejected the request.
    UserRejected,
    /// The approval expired before consumption.
    ApprovalExpired,
    /// The approval has already been consumed.
    ApprovalConsumed,
    /// The approval was invalidated by a state change or mismatch.
    ApprovalInvalidated,
    /// The response did not match the issued challenge.
    ApprovalMismatch,
    /// A registry or protocol rule requires a hard denial.
    ProtocolInvalid,
    /// A nonce state transition is not permitted.
    InvalidNonceTransition,
    /// A possibly signed nonce was presented for release/reuse.
    UnsafeNonceRelease,
    /// Two distinct transactions were reported finalized for one account nonce.
    ConflictingFinality,
    /// A durable record is malformed or uses an unsupported version.
    CorruptDurableRecord,
}

/// Internal protocol error with no attacker-controlled message text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolError {
    /// Stable semantic kind.
    pub kind: ProtocolErrorKind,
    /// Optional stable field tag.
    pub field: Option<ErrorField>,
}

impl ProtocolError {
    /// Constructs a field-specific error.
    #[must_use]
    pub const fn at(kind: ProtocolErrorKind, field: ErrorField) -> Self {
        Self {
            kind,
            field: Some(field),
        }
    }

    /// Constructs an error not associated with one external field.
    #[must_use]
    pub const fn new(kind: ProtocolErrorKind) -> Self {
        Self { kind, field: None }
    }

    /// Maps the internal error to an EIP-1193/JSON-RPC-safe provider error.
    #[must_use]
    pub const fn provider_error(self) -> ProviderError {
        match self.kind {
            ProtocolErrorKind::UserRejected => ProviderError {
                code: 4001,
                message: "User rejected the request.",
            },
            ProtocolErrorKind::UnsupportedEnvelope => ProviderError {
                code: 4200,
                message: "The requested operation is not supported.",
            },
            ProtocolErrorKind::ApprovalExpired
            | ProtocolErrorKind::ApprovalConsumed
            | ProtocolErrorKind::ApprovalInvalidated
            | ProtocolErrorKind::ApprovalMismatch => ProviderError {
                code: -32_000,
                message: "The approval is no longer valid.",
            },
            ProtocolErrorKind::InvalidNonceTransition
            | ProtocolErrorKind::UnsafeNonceRelease
            | ProtocolErrorKind::ConflictingFinality
            | ProtocolErrorKind::CorruptDurableRecord => ProviderError {
                code: -32_603,
                message: "The wallet could not complete the request safely.",
            },
            ProtocolErrorKind::ProtocolInvalid => ProviderError {
                code: 4100,
                message: "The selected chain or protocol rules are not authorized.",
            },
            ProtocolErrorKind::MissingField
            | ProtocolErrorKind::ConflictingFields
            | ProtocolErrorKind::ChainMismatch
            | ProtocolErrorKind::InvalidNumericInvariant
            | ProtocolErrorKind::BoundsExceeded
            | ProtocolErrorKind::DuplicateAccessListItem
            | ProtocolErrorKind::MissingTypedDataBinding
            | ProtocolErrorKind::InvalidBrowserContext => ProviderError {
                code: -32_602,
                message: "Invalid parameters.",
            },
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.provider_error().message)
    }
}

impl std::error::Error for ProtocolError {}

/// Sanitized provider-facing error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderError {
    /// EIP-1193 or JSON-RPC error code.
    pub code: i64,
    /// Static non-sensitive message.
    pub message: &'static str,
}

#[cfg(test)]
mod tests {
    use super::{ErrorField, ProtocolError, ProtocolErrorKind};

    #[test]
    fn mapping_does_not_echo_field_values() {
        let error = ProtocolError::at(ProtocolErrorKind::ChainMismatch, ErrorField::ChainId);
        assert_eq!(error.provider_error().code, -32_602);
        assert_eq!(error.to_string(), "Invalid parameters.");
    }
}
