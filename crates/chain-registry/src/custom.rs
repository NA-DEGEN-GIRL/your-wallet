use thiserror::Error;

use crate::{
    Adapter, ChainId, EnvelopeSet, FinalityModel, RpcEndpointClass, RpcUrlError, chain_by_id,
    classify_rpc_endpoint,
};

/// Untrusted fields proposed for a user-defined EVM chain.
#[derive(Debug, Clone, Copy)]
pub struct CustomChainProposal<'a> {
    /// Display name shown in every approval.
    pub display_name: &'a str,
    /// Full-width EIP-155 identifier.
    pub chain_id: ChainId,
    /// Native currency display symbol.
    pub native_symbol: &'a str,
    /// Native currency decimal places.
    pub native_decimals: u8,
    /// Session-only RPC endpoint. The validated result does not retain it.
    pub rpc_endpoint: &'a str,
    /// Requested transaction type bytes; only `0`, `1`, and `2` are valid.
    pub transaction_type_bytes: &'a [u8],
    /// Explicit per-session direct-development exception for private RPC hosts.
    pub allow_private_rpc_for_direct_development: bool,
}

/// A sanitized user-defined chain policy.
///
/// No RPC URL is retained, and the adapter/finality fields cannot be selected by
/// untrusted registry data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCustomChain {
    /// Sanitized display name.
    pub display_name: String,
    /// Full-width EIP-155 identifier.
    pub chain_id: ChainId,
    /// Sanitized native symbol.
    pub native_symbol: String,
    /// Native decimal places.
    pub native_decimals: u8,
    /// Fixed conservative adapter.
    pub adapter: Adapter,
    /// Standard envelope subset requested by the user.
    pub transaction_envelopes: EnvelopeSet,
    /// Fixed absence of a finality claim.
    pub finality: FinalityModel,
    /// Endpoint classification, without retaining the endpoint itself.
    pub rpc_endpoint_class: RpcEndpointClass,
    /// Mandatory signing interaction policy.
    pub signing_policy: CustomSigningPolicy,
    /// Warnings that must be rendered in trusted approval UI.
    pub warnings: Vec<CustomWarning>,
}

/// Signing UX required for a validated custom chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomSigningPolicy {
    /// A prominent warning and deliberate hold-to-confirm are always required.
    StrongWarningAndHoldRequired,
}

/// Stable warnings produced for every custom-chain approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomWarning {
    /// Chain identity has no wallet-pinned immutable fingerprint.
    UnpinnedIdentity,
    /// Only standard type-0, type-1, and type-2 EIP-155 behavior is available.
    GenericEvmRulesOnly,
    /// The wallet makes no confirmation or finality guarantee.
    NoFinalityClaim,
    /// DNS resolution and the actual connected peer require global-unicast checks.
    ResolvedPeerCheckRequired,
    /// A private endpoint was allowed only for this direct-development session.
    PrivateRpcDevelopmentOverride,
}

/// Failure to validate a user-defined chain proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CustomChainError {
    /// Display name is empty, too long, or contains control characters.
    #[error("custom chain display name is invalid")]
    InvalidDisplayName,
    /// The zero chain identifier is not allowed.
    #[error("custom chain identifier must be nonzero")]
    ZeroChainId,
    /// The identifier belongs to an immutable built-in definition.
    #[error("custom chain identifier collides with a built-in chain")]
    BuiltInChainId,
    /// Native symbol is not a conservative uppercase ASCII symbol.
    #[error("custom native currency symbol is invalid")]
    InvalidNativeSymbol,
    /// Decimal precision exceeds the UI and amount-scaling safety bound.
    #[error("custom native currency decimals exceed the supported bound")]
    InvalidNativeDecimals,
    /// At least one standard transaction type is required.
    #[error("custom chain must enable at least one transaction type")]
    NoTransactionType,
    /// A transaction type was unsupported or repeated.
    #[error("custom chain transaction type is unsupported or duplicated")]
    InvalidTransactionType,
    /// RPC endpoint validation failed.
    #[error(transparent)]
    Rpc(#[from] RpcUrlError),
}

/// Validates an untrusted custom chain without selecting executable behavior.
///
/// The result always uses [`Adapter::GenericEvm155`], always makes
/// [`FinalityModel::NoClaim`], and always requires a strong warning.
///
/// # Errors
///
/// Returns [`CustomChainError`] when identity/display fields are unsafe, the
/// requested envelope set is not a unique non-empty subset of types 0/1/2, or
/// the session RPC endpoint does not pass conservative URL validation.
pub fn validate_custom_chain(
    proposal: CustomChainProposal<'_>,
) -> Result<ValidatedCustomChain, CustomChainError> {
    let display_name = proposal.display_name.trim();
    if display_name.is_empty()
        || display_name.chars().count() > 64
        || display_name.chars().any(char::is_control)
    {
        return Err(CustomChainError::InvalidDisplayName);
    }
    if proposal.chain_id.is_zero() {
        return Err(CustomChainError::ZeroChainId);
    }
    if chain_by_id(proposal.chain_id).is_some() {
        return Err(CustomChainError::BuiltInChainId);
    }
    if proposal.native_symbol.is_empty()
        || proposal.native_symbol.len() > 12
        || !proposal
            .native_symbol
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(CustomChainError::InvalidNativeSymbol);
    }
    if proposal.native_decimals > 36 {
        return Err(CustomChainError::InvalidNativeDecimals);
    }
    let transaction_envelopes = EnvelopeSet::from_type_bytes(proposal.transaction_type_bytes)
        .map_err(|_| CustomChainError::InvalidTransactionType)?;
    if transaction_envelopes.is_empty() {
        return Err(CustomChainError::NoTransactionType);
    }
    let rpc_endpoint_class = classify_rpc_endpoint(
        proposal.rpc_endpoint,
        proposal.allow_private_rpc_for_direct_development,
    )?;

    let mut warnings = vec![
        CustomWarning::UnpinnedIdentity,
        CustomWarning::GenericEvmRulesOnly,
        CustomWarning::NoFinalityClaim,
    ];
    match rpc_endpoint_class {
        RpcEndpointClass::DomainNeedsResolvedPeerCheck => {
            warnings.push(CustomWarning::ResolvedPeerCheckRequired);
        }
        RpcEndpointClass::PrivateDevelopmentOverride => {
            warnings.push(CustomWarning::PrivateRpcDevelopmentOverride);
        }
        RpcEndpointClass::PublicIpLiteral => {}
    }

    Ok(ValidatedCustomChain {
        display_name: display_name.to_owned(),
        chain_id: proposal.chain_id,
        native_symbol: proposal.native_symbol.to_owned(),
        native_decimals: proposal.native_decimals,
        adapter: Adapter::GenericEvm155,
        transaction_envelopes,
        finality: FinalityModel::NoClaim,
        rpc_endpoint_class,
        signing_policy: CustomSigningPolicy::StrongWarningAndHoldRequired,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        Adapter, ChainId, CustomChainError, CustomChainProposal, CustomSigningPolicy,
        CustomWarning, FinalityModel, RpcEndpointClass, validate_custom_chain,
    };

    fn proposal(rpc_endpoint: &str) -> CustomChainProposal<'_> {
        CustomChainProposal {
            display_name: "User Chain",
            chain_id: ChainId::from_u64(9_999_991),
            native_symbol: "TEST",
            native_decimals: 18,
            rpc_endpoint,
            transaction_type_bytes: &[0, 1, 2],
            allow_private_rpc_for_direct_development: false,
        }
    }

    #[test]
    fn custom_chain_cannot_select_code_or_claim_finality() {
        let validated = validate_custom_chain(proposal("https://rpc.example.com"));
        assert!(validated.is_ok());
        if let Ok(validated) = validated {
            assert_eq!(validated.adapter, Adapter::GenericEvm155);
            assert_eq!(validated.finality, FinalityModel::NoClaim);
            assert_eq!(
                validated.signing_policy,
                CustomSigningPolicy::StrongWarningAndHoldRequired
            );
            assert!(
                validated
                    .warnings
                    .contains(&CustomWarning::UnpinnedIdentity)
            );
            assert!(
                validated
                    .warnings
                    .contains(&CustomWarning::GenericEvmRulesOnly)
            );
            assert!(validated.warnings.contains(&CustomWarning::NoFinalityClaim));
            assert!(
                validated
                    .warnings
                    .contains(&CustomWarning::ResolvedPeerCheckRequired)
            );
            assert_eq!(
                validated.rpc_endpoint_class,
                RpcEndpointClass::DomainNeedsResolvedPeerCheck
            );
        }
    }

    #[test]
    fn custom_chain_cannot_shadow_builtin_chain_id() {
        let mut input = proposal("https://rpc.example.com");
        input.chain_id = ChainId::from_u64(1);
        assert_eq!(
            validate_custom_chain(input),
            Err(CustomChainError::BuiltInChainId)
        );
    }

    #[test]
    fn type_three_and_duplicate_types_are_rejected() {
        let mut type_three = proposal("https://rpc.example.com");
        type_three.transaction_type_bytes = &[0, 3];
        assert_eq!(
            validate_custom_chain(type_three),
            Err(CustomChainError::InvalidTransactionType)
        );

        let mut duplicate = proposal("https://rpc.example.com");
        duplicate.transaction_type_bytes = &[0, 1, 1];
        assert_eq!(
            validate_custom_chain(duplicate),
            Err(CustomChainError::InvalidTransactionType)
        );
    }

    #[test]
    fn private_rpc_requires_direct_development_override() {
        let default_result = validate_custom_chain(proposal("http://127.0.0.1:8545"));
        assert!(default_result.is_err());

        let mut overridden = proposal("http://127.0.0.1:8545");
        overridden.allow_private_rpc_for_direct_development = true;
        let validated = validate_custom_chain(overridden);
        assert!(validated.is_ok());
        if let Ok(validated) = validated {
            assert_eq!(
                validated.rpc_endpoint_class,
                RpcEndpointClass::PrivateDevelopmentOverride
            );
            assert!(
                validated
                    .warnings
                    .contains(&CustomWarning::PrivateRpcDevelopmentOverride)
            );
        }
    }

    #[test]
    fn malformed_display_fields_are_rejected() {
        let mut bad_name = proposal("https://rpc.example.com");
        bad_name.display_name = "\u{0000}";
        assert_eq!(
            validate_custom_chain(bad_name),
            Err(CustomChainError::InvalidDisplayName)
        );

        let mut bad_symbol = proposal("https://rpc.example.com");
        bad_symbol.native_symbol = "te$t";
        assert_eq!(
            validate_custom_chain(bad_symbol),
            Err(CustomChainError::InvalidNativeSymbol)
        );
    }
}
