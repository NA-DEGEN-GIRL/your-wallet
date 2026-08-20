use std::collections::BTreeSet;

use wallet_eip712::ValidatedTypedDataV4;
use wallet_model::{
    AccessListEntry, AccessListTransaction, BoundedBytes, CanonicalOperation, ChainIdentity,
    DynamicFeeTransaction, Hash32, LegacyTransaction, MAX_ACCESS_LIST_ENTRIES, MAX_CALLDATA_BYTES,
    MAX_MESSAGE_BYTES, MAX_STORAGE_KEYS_PER_ENTRY, PersonalMessage, TypedDataV4, U256,
    UntrustedAccessListEntry, UntrustedOperation, UntrustedTransaction, UntrustedTypedDataV4,
};

use crate::{ErrorField, ProtocolError, ProtocolErrorKind};

/// Schema identifiers whose signatures and trust roots were verified outside this crate.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SignedSchemaAllowlist {
    schema_ids: Vec<Hash32>,
}

impl SignedSchemaAllowlist {
    /// Canonicalizes a set of already-verified signed schema identifiers.
    #[must_use]
    pub fn from_verified(mut schema_ids: Vec<Hash32>) -> Self {
        schema_ids.sort_unstable();
        schema_ids.dedup();
        Self { schema_ids }
    }

    /// Returns whether a schema has been verified and admitted.
    #[must_use]
    pub fn contains(&self, schema_id: &Hash32) -> bool {
        self.schema_ids.binary_search(schema_id).is_ok()
    }
}

/// Converts untrusted operations into signer-ready canonical operations.
#[derive(Clone, Debug)]
pub struct OperationValidator {
    expected_chain: ChainIdentity,
    schemas: SignedSchemaAllowlist,
}

/// Opaque proof that an untrusted operation passed every canonical protocol
/// validation for one exact chain identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedOperation {
    operation: CanonicalOperation,
}

impl ValidatedOperation {
    /// Borrows the canonical value for deterministic display and encoding.
    ///
    /// The owned value is never exposed, so safe callers cannot re-wrap a
    /// caller-constructed `CanonicalOperation` as validated.
    #[must_use]
    pub const fn canonical(&self) -> &CanonicalOperation {
        &self.operation
    }

    pub(crate) fn into_canonical(self) -> CanonicalOperation {
        self.operation
    }
}

impl OperationValidator {
    /// Creates a validator for one selected chain and signed-schema policy.
    #[must_use]
    pub const fn new(expected_chain: ChainIdentity, schemas: SignedSchemaAllowlist) -> Self {
        Self {
            expected_chain,
            schemas,
        }
    }

    /// Validates one operation without silently discarding conflicting fields.
    pub fn validate(
        &self,
        operation: UntrustedOperation,
    ) -> Result<ValidatedOperation, ProtocolError> {
        let operation = match operation {
            UntrustedOperation::Transaction(transaction) => self.validate_transaction(transaction),
            UntrustedOperation::PersonalMessage(message) => {
                let message = BoundedBytes::<MAX_MESSAGE_BYTES>::new(message).map_err(|_| {
                    ProtocolError::at(ProtocolErrorKind::BoundsExceeded, ErrorField::Payload)
                })?;
                Ok(CanonicalOperation::PersonalMessage(PersonalMessage {
                    message,
                }))
            }
            UntrustedOperation::TypedDataV4(_) => Err(ProtocolError::at(
                ProtocolErrorKind::ProtocolInvalid,
                ErrorField::TypedDataDomain,
            )),
        }?;
        Ok(ValidatedOperation { operation })
    }

    /// Admits EIP-712 only from the strict exact-source parser's opaque proof.
    pub fn validate_eip712(
        &self,
        typed_data: &ValidatedTypedDataV4,
    ) -> Result<ValidatedOperation, ProtocolError> {
        let operation = self.validate_typed_data(typed_data.as_untrusted())?;
        Ok(ValidatedOperation { operation })
    }

    #[allow(clippy::too_many_lines)]
    fn validate_transaction(
        &self,
        transaction: UntrustedTransaction,
    ) -> Result<CanonicalOperation, ProtocolError> {
        let UntrustedTransaction {
            envelope_type,
            chain_id,
            nonce,
            gas_limit,
            gas_price,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            target,
            value,
            data,
            access_list,
        } = transaction;

        let inferred_type = match envelope_type {
            Some(envelope) => envelope,
            None if max_priority_fee_per_gas.is_some() || max_fee_per_gas.is_some() => 2,
            None if access_list.is_some() => 1,
            None => 0,
        };
        if inferred_type > 2 {
            return Err(ProtocolError::at(
                ProtocolErrorKind::UnsupportedEnvelope,
                ErrorField::EnvelopeType,
            ));
        }

        let chain_id = required(chain_id, ErrorField::ChainId)?;
        if chain_id.is_zero() || chain_id != self.expected_chain.chain_id() {
            return Err(ProtocolError::at(
                ProtocolErrorKind::ChainMismatch,
                ErrorField::ChainId,
            ));
        }
        let nonce = required(nonce, ErrorField::Nonce)?;
        let gas_limit = required(gas_limit, ErrorField::GasLimit)?;
        if gas_limit.is_zero() {
            return Err(ProtocolError::at(
                ProtocolErrorKind::InvalidNumericInvariant,
                ErrorField::GasLimit,
            ));
        }
        let target = required(target, ErrorField::Target)?;
        let value = value.unwrap_or(U256::ZERO);
        let data = BoundedBytes::<MAX_CALLDATA_BYTES>::new(data).map_err(|_| {
            ProtocolError::at(ProtocolErrorKind::BoundsExceeded, ErrorField::Payload)
        })?;

        match inferred_type {
            0 => {
                if access_list.is_some()
                    || max_priority_fee_per_gas.is_some()
                    || max_fee_per_gas.is_some()
                {
                    return Err(conflicting(ErrorField::EnvelopeType));
                }
                let gas_price = required(gas_price, ErrorField::GasPrice)?;
                Ok(CanonicalOperation::LegacyEip155(LegacyTransaction {
                    chain_id,
                    nonce,
                    gas_price,
                    gas_limit,
                    target,
                    value,
                    data,
                }))
            }
            1 => {
                if max_priority_fee_per_gas.is_some() || max_fee_per_gas.is_some() {
                    return Err(conflicting(ErrorField::EnvelopeType));
                }
                let gas_price = required(gas_price, ErrorField::GasPrice)?;
                let access_list = validate_access_list(access_list.unwrap_or_default())?;
                Ok(CanonicalOperation::AccessListEip2930(
                    AccessListTransaction {
                        chain_id,
                        nonce,
                        gas_price,
                        gas_limit,
                        target,
                        value,
                        data,
                        access_list,
                    },
                ))
            }
            2 => {
                if gas_price.is_some() {
                    return Err(conflicting(ErrorField::GasPrice));
                }
                let priority_fee =
                    required(max_priority_fee_per_gas, ErrorField::MaxPriorityFeePerGas)?;
                let fee_cap = required(max_fee_per_gas, ErrorField::MaxFeePerGas)?;
                if fee_cap < priority_fee {
                    return Err(ProtocolError::at(
                        ProtocolErrorKind::InvalidNumericInvariant,
                        ErrorField::MaxFeePerGas,
                    ));
                }
                let access_list = validate_access_list(access_list.unwrap_or_default())?;
                Ok(CanonicalOperation::DynamicFeeEip1559(
                    DynamicFeeTransaction {
                        chain_id,
                        nonce,
                        max_priority_fee_per_gas: priority_fee,
                        max_fee_per_gas: fee_cap,
                        gas_limit,
                        target,
                        value,
                        data,
                        access_list,
                    },
                ))
            }
            _ => Err(ProtocolError::at(
                ProtocolErrorKind::UnsupportedEnvelope,
                ErrorField::EnvelopeType,
            )),
        }
    }

    fn validate_typed_data(
        &self,
        typed_data: &UntrustedTypedDataV4,
    ) -> Result<CanonicalOperation, ProtocolError> {
        if let Some(chain_id) = typed_data.chain_id
            && (chain_id != self.expected_chain.chain_id() || chain_id.is_zero())
        {
            return Err(ProtocolError::at(
                ProtocolErrorKind::ChainMismatch,
                ErrorField::TypedDataDomain,
            ));
        }

        if typed_data.schema_id.is_some()
            && typed_data.chain_id.is_some()
            && typed_data.verifying_contract.is_some()
        {
            return Err(ProtocolError::at(
                ProtocolErrorKind::ConflictingFields,
                ErrorField::TypedDataDomain,
            ));
        }

        let missing_domain_binding =
            typed_data.chain_id.is_none() || typed_data.verifying_contract.is_none();
        let schema_exception = if missing_domain_binding {
            let schema_id = required(typed_data.schema_id, ErrorField::TypedDataDomain)?;
            if !self.schemas.contains(&schema_id) {
                return Err(ProtocolError::at(
                    ProtocolErrorKind::MissingTypedDataBinding,
                    ErrorField::TypedDataDomain,
                ));
            }
            Some(schema_id)
        } else {
            None
        };

        Ok(CanonicalOperation::TypedDataV4(TypedDataV4 {
            domain_separator: typed_data.domain_separator,
            message_hash: typed_data.message_hash,
            source_document_hash: typed_data.source_document_hash,
            chain_id: typed_data.chain_id,
            verifying_contract: typed_data.verifying_contract,
            schema_exception,
        }))
    }
}

fn required<T>(value: Option<T>, field: ErrorField) -> Result<T, ProtocolError> {
    value.ok_or_else(|| ProtocolError::at(ProtocolErrorKind::MissingField, field))
}

const fn conflicting(field: ErrorField) -> ProtocolError {
    ProtocolError::at(ProtocolErrorKind::ConflictingFields, field)
}

fn validate_access_list(
    entries: Vec<UntrustedAccessListEntry>,
) -> Result<Vec<AccessListEntry>, ProtocolError> {
    if entries.len() > MAX_ACCESS_LIST_ENTRIES {
        return Err(ProtocolError::at(
            ProtocolErrorKind::BoundsExceeded,
            ErrorField::AccessList,
        ));
    }
    let mut seen_addresses = BTreeSet::new();
    let mut validated = Vec::with_capacity(entries.len());
    for entry in entries {
        if !seen_addresses.insert(entry.address) {
            return Err(ProtocolError::at(
                ProtocolErrorKind::DuplicateAccessListItem,
                ErrorField::AccessList,
            ));
        }
        if entry.storage_keys.len() > MAX_STORAGE_KEYS_PER_ENTRY {
            return Err(ProtocolError::at(
                ProtocolErrorKind::BoundsExceeded,
                ErrorField::AccessList,
            ));
        }
        let mut seen_keys = BTreeSet::new();
        for key in &entry.storage_keys {
            if !seen_keys.insert(*key) {
                return Err(ProtocolError::at(
                    ProtocolErrorKind::DuplicateAccessListItem,
                    ErrorField::AccessList,
                ));
            }
        }
        validated.push(AccessListEntry::from_validated(
            entry.address,
            entry.storage_keys,
        ));
    }
    Ok(validated)
}

#[cfg(test)]
mod tests {
    use wallet_model::{
        AdapterKind, Address20, CanonicalOperation, ChainIdentity, Hash32, TransactionTarget, U256,
        UntrustedAccessListEntry, UntrustedOperation, UntrustedTransaction, UntrustedTypedDataV4,
    };

    use super::{OperationValidator, SignedSchemaAllowlist};
    use crate::{ErrorField, ProtocolError, ProtocolErrorKind};

    fn chain() -> ChainIdentity {
        ChainIdentity::new(
            U256::from(1),
            Hash32::new([1; 32]),
            AdapterKind::EthereumPos,
            Hash32::new([2; 32]),
        )
    }

    fn base_transaction() -> UntrustedTransaction {
        UntrustedTransaction {
            chain_id: Some(U256::from(1)),
            nonce: Some(U256::ZERO),
            gas_limit: Some(U256::from(21_000)),
            gas_price: Some(U256::from(10)),
            target: Some(TransactionTarget::Call(Address20::new([3; 20]))),
            ..UntrustedTransaction::default()
        }
    }

    #[test]
    fn inference_is_deterministic_and_conflicts_are_rejected() -> Result<(), ProtocolError> {
        let validator = OperationValidator::new(chain(), SignedSchemaAllowlist::default());
        let legacy = validator.validate(UntrustedOperation::Transaction(base_transaction()))?;
        assert!(matches!(
            legacy.canonical(),
            CanonicalOperation::LegacyEip155(_)
        ));

        let mut conflicting = base_transaction();
        conflicting.max_fee_per_gas = Some(U256::from(20));
        conflicting.max_priority_fee_per_gas = Some(U256::from(1));
        let error = validator.validate(UntrustedOperation::Transaction(conflicting));
        assert_eq!(
            error,
            Err(ProtocolError::at(
                ProtocolErrorKind::ConflictingFields,
                ErrorField::GasPrice,
            ))
        );
        Ok(())
    }

    #[test]
    fn duplicate_access_list_items_are_rejected() {
        let validator = OperationValidator::new(chain(), SignedSchemaAllowlist::default());
        let duplicate = UntrustedAccessListEntry {
            address: Address20::new([9; 20]),
            storage_keys: vec![Hash32::new([8; 32]), Hash32::new([8; 32])],
        };
        let mut transaction = base_transaction();
        transaction.envelope_type = Some(1);
        transaction.access_list = Some(vec![duplicate]);
        assert!(matches!(
            validator.validate(UntrustedOperation::Transaction(transaction)),
            Err(ProtocolError {
                kind: ProtocolErrorKind::DuplicateAccessListItem,
                ..
            })
        ));
    }

    #[test]
    fn caller_prehashed_typed_data_is_never_admitted() {
        let schema = Hash32::new([7; 32]);
        let request = UntrustedTypedDataV4 {
            domain_separator: Hash32::new([1; 32]),
            message_hash: Hash32::new([2; 32]),
            source_document_hash: Hash32::new([3; 32]),
            chain_id: None,
            verifying_contract: None,
            schema_id: Some(schema),
        };
        let denied =
            OperationValidator::new(chain(), SignedSchemaAllowlist::from_verified(vec![schema]))
                .validate(UntrustedOperation::TypedDataV4(request));
        assert_eq!(
            denied,
            Err(ProtocolError::at(
                ProtocolErrorKind::ProtocolInvalid,
                ErrorField::TypedDataDomain,
            ))
        );
    }

    #[test]
    fn dynamic_fee_cap_must_cover_priority_fee() {
        let validator = OperationValidator::new(chain(), SignedSchemaAllowlist::default());
        let mut transaction = base_transaction();
        transaction.gas_price = None;
        transaction.max_priority_fee_per_gas = Some(U256::from(3));
        transaction.max_fee_per_gas = Some(U256::from(2));
        let error = validator.validate(UntrustedOperation::Transaction(transaction));
        assert!(matches!(
            error,
            Err(ProtocolError {
                kind: ProtocolErrorKind::InvalidNumericInvariant,
                ..
            })
        ));
    }
}
