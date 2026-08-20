//! Typed signing for validated wallet operations.
//!
//! This module intentionally exports no raw digest-signing function. It derives
//! the signing prehash independently from a typed canonical operation.

use core::fmt;

use sha3::{Digest as _, Keccak256};
use wallet_model::{AccessListEntry, CanonicalOperation, TransactionTarget, U256};
use wallet_protocol::AuthorizedOperation;

use crate::{RawPrivateKey, SecretError};

/// Recoverable deterministic signature for one canonical wallet operation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CanonicalSignature {
    signing_prehash: [u8; 32],
    compact: [u8; 64],
    recovery_id: u8,
}

/// Result of consuming an authorized operation in the secret signer.
///
/// The canonical operation is returned only after the private-key operation so
/// the caller can independently encode and post-validate the produced
/// signature without retaining a reusable authorization capability.
#[derive(Clone, Eq, PartialEq)]
pub struct SignedCanonicalOperation {
    signature: CanonicalSignature,
    operation: CanonicalOperation,
}

impl fmt::Debug for SignedCanonicalOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedCanonicalOperation")
            .field("signature", &"[REDACTED]")
            .field("operation", &operation_kind(&self.operation))
            .finish()
    }
}

const fn operation_kind(operation: &CanonicalOperation) -> &'static str {
    match operation {
        CanonicalOperation::LegacyEip155(_) => "LegacyEip155",
        CanonicalOperation::AccessListEip2930(_) => "AccessListEip2930",
        CanonicalOperation::DynamicFeeEip1559(_) => "DynamicFeeEip1559",
        CanonicalOperation::PersonalMessage(_) => "PersonalMessage",
        CanonicalOperation::TypedDataV4(_) => "TypedDataV4",
    }
}

impl SignedCanonicalOperation {
    /// Consumes the result into the signature and the exact signed operation.
    #[must_use]
    pub fn into_parts(self) -> (CanonicalSignature, CanonicalOperation) {
        (self.signature, self.operation)
    }
}

impl fmt::Debug for CanonicalSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalSignature([REDACTED])")
    }
}

impl CanonicalSignature {
    /// Returns the exact digest independently derived from the operation.
    #[must_use]
    pub const fn signing_prehash(&self) -> &[u8; 32] {
        &self.signing_prehash
    }

    /// Returns fixed-width `r || s` bytes.
    #[must_use]
    pub const fn compact(&self) -> &[u8; 64] {
        &self.compact
    }

    /// Returns Ethereum `yParity`, restricted to zero or one.
    #[must_use]
    pub const fn recovery_id(&self) -> u8 {
        self.recovery_id
    }
}

impl RawPrivateKey {
    /// Signs exactly one typed canonical operation.
    ///
    /// The caller never supplies a digest, preventing an accidental raw-sign
    /// bypass around the canonical operation boundary.
    ///
    /// # Errors
    ///
    /// Returns an error if key reconstruction, signing, recovery-ID conversion,
    /// or a fixed cryptographic invariant fails.
    pub fn sign_authorized_operation(
        &self,
        authorization: AuthorizedOperation,
    ) -> Result<SignedCanonicalOperation, SecretError> {
        let operation = authorization.into_canonical();
        let preimage = signing_preimage(&operation);
        let signing_prehash = keccak_array(&preimage);
        let signature = self.sign_recoverable_prehash(signing_prehash)?;
        let (recovery_id, compact) = signature.serialize_compact();
        let recovery_id =
            u8::try_from(i32::from(recovery_id)).map_err(|_| SecretError::CryptographicFailure)?;
        if recovery_id > 1 {
            return Err(SecretError::CryptographicFailure);
        }
        Ok(SignedCanonicalOperation {
            signature: CanonicalSignature {
                signing_prehash,
                compact,
                recovery_id,
            },
            operation,
        })
    }
}

fn signing_preimage(operation: &CanonicalOperation) -> Vec<u8> {
    match operation {
        CanonicalOperation::LegacyEip155(transaction) => rlp_list(&[
            rlp_u256(transaction.nonce),
            rlp_u256(transaction.gas_price),
            rlp_u256(transaction.gas_limit),
            rlp_target(transaction.target),
            rlp_u256(transaction.value),
            rlp_bytes(transaction.data.as_slice()),
            rlp_u256(transaction.chain_id),
            rlp_bytes(&[]),
            rlp_bytes(&[]),
        ]),
        CanonicalOperation::AccessListEip2930(transaction) => typed_envelope(
            1,
            rlp_list(&[
                rlp_u256(transaction.chain_id),
                rlp_u256(transaction.nonce),
                rlp_u256(transaction.gas_price),
                rlp_u256(transaction.gas_limit),
                rlp_target(transaction.target),
                rlp_u256(transaction.value),
                rlp_bytes(transaction.data.as_slice()),
                rlp_access_list(&transaction.access_list),
            ]),
        ),
        CanonicalOperation::DynamicFeeEip1559(transaction) => typed_envelope(
            2,
            rlp_list(&[
                rlp_u256(transaction.chain_id),
                rlp_u256(transaction.nonce),
                rlp_u256(transaction.max_priority_fee_per_gas),
                rlp_u256(transaction.max_fee_per_gas),
                rlp_u256(transaction.gas_limit),
                rlp_target(transaction.target),
                rlp_u256(transaction.value),
                rlp_bytes(transaction.data.as_slice()),
                rlp_access_list(&transaction.access_list),
            ]),
        ),
        CanonicalOperation::PersonalMessage(message) => message.eip191_preimage(),
        CanonicalOperation::TypedDataV4(typed_data) => typed_data.eip712_preimage().to_vec(),
    }
}

fn typed_envelope(kind: u8, mut payload: Vec<u8>) -> Vec<u8> {
    payload.insert(0, kind);
    payload
}

fn rlp_target(target: TransactionTarget) -> Vec<u8> {
    match target {
        TransactionTarget::Create => rlp_bytes(&[]),
        TransactionTarget::Call(address) => rlp_bytes(address.as_bytes()),
    }
}

fn rlp_access_list(entries: &[AccessListEntry]) -> Vec<u8> {
    let encoded: Vec<_> = entries
        .iter()
        .map(|entry| {
            let keys: Vec<_> = entry
                .storage_keys()
                .iter()
                .map(|key| rlp_bytes(key.as_bytes()))
                .collect();
            rlp_list(&[rlp_bytes(entry.address().as_bytes()), rlp_list(&keys)])
        })
        .collect();
    rlp_list(&encoded)
}

fn rlp_u256(value: U256) -> Vec<u8> {
    rlp_integer_bytes(value.as_be_bytes())
}

fn rlp_integer_bytes(bytes: &[u8]) -> Vec<u8> {
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    rlp_bytes(&bytes[first..])
}

fn rlp_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return vec![bytes[0]];
    }
    let mut output = Vec::new();
    encode_length(0x80, 0xb7, bytes.len(), &mut output);
    output.extend_from_slice(bytes);
    output
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_length = items
        .iter()
        .fold(0_usize, |total, item| total.saturating_add(item.len()));
    let mut output = Vec::new();
    encode_length(0xc0, 0xf7, payload_length, &mut output);
    for item in items {
        output.extend_from_slice(item);
    }
    output
}

fn encode_length(short_base: u8, long_base: u8, length: usize, output: &mut Vec<u8>) {
    if length <= 55 {
        output.push(short_base.saturating_add(u8::try_from(length).unwrap_or(55)));
        return;
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    let significant = &bytes[first..];
    output.push(long_base.saturating_add(u8::try_from(significant.len()).unwrap_or(8)));
    output.extend_from_slice(significant);
}

fn keccak_array(bytes: &[u8]) -> [u8; 32] {
    let digest = Keccak256::digest(bytes);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

#[cfg(test)]
mod tests {
    use wallet_model::{BoundedBytes, PersonalMessage};

    use super::{CanonicalSignature, SignedCanonicalOperation};

    #[test]
    fn signed_operation_debug_reveals_only_operation_kind() -> Result<(), Box<dyn std::error::Error>>
    {
        let marker = b"private-debug-marker";
        let signed = SignedCanonicalOperation {
            signature: CanonicalSignature {
                signing_prehash: [0x41; 32],
                compact: [0x42; 64],
                recovery_id: 1,
            },
            operation: wallet_model::CanonicalOperation::PersonalMessage(PersonalMessage {
                message: BoundedBytes::new(marker.to_vec())?,
            }),
        };

        let rendered = format!("{signed:?}");
        assert!(rendered.contains("PersonalMessage"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("private-debug-marker"));
        assert!(!rendered.contains("65, 65"));
        assert!(!rendered.contains("66, 66"));
        Ok(())
    }
}
