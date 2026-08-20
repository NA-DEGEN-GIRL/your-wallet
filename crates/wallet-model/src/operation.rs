use core::fmt;

use crate::{Address20, BoundedBytes, CanonicalEncode, CodecError, Hash32, Transcript, U256};

/// Maximum calldata accepted by the canonical signing boundary.
pub const MAX_CALLDATA_BYTES: usize = 131_072;
/// Maximum personal-sign message length.
pub const MAX_MESSAGE_BYTES: usize = 1_048_576;
/// Maximum number of EIP-2930 access-list addresses.
pub const MAX_ACCESS_LIST_ENTRIES: usize = 256;
/// Maximum storage keys accepted for one access-list address.
pub const MAX_STORAGE_KEYS_PER_ENTRY: usize = 1_024;

/// Explicit recipient semantics for a transaction.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum TransactionTarget {
    /// Contract creation (`to` is the empty byte string in the signing payload).
    Create,
    /// Call or plain transfer to an address.
    Call(Address20),
}

impl fmt::Debug for TransactionTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create => formatter.write_str("TransactionTarget::Create"),
            Self::Call(_) => formatter.write_str("TransactionTarget::Call([REDACTED])"),
        }
    }
}

impl CanonicalEncode for TransactionTarget {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        match self {
            Self::Create => transcript.push_u8(0),
            Self::Call(address) => {
                transcript.push_u8(1);
                address.encode(transcript)?;
            }
        }
        Ok(())
    }
}

/// Untrusted access-list entry before duplicate and size validation.
#[derive(Clone, Eq, PartialEq)]
pub struct UntrustedAccessListEntry {
    /// Account whose storage is warmed.
    pub address: Address20,
    /// Storage slots in source order.
    pub storage_keys: Vec<Hash32>,
}

impl fmt::Debug for UntrustedAccessListEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UntrustedAccessListEntry")
            .field("address", &"[REDACTED]")
            .field("storage_keys", &"[REDACTED]")
            .field("storage_key_count", &self.storage_keys.len())
            .finish()
    }
}

/// Validated access-list entry.
#[derive(Clone, Eq, PartialEq)]
pub struct AccessListEntry {
    address: Address20,
    storage_keys: Vec<Hash32>,
}

impl fmt::Debug for AccessListEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessListEntry")
            .field("address", &"[REDACTED]")
            .field("storage_keys", &"[REDACTED]")
            .field("storage_key_count", &self.storage_keys.len())
            .finish()
    }
}

impl AccessListEntry {
    /// Constructs an entry after external validation.
    #[must_use]
    pub const fn from_validated(address: Address20, storage_keys: Vec<Hash32>) -> Self {
        Self {
            address,
            storage_keys,
        }
    }

    /// Returns the warmed account.
    #[must_use]
    pub const fn address(&self) -> Address20 {
        self.address
    }

    /// Returns storage slots in signing order.
    #[must_use]
    pub fn storage_keys(&self) -> &[Hash32] {
        &self.storage_keys
    }
}

impl CanonicalEncode for AccessListEntry {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        self.address.encode(transcript)?;
        self.storage_keys.encode(transcript)
    }
}

/// Browser/RPC transaction fields before type inference and validation.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct UntrustedTransaction {
    /// Optional explicit envelope type (`0`, `1`, or `2`).
    pub envelope_type: Option<u8>,
    /// Chain ID supplied by the caller or RPC preparation stage.
    pub chain_id: Option<U256>,
    /// Prepared account nonce.
    pub nonce: Option<U256>,
    /// Prepared gas limit.
    pub gas_limit: Option<U256>,
    /// Legacy/type-1 gas price.
    pub gas_price: Option<U256>,
    /// Type-2 priority fee.
    pub max_priority_fee_per_gas: Option<U256>,
    /// Type-2 total fee cap.
    pub max_fee_per_gas: Option<U256>,
    /// Explicit target. `None` means the field has not yet been normalized.
    pub target: Option<TransactionTarget>,
    /// Native value, defaulting to zero during validation.
    pub value: Option<U256>,
    /// Untrusted calldata.
    pub data: Vec<u8>,
    /// Access list; presence is significant for inference, even when empty.
    pub access_list: Option<Vec<UntrustedAccessListEntry>>,
}

impl fmt::Debug for UntrustedTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UntrustedTransaction")
            .field("envelope_type", &self.envelope_type)
            .field("chain_id", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("gas_limit", &"[REDACTED]")
            .field("gas_price", &"[REDACTED]")
            .field("max_priority_fee_per_gas", &"[REDACTED]")
            .field("max_fee_per_gas", &"[REDACTED]")
            .field("target", &self.target)
            .field("value", &"[REDACTED]")
            .field("data", &"[REDACTED]")
            .field("calldata_len", &self.data.len())
            .field("access_list", &"[REDACTED]")
            .field(
                "access_list_entries",
                &self.access_list.as_ref().map(Vec::len),
            )
            .finish()
    }
}

/// Untrusted digest-ready EIP-712 v4 request.
#[derive(Clone, Eq, PartialEq)]
pub struct UntrustedTypedDataV4 {
    /// EIP-712 domain separator computed by a separately tested parser.
    pub domain_separator: Hash32,
    /// Hash of the primary message struct.
    pub message_hash: Hash32,
    /// SHA-256 digest of the exact canonical source JSON shown to the user.
    pub source_document_hash: Hash32,
    /// Domain chain ID, if the domain declares one.
    pub chain_id: Option<U256>,
    /// Domain verifying contract, if declared.
    pub verifying_contract: Option<Address20>,
    /// Signed schema identifier offered as an exception when domain fields are absent.
    pub schema_id: Option<Hash32>,
}

impl fmt::Debug for UntrustedTypedDataV4 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UntrustedTypedDataV4")
            .field("domain_separator", &"[REDACTED]")
            .field("message_hash", &"[REDACTED]")
            .field("source_document_hash", &"[REDACTED]")
            .field("chain_id", &"[REDACTED]")
            .field("verifying_contract", &"[REDACTED]")
            .field("schema_id", &"[REDACTED]")
            .finish()
    }
}

/// An untrusted signing operation admitted at the protocol boundary.
#[derive(Clone, Eq, PartialEq)]
pub enum UntrustedOperation {
    /// Transaction request.
    Transaction(UntrustedTransaction),
    /// EIP-191 personal message bytes.
    PersonalMessage(Vec<u8>),
    /// Pre-parsed EIP-712 v4 data.
    TypedDataV4(UntrustedTypedDataV4),
}

impl fmt::Debug for UntrustedOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transaction(transaction) => formatter
                .debug_tuple("UntrustedOperation::Transaction")
                .field(transaction)
                .finish(),
            Self::PersonalMessage(message) => formatter
                .debug_struct("UntrustedOperation::PersonalMessage")
                .field("message", &"[REDACTED]")
                .field("bytes", &message.len())
                .finish(),
            Self::TypedDataV4(typed_data) => formatter
                .debug_tuple("UntrustedOperation::TypedDataV4")
                .field(typed_data)
                .finish(),
        }
    }
}

/// Canonical EIP-155 legacy transaction.
#[derive(Clone, Eq, PartialEq)]
pub struct LegacyTransaction {
    /// Non-zero EIP-155 chain ID.
    pub chain_id: U256,
    /// Account nonce.
    pub nonce: U256,
    /// Gas price.
    pub gas_price: U256,
    /// Gas limit.
    pub gas_limit: U256,
    /// Transaction target.
    pub target: TransactionTarget,
    /// Native value.
    pub value: U256,
    /// Calldata.
    pub data: BoundedBytes<MAX_CALLDATA_BYTES>,
}

impl fmt::Debug for LegacyTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyTransaction")
            .field("chain_id", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("gas_price", &"[REDACTED]")
            .field("gas_limit", &"[REDACTED]")
            .field("target", &self.target)
            .field("value", &"[REDACTED]")
            .field("data", &"[REDACTED]")
            .field("calldata_len", &self.data.len())
            .finish()
    }
}

impl CanonicalEncode for LegacyTransaction {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        self.chain_id.encode(transcript)?;
        self.nonce.encode(transcript)?;
        self.gas_price.encode(transcript)?;
        self.gas_limit.encode(transcript)?;
        self.target.encode(transcript)?;
        self.value.encode(transcript)?;
        self.data.encode(transcript)
    }
}

/// Canonical EIP-2930 type-1 transaction.
#[derive(Clone, Eq, PartialEq)]
pub struct AccessListTransaction {
    /// Non-zero EIP-155 chain ID.
    pub chain_id: U256,
    /// Account nonce.
    pub nonce: U256,
    /// Gas price.
    pub gas_price: U256,
    /// Gas limit.
    pub gas_limit: U256,
    /// Transaction target.
    pub target: TransactionTarget,
    /// Native value.
    pub value: U256,
    /// Calldata.
    pub data: BoundedBytes<MAX_CALLDATA_BYTES>,
    /// Validated, order-preserving access list.
    pub access_list: Vec<AccessListEntry>,
}

impl fmt::Debug for AccessListTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessListTransaction")
            .field("chain_id", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("gas_price", &"[REDACTED]")
            .field("gas_limit", &"[REDACTED]")
            .field("target", &self.target)
            .field("value", &"[REDACTED]")
            .field("data", &"[REDACTED]")
            .field("calldata_len", &self.data.len())
            .field("access_list", &"[REDACTED]")
            .field("access_list_entries", &self.access_list.len())
            .finish()
    }
}

impl CanonicalEncode for AccessListTransaction {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        self.chain_id.encode(transcript)?;
        self.nonce.encode(transcript)?;
        self.gas_price.encode(transcript)?;
        self.gas_limit.encode(transcript)?;
        self.target.encode(transcript)?;
        self.value.encode(transcript)?;
        self.data.encode(transcript)?;
        self.access_list.encode(transcript)
    }
}

/// Canonical EIP-1559 type-2 transaction.
#[derive(Clone, Eq, PartialEq)]
pub struct DynamicFeeTransaction {
    /// Non-zero EIP-155 chain ID.
    pub chain_id: U256,
    /// Account nonce.
    pub nonce: U256,
    /// Maximum priority fee per gas.
    pub max_priority_fee_per_gas: U256,
    /// Maximum total fee per gas.
    pub max_fee_per_gas: U256,
    /// Gas limit.
    pub gas_limit: U256,
    /// Transaction target.
    pub target: TransactionTarget,
    /// Native value.
    pub value: U256,
    /// Calldata.
    pub data: BoundedBytes<MAX_CALLDATA_BYTES>,
    /// Validated, order-preserving access list.
    pub access_list: Vec<AccessListEntry>,
}

impl fmt::Debug for DynamicFeeTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DynamicFeeTransaction")
            .field("chain_id", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("max_priority_fee_per_gas", &"[REDACTED]")
            .field("max_fee_per_gas", &"[REDACTED]")
            .field("gas_limit", &"[REDACTED]")
            .field("target", &self.target)
            .field("value", &"[REDACTED]")
            .field("data", &"[REDACTED]")
            .field("calldata_len", &self.data.len())
            .field("access_list", &"[REDACTED]")
            .field("access_list_entries", &self.access_list.len())
            .finish()
    }
}

impl CanonicalEncode for DynamicFeeTransaction {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        self.chain_id.encode(transcript)?;
        self.nonce.encode(transcript)?;
        self.max_priority_fee_per_gas.encode(transcript)?;
        self.max_fee_per_gas.encode(transcript)?;
        self.gas_limit.encode(transcript)?;
        self.target.encode(transcript)?;
        self.value.encode(transcript)?;
        self.data.encode(transcript)?;
        self.access_list.encode(transcript)
    }
}

/// Canonical personal-sign message.
#[derive(Clone, Eq, PartialEq)]
pub struct PersonalMessage {
    /// Exact message bytes.
    pub message: BoundedBytes<MAX_MESSAGE_BYTES>,
}

impl fmt::Debug for PersonalMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersonalMessage")
            .field("message", &"[REDACTED]")
            .field("bytes", &self.message.len())
            .finish()
    }
}

impl PersonalMessage {
    /// Builds the exact EIP-191 preimage (`0x19 || "Ethereum Signed Message..."`).
    #[must_use]
    pub fn eip191_preimage(&self) -> Vec<u8> {
        const PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n";
        let decimal_length = self.message.len().to_string();
        let mut preimage = Vec::with_capacity(
            PREFIX
                .len()
                .saturating_add(decimal_length.len())
                .saturating_add(self.message.len()),
        );
        preimage.extend_from_slice(PREFIX);
        preimage.extend_from_slice(decimal_length.as_bytes());
        preimage.extend_from_slice(self.message.as_slice());
        preimage
    }
}

impl CanonicalEncode for PersonalMessage {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        self.message.encode(transcript)
    }
}

/// Validated digest-ready EIP-712 v4 payload.
#[derive(Clone, Eq, PartialEq)]
pub struct TypedDataV4 {
    /// Domain separator.
    pub domain_separator: Hash32,
    /// Primary struct hash.
    pub message_hash: Hash32,
    /// Digest of the exact canonical source document used for display.
    pub source_document_hash: Hash32,
    /// Domain chain ID, absent only under an approved signed-schema exception.
    pub chain_id: Option<U256>,
    /// Verifying contract, absent only under an approved signed-schema exception.
    pub verifying_contract: Option<Address20>,
    /// Verified schema exception used, if any.
    pub schema_exception: Option<Hash32>,
}

impl fmt::Debug for TypedDataV4 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TypedDataV4")
            .field("domain_separator", &"[REDACTED]")
            .field("message_hash", &"[REDACTED]")
            .field("source_document_hash", &"[REDACTED]")
            .field("chain_id", &"[REDACTED]")
            .field("verifying_contract", &"[REDACTED]")
            .field("schema_exception", &"[REDACTED]")
            .finish()
    }
}

impl TypedDataV4 {
    /// Returns the fixed EIP-712 digest preimage.
    #[must_use]
    pub fn eip712_preimage(&self) -> [u8; 66] {
        let mut output = [0_u8; 66];
        output[0] = 0x19;
        output[1] = 0x01;
        output[2..34].copy_from_slice(self.domain_separator.as_bytes());
        output[34..].copy_from_slice(self.message_hash.as_bytes());
        output
    }
}

impl CanonicalEncode for TypedDataV4 {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        self.domain_separator.encode(transcript)?;
        self.message_hash.encode(transcript)?;
        self.source_document_hash.encode(transcript)?;
        transcript.push_optional(self.chain_id.as_ref())?;
        transcript.push_optional(self.verifying_contract.as_ref())?;
        transcript.push_optional(self.schema_exception.as_ref())
    }
}

/// Fully validated operation that the signer is permitted to hash and sign.
#[derive(Clone, Eq, PartialEq)]
pub enum CanonicalOperation {
    /// EIP-155 legacy envelope.
    LegacyEip155(LegacyTransaction),
    /// EIP-2930 type-1 envelope.
    AccessListEip2930(AccessListTransaction),
    /// EIP-1559 type-2 envelope.
    DynamicFeeEip1559(DynamicFeeTransaction),
    /// EIP-191 personal message.
    PersonalMessage(PersonalMessage),
    /// EIP-712 v4 typed data.
    TypedDataV4(TypedDataV4),
}

impl fmt::Debug for CanonicalOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LegacyEip155(transaction) => formatter
                .debug_tuple("CanonicalOperation::LegacyEip155")
                .field(transaction)
                .finish(),
            Self::AccessListEip2930(transaction) => formatter
                .debug_tuple("CanonicalOperation::AccessListEip2930")
                .field(transaction)
                .finish(),
            Self::DynamicFeeEip1559(transaction) => formatter
                .debug_tuple("CanonicalOperation::DynamicFeeEip1559")
                .field(transaction)
                .finish(),
            Self::PersonalMessage(message) => formatter
                .debug_tuple("CanonicalOperation::PersonalMessage")
                .field(message)
                .finish(),
            Self::TypedDataV4(typed_data) => formatter
                .debug_tuple("CanonicalOperation::TypedDataV4")
                .field(typed_data)
                .finish(),
        }
    }
}

impl CanonicalOperation {
    /// Returns the stable transcript tag for this operation kind.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::LegacyEip155(_) => 0,
            Self::AccessListEip2930(_) => 1,
            Self::DynamicFeeEip1559(_) => 2,
            Self::PersonalMessage(_) => 3,
            Self::TypedDataV4(_) => 4,
        }
    }

    /// Returns the transaction chain ID, when the operation carries one.
    #[must_use]
    pub const fn chain_id(&self) -> Option<U256> {
        match self {
            Self::LegacyEip155(transaction) => Some(transaction.chain_id),
            Self::AccessListEip2930(transaction) => Some(transaction.chain_id),
            Self::DynamicFeeEip1559(transaction) => Some(transaction.chain_id),
            Self::TypedDataV4(typed_data) => typed_data.chain_id,
            Self::PersonalMessage(_) => None,
        }
    }
}

impl CanonicalEncode for CanonicalOperation {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        transcript.push_u8(self.tag());
        match self {
            Self::LegacyEip155(value) => value.encode(transcript),
            Self::AccessListEip2930(value) => value.encode(transcript),
            Self::DynamicFeeEip1559(value) => value.encode(transcript),
            Self::PersonalMessage(value) => value.encode(transcript),
            Self::TypedDataV4(value) => value.encode(transcript),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BoundedBytes, CanonicalOperation, DynamicFeeTransaction, PersonalMessage};
    use crate::{Address20, ParseValueError, TransactionTarget, U256};

    #[test]
    fn operation_debug_redacts_addresses_calldata_messages_and_amounts()
    -> Result<(), ParseValueError> {
        let transaction = CanonicalOperation::DynamicFeeEip1559(DynamicFeeTransaction {
            chain_id: U256::from_u64(1),
            nonce: U256::from_u64(77),
            max_priority_fee_per_gas: U256::from_u64(123),
            max_fee_per_gas: U256::from_u64(456),
            gas_limit: U256::from_u64(21_000),
            target: TransactionTarget::Call(Address20::new([0x5a; 20])),
            value: U256::from_u64(999),
            data: BoundedBytes::new(vec![0xde, 0xad, 0xbe, 0xef])?,
            access_list: Vec::new(),
        });
        let message = CanonicalOperation::PersonalMessage(PersonalMessage {
            message: BoundedBytes::new(b"do-not-log-this-message".to_vec())?,
        });

        let rendered = format!("{transaction:?} {message:?}");
        assert!(rendered.contains("DynamicFeeEip1559"));
        assert!(rendered.contains("PersonalMessage"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("222, 173, 190, 239"));
        assert!(!rendered.contains("90, 90, 90"));
        assert!(!rendered.contains("do-not-log-this-message"));
        assert!(!rendered.contains("999"));
        Ok(())
    }

    #[test]
    fn personal_sign_prefix_uses_decimal_byte_length() -> Result<(), ParseValueError> {
        let message = PersonalMessage {
            message: BoundedBytes::new(vec![0_u8; 12])?,
        };
        assert!(
            message
                .eip191_preimage()
                .starts_with(b"\x19Ethereum Signed Message:\n12")
        );
        Ok(())
    }
}
