//! Narrow, fail-closed JSON-RPC client for the standalone Sepolia demo.
//!
//! This module is intentionally independent from the production wallet IPC and
//! release-attestation paths. It exposes no general-purpose JSON-RPC method and
//! has no endpoint override: every request goes to the one compiled HTTPS
//! Sepolia endpoint. Values that can identify an account or transaction use
//! explicitly redacted `Debug` implementations.

use std::fmt;
use std::io::Read as _;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::de::{DeserializeOwned, Deserializer, IgnoredAny, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::erc20::{
    TokenAmount, balance_of_call_data, decimals_call_data, symbol_call_data, transfer_call_data,
};
use crate::ui::SessionPermit;

/// Ethereum Sepolia's EIP-155 chain identifier.
pub const SEPOLIA_CHAIN_ID: u64 = 11_155_111;

/// The sole endpoint compiled into this disposable testnet demo.
pub const SEPOLIA_RPC_ENDPOINT: &str = "https://ethereum-sepolia-rpc.publicnode.com";

const SEPOLIA_CHAIN_ID_QUANTITY: &str = "0xaa36a7";
const SEPOLIA_GENESIS_HASH: [u8; 32] = [
    0x25, 0xa5, 0xcc, 0x10, 0x6e, 0xea, 0x71, 0x38, 0xac, 0xab, 0x33, 0x23, 0x1d, 0x71, 0x60, 0xd6,
    0x9c, 0xb7, 0x77, 0xee, 0x0c, 0x2c, 0x55, 0x3f, 0xcd, 0xdf, 0x51, 0x38, 0x99, 0x3e, 0x6d, 0xd9,
];
const JSON_RPC_VERSION: &str = "2.0";
const JSON_RPC_ID: u64 = 1;
const MAX_REQUEST_BYTES: usize = 4 * 1024;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_RAW_TRANSACTION_BYTES: usize = 512;
const MAX_RECEIPT_LOGS: usize = 128;
const MAX_RECEIPT_LOG_TOPICS: usize = 4;
const MAX_RECEIPT_LOG_DATA_BYTES: usize = 8 * 1024;
const MAX_BLOCK_TRANSACTIONS: usize = 3 * 1024;
const MAX_BLOCK_UNCLES: usize = 2;
const MAX_BLOCK_WITHDRAWALS: usize = 64;
const MAX_BLOCK_EXTRA_DATA_BYTES: usize = 32;
const MAX_REMOTE_ERROR_MESSAGE_BYTES: usize = 1024;
#[cfg_attr(not(test), allow(dead_code))]
const MAX_CONTRACT_CODE_BYTES: usize = 64 * 1024;
#[cfg_attr(not(test), allow(dead_code))]
const MAX_CONTRACT_CALL_RESULT_BYTES: usize = 4 * 1024;
const GLOBAL_TIMEOUT: Duration = Duration::from_secs(12);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(4);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(8);
const VERIFY_ATTEMPTS: usize = 3;
const VERIFY_RETRY_DELAY: Duration = Duration::from_millis(150);

/// Exact 20-byte account address.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Address20([u8; 20]);

impl Address20 {
    /// Construct an address from its exact bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Borrow the exact address bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl fmt::Debug for Address20 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Address20([REDACTED])")
    }
}

/// Bounded bytecode returned by `eth_getCode` for one pinned-Sepolia address.
///
/// The bytes are deliberately opaque to callers except for an empty-code check
/// and a borrowed view used by the token policy. They are never rendered in
/// diagnostics.
#[derive(Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct ContractCode(Vec<u8>);

#[cfg_attr(not(test), allow(dead_code))]
impl ContractCode {
    /// Whether the address had no code in the pending state.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrow the bounded bytecode for a local hash or exact comparison.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ContractCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContractCode([REDACTED])")
    }
}

/// Bounded bytes returned by one allowlisted read-only `eth_call`.
#[derive(Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct ContractCallResult(Vec<u8>);

#[cfg_attr(not(test), allow(dead_code))]
impl ContractCallResult {
    /// Borrow the bounded ABI result for strict local decoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ContractCallResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContractCallResult([REDACTED])")
    }
}

/// One unsigned 256-bit RPC quantity in big-endian byte order.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Quantity256([u8; 32]);

impl Quantity256 {
    /// The zero quantity.
    pub const ZERO: Self = Self([0; 32]);

    /// Construct an RPC quantity from exact big-endian bytes.
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the exact big-endian bytes.
    #[must_use]
    pub const fn as_be_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn checked_add(self, other: Self) -> Option<Self> {
        let mut output = [0_u8; 32];
        let mut carry = 0_u16;
        for index in (0..32).rev() {
            let sum = u16::from(self.0[index]) + u16::from(other.0[index]) + carry;
            output[index] = sum as u8;
            carry = sum >> 8;
        }
        (carry == 0).then_some(Self(output))
    }

    fn checked_sub(self, other: Self) -> Option<Self> {
        let mut output = [0_u8; 32];
        let mut borrow = 0_u16;
        for index in (0..32).rev() {
            let minuend = u16::from(self.0[index]);
            let subtrahend = u16::from(other.0[index]) + borrow;
            if minuend >= subtrahend {
                output[index] = (minuend - subtrahend) as u8;
                borrow = 0;
            } else {
                output[index] = (minuend + 256 - subtrahend) as u8;
                borrow = 1;
            }
        }
        (borrow == 0).then_some(Self(output))
    }
}

impl fmt::Debug for Quantity256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Quantity256([REDACTED])")
    }
}

/// Exact transaction hash returned by the Sepolia endpoint.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct TransactionHash([u8; 32]);

impl TransactionHash {
    /// Construct a transaction hash from its exact bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the exact hash bytes for comparison with the locally computed
    /// Keccak-256 transaction hash.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact execution block hash returned by the Sepolia endpoint.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct BlockHash([u8; 32]);

impl BlockHash {
    /// Construct a block hash from its exact bytes.
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the exact hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for BlockHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BlockHash([REDACTED])")
    }
}

/// One canonical block-number/hash pair.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BlockAnchor {
    /// Canonical execution block number, bounded to `u64`.
    pub number: u64,
    /// Canonical execution block hash.
    pub hash: BlockHash,
}

impl fmt::Debug for BlockAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BlockAnchor([REDACTED])")
    }
}

/// Minimal canonical execution block header used for confirmation tracking.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BlockHeader {
    /// Canonical execution block number, bounded to `u64`.
    pub number: u64,
    /// Canonical execution block hash.
    pub hash: BlockHash,
}

impl fmt::Debug for BlockHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BlockHeader([REDACTED])")
    }
}

/// Bounded transaction input observed from Sepolia.
#[derive(Clone, Eq, PartialEq)]
pub struct TransactionInput(Vec<u8>);

impl TransactionInput {
    /// Borrow the exact input bytes. The result never exceeds the signed raw
    /// transaction cap used by this demo.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for TransactionInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransactionInput([REDACTED])")
    }
}

/// One strictly decoded type-2 transaction observation.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedTransaction {
    /// Transaction hash returned as part of the object itself.
    pub hash: TransactionHash,
    /// Recovered sender reported by the execution endpoint.
    pub from: Address20,
    /// Recipient or token contract. Contract-creation transactions are outside
    /// this demo's closed native/ERC-20 activity model.
    pub to: Address20,
    /// Sender nonce.
    pub nonce: Quantity256,
    /// Native value.
    pub value: Quantity256,
    /// Exact bounded transaction input.
    pub input: TransactionInput,
    /// Signed gas limit.
    pub gas: Quantity256,
    /// Signed EIP-1559 priority-fee ceiling.
    pub max_priority_fee_per_gas: Quantity256,
    /// Signed EIP-1559 total fee ceiling.
    pub max_fee_per_gas: Quantity256,
    /// EIP-1559 recovery parity retained for local signed-envelope validation.
    pub y_parity: u8,
    /// Exact ECDSA `r` scalar retained for local signed-envelope validation.
    pub r: Quantity256,
    /// Exact ECDSA `s` scalar retained for local signed-envelope validation.
    pub s: Quantity256,
    /// Inclusion anchor, or `None` only while both block fields are JSON null.
    pub block: Option<BlockAnchor>,
    /// Index in the inclusion block, or `None` only while pending.
    pub transaction_index: Option<u64>,
}

impl fmt::Debug for ObservedTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObservedTransaction([REDACTED])")
    }
}

/// Canonical receipt execution outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionStatus {
    /// EVM execution failed (`status = 0x0`).
    Failed,
    /// EVM execution succeeded (`status = 0x1`).
    Succeeded,
}

/// One strictly decoded type-2 transaction receipt.
#[derive(Clone, Eq, PartialEq)]
pub struct TransactionReceipt {
    /// Hash of the transaction this receipt describes.
    pub transaction_hash: TransactionHash,
    /// Transaction index in the anchored block.
    pub transaction_index: u64,
    /// Recovered transaction sender.
    pub from: Address20,
    /// Recipient or token contract. Contract creation is rejected.
    pub to: Address20,
    /// EVM execution status.
    pub status: TransactionStatus,
    /// Required canonical inclusion anchor.
    pub block: BlockAnchor,
    /// Gas consumed by this transaction.
    pub gas_used: Quantity256,
    /// Cumulative gas consumed at this transaction in the block.
    pub cumulative_gas_used: Quantity256,
    /// Effective fee paid per gas.
    pub effective_gas_price: Quantity256,
}

impl fmt::Debug for TransactionReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransactionReceipt([REDACTED])")
    }
}

impl fmt::Debug for TransactionHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransactionHash([REDACTED])")
    }
}

/// Conservative EIP-1559 fee inputs derived from the endpoint.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FeeQuote {
    /// Latest observed EIP-1559 base fee.
    pub base_fee_per_gas: Quantity256,
    /// Suggested priority fee. When the priority-fee method is unavailable,
    /// this is the positive difference between the legacy gas price and base
    /// fee, or zero if that gas price is not above base fee.
    pub max_priority_fee_per_gas: Quantity256,
    /// Maximum fee per gas, always `2 * base fee + priority fee`.
    pub max_fee_per_gas: Quantity256,
}

impl fmt::Debug for FeeQuote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FeeQuote([REDACTED])")
    }
}

/// Stable, payload-free RPC failure categories.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RpcError {
    /// The HTTPS request could not be completed.
    Transport,
    /// A configured request deadline elapsed.
    Timeout,
    /// The server attempted an HTTP redirect, which this client never follows.
    RedirectRejected,
    /// The endpoint returned a non-success HTTP status.
    HttpStatus,
    /// A request exceeded the local hard bound.
    RequestTooLarge,
    /// A response exceeded the local hard bound.
    ResponseTooLarge,
    /// The JSON-RPC envelope or typed result was malformed or ambiguous.
    InvalidResponse,
    /// The endpoint returned a JSON-RPC error object.
    RemoteRejected,
    /// The endpoint returned the JSON-RPC method-not-found code (`-32601`).
    MethodUnavailable,
    /// The observed chain ID or genesis hash was not exactly Sepolia.
    ChainMismatch,
    /// A read was attempted before a successful chain verification.
    ChainNotVerified,
    /// The raw transaction was empty, oversized, or not a type-2 envelope.
    RawTransactionRejected,
    /// The worker session was revoked after final chain verification and
    /// before the irreversible broadcast transport call.
    SessionRevoked,
    /// A fee computation overflowed 256 bits.
    NumericOverflow,
}

impl fmt::Debug for RpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Transport => "RpcError::Transport",
            Self::Timeout => "RpcError::Timeout",
            Self::RedirectRejected => "RpcError::RedirectRejected",
            Self::HttpStatus => "RpcError::HttpStatus",
            Self::RequestTooLarge => "RpcError::RequestTooLarge",
            Self::ResponseTooLarge => "RpcError::ResponseTooLarge",
            Self::InvalidResponse => "RpcError::InvalidResponse",
            Self::RemoteRejected => "RpcError::RemoteRejected",
            Self::MethodUnavailable => "RpcError::MethodUnavailable",
            Self::ChainMismatch => "RpcError::ChainMismatch",
            Self::ChainNotVerified => "RpcError::ChainNotVerified",
            Self::RawTransactionRejected => "RpcError::RawTransactionRejected",
            Self::SessionRevoked => "RpcError::SessionRevoked",
            Self::NumericOverflow => "RpcError::NumericOverflow",
        })
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Transport => "Sepolia RPC transport failed",
            Self::Timeout => "Sepolia RPC request timed out",
            Self::RedirectRejected => "Sepolia RPC redirect was rejected",
            Self::HttpStatus => "Sepolia RPC returned an HTTP error",
            Self::RequestTooLarge => "Sepolia RPC request exceeded its safety limit",
            Self::ResponseTooLarge => "Sepolia RPC response exceeded its safety limit",
            Self::InvalidResponse => "Sepolia RPC response was invalid",
            Self::RemoteRejected => "Sepolia RPC rejected the request",
            Self::MethodUnavailable => "Sepolia RPC method is unavailable",
            Self::ChainMismatch => "RPC endpoint is not the pinned Sepolia chain",
            Self::ChainNotVerified => "Sepolia RPC identity has not been verified",
            Self::RawTransactionRejected => "signed transaction violated the demo policy",
            Self::SessionRevoked => "wallet session was revoked before broadcast",
            Self::NumericOverflow => "Sepolia fee calculation overflowed",
        })
    }
}

impl std::error::Error for RpcError {}

/// Concrete fixed-endpoint Sepolia RPC client.
pub struct SepoliaRpc {
    transport: Box<dyn Transport>,
    chain_verified: AtomicBool,
}

impl fmt::Debug for SepoliaRpc {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SepoliaRpc([FIXED HTTPS ENDPOINT; REDACTED STATE])")
    }
}

impl Default for SepoliaRpc {
    fn default() -> Self {
        Self::new()
    }
}

impl SepoliaRpc {
    /// Construct the fixed HTTPS client. No environment, command-line, or UI
    /// value can replace the compiled endpoint.
    #[must_use]
    pub fn new() -> Self {
        Self {
            transport: Box::new(HttpTransport::new()),
            chain_verified: AtomicBool::new(false),
        }
    }

    /// Verify both the exact Sepolia chain ID and pinned execution genesis.
    pub fn verify_sepolia(&self) -> Result<(), RpcError> {
        self.chain_verified.store(false, Ordering::Release);

        for attempt in 0..VERIFY_ATTEMPTS {
            match self.verify_sepolia_once() {
                Ok(()) => {
                    self.chain_verified.store(true, Ordering::Release);
                    return Ok(());
                }
                Err(error)
                    if attempt + 1 < VERIFY_ATTEMPTS && is_retryable_verification_error(error) =>
                {
                    std::thread::sleep(VERIFY_RETRY_DELAY);
                }
                Err(error) => return Err(error),
            }
        }
        Err(RpcError::Transport)
    }

    fn verify_sepolia_once(&self) -> Result<(), RpcError> {
        let chain_id: String = self.call(RpcMethod::ChainId, json!([]))?;
        if chain_id != SEPOLIA_CHAIN_ID_QUANTITY {
            return Err(RpcError::ChainMismatch);
        }

        let genesis: GenesisBlock = self.call(RpcMethod::BlockByNumber, json!(["0x0", false]))?;
        let observed_hash = decode_fixed_hex::<32>(&genesis.hash)?;
        if observed_hash != SEPOLIA_GENESIS_HASH {
            return Err(RpcError::ChainMismatch);
        }
        Ok(())
    }

    /// Read the latest balance for one account after chain verification.
    pub fn balance(&self, address: Address20) -> Result<Quantity256, RpcError> {
        self.require_verified()?;
        let result: String = self.call(
            RpcMethod::Balance,
            json!([encode_prefixed_hex(address.as_bytes()), "latest"]),
        )?;
        parse_quantity(&result)
    }

    /// Read the pending balance for one account after chain verification.
    pub fn pending_balance(&self, address: Address20) -> Result<Quantity256, RpcError> {
        self.require_verified()?;
        let result: String = self.call(
            RpcMethod::Balance,
            json!([encode_prefixed_hex(address.as_bytes()), "pending"]),
        )?;
        parse_quantity(&result)
    }

    /// Read the pending nonce for one account after chain verification.
    pub fn pending_nonce(&self, address: Address20) -> Result<Quantity256, RpcError> {
        self.transaction_count(address, AccountStateTag::Pending)
    }

    /// Read the latest included nonce for one account after chain verification.
    pub fn latest_nonce(&self, address: Address20) -> Result<Quantity256, RpcError> {
        self.transaction_count(address, AccountStateTag::Latest)
    }

    fn transaction_count(
        &self,
        address: Address20,
        state: AccountStateTag,
    ) -> Result<Quantity256, RpcError> {
        self.require_verified()?;
        let result: RpcQuantity = self.call(
            RpcMethod::TransactionCount,
            json!([encode_prefixed_hex(address.as_bytes()), state.as_str()]),
        )?;
        Ok(result.0)
    }

    /// Observe one transaction by exact hash. JSON `null` is returned as
    /// `None`; every object is otherwise decoded through a closed type-2
    /// Sepolia schema.
    pub fn transaction_by_hash(
        &self,
        hash: TransactionHash,
    ) -> Result<Option<ObservedTransaction>, RpcError> {
        self.require_verified()?;
        let wire: Option<ObservedTransactionWire> = self.call_nullable(
            RpcMethod::TransactionByHash,
            json!([encode_prefixed_hex(hash.as_bytes())]),
        )?;
        let observed = wire.map(ObservedTransactionWire::validate).transpose()?;
        if observed
            .as_ref()
            .is_some_and(|transaction| transaction.hash != hash)
        {
            return Err(RpcError::InvalidResponse);
        }
        Ok(observed)
    }

    /// Observe one receipt by exact transaction hash. JSON `null` is returned
    /// as `None`; a present receipt must be a canonical included type-2 receipt.
    pub fn transaction_receipt(
        &self,
        hash: TransactionHash,
    ) -> Result<Option<TransactionReceipt>, RpcError> {
        self.require_verified()?;
        let wire: Option<TransactionReceiptWire> = self.call_nullable(
            RpcMethod::TransactionReceipt,
            json!([encode_prefixed_hex(hash.as_bytes())]),
        )?;
        let receipt = wire.map(TransactionReceiptWire::validate).transpose()?;
        if receipt
            .as_ref()
            .is_some_and(|receipt| receipt.transaction_hash != hash)
        {
            return Err(RpcError::InvalidResponse);
        }
        Ok(receipt)
    }

    /// Read one block header by exact canonical number. JSON `null` means that
    /// the endpoint does not currently know that height.
    pub fn block_header_by_number(&self, number: u64) -> Result<Option<BlockHeader>, RpcError> {
        self.require_verified()?;
        let wire: Option<BlockHeaderWire> = self.call_nullable(
            RpcMethod::BlockByNumber,
            json!([encode_u64_quantity(number), false]),
        )?;
        let header = wire.map(BlockHeaderWire::validate).transpose()?;
        if header
            .as_ref()
            .is_some_and(|header| header.number != number)
        {
            return Err(RpcError::InvalidResponse);
        }
        Ok(header)
    }

    /// Read the current canonical Sepolia execution head.
    pub fn latest_block_header(&self) -> Result<BlockHeader, RpcError> {
        self.require_verified()?;
        let wire: BlockHeaderWire =
            self.call(RpcMethod::BlockByNumber, json!(["latest", false]))?;
        wire.validate()
    }

    /// Read the latest observed EIP-1559 base fee after chain verification.
    pub fn latest_base_fee(&self) -> Result<Quantity256, RpcError> {
        self.require_verified()?;
        let latest: LatestBlock = self.call(RpcMethod::BlockByNumber, json!(["latest", false]))?;
        parse_quantity(&latest.base_fee_per_gas)
    }

    /// Obtain conservative EIP-1559 fee inputs.
    pub fn fee_quote(&self) -> Result<FeeQuote, RpcError> {
        let base_fee = self.latest_base_fee()?;
        let doubled_base = base_fee
            .checked_add(base_fee)
            .ok_or(RpcError::NumericOverflow)?;

        match self.call::<String>(RpcMethod::MaxPriorityFee, json!([])) {
            Ok(priority_text) => {
                let priority = parse_quantity(&priority_text)?;
                let maximum = doubled_base
                    .checked_add(priority)
                    .ok_or(RpcError::NumericOverflow)?;
                Ok(FeeQuote {
                    base_fee_per_gas: base_fee,
                    max_priority_fee_per_gas: priority,
                    max_fee_per_gas: maximum,
                })
            }
            Err(RpcError::MethodUnavailable) => {
                let gas_price: String = self.call(RpcMethod::GasPrice, json!([]))?;
                let gas_price = parse_quantity(&gas_price)?;
                let priority = gas_price.checked_sub(base_fee).unwrap_or(Quantity256::ZERO);
                let maximum = doubled_base
                    .checked_add(priority)
                    .ok_or(RpcError::NumericOverflow)?;
                Ok(FeeQuote {
                    base_fee_per_gas: base_fee,
                    max_priority_fee_per_gas: priority,
                    max_fee_per_gas: maximum,
                })
            }
            Err(error) => Err(error),
        }
    }

    /// Estimate gas for exactly one pending, unsigned EIP-1559 native transfer.
    /// The request deliberately omits `gas`; callers must separately enforce
    /// the demo's fixed 21,000-gas policy against the returned quantity.
    #[allow(clippy::too_many_arguments)]
    pub fn estimate_native_transfer_gas(
        &self,
        sender: Address20,
        recipient: Address20,
        value: Quantity256,
        nonce: Quantity256,
        max_priority_fee_per_gas: Quantity256,
        max_fee_per_gas: Quantity256,
    ) -> Result<Quantity256, RpcError> {
        self.require_verified()?;
        let transaction = NativeTransferEstimate {
            from: encode_prefixed_hex(sender.as_bytes()),
            to: encode_prefixed_hex(recipient.as_bytes()),
            value: encode_quantity(value),
            input: "0x",
            transaction_type: "0x2",
            nonce: encode_quantity(nonce),
            max_priority_fee_per_gas: encode_quantity(max_priority_fee_per_gas),
            max_fee_per_gas: encode_quantity(max_fee_per_gas),
        };
        let result: String = self.call(RpcMethod::EstimateGas, json!([transaction, "pending"]))?;
        parse_quantity(&result)
    }

    /// Read the pending-state code for one prospective token contract.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn contract_code(&self, contract: Address20) -> Result<ContractCode, RpcError> {
        self.require_verified()?;
        let result: String = self.call(
            RpcMethod::GetCode,
            json!([encode_prefixed_hex(contract.as_bytes()), "pending"]),
        )?;
        decode_bounded_hex(&result, MAX_CONTRACT_CODE_BYTES).map(ContractCode)
    }

    /// Read and return the exact pending-state ERC-20 `decimals()` result.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn erc20_decimals(&self, contract: Address20) -> Result<ContractCallResult, RpcError> {
        self.contract_call_exact(None, contract, &decimals_call_data())
    }

    /// Read and return the exact pending-state ERC-20 `symbol()` result.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn erc20_symbol(&self, contract: Address20) -> Result<ContractCallResult, RpcError> {
        self.contract_call_exact(None, contract, &symbol_call_data())
    }

    /// Read and return the exact pending-state ERC-20 `balanceOf(owner)` result.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn erc20_balance_of(
        &self,
        contract: Address20,
        owner: Address20,
    ) -> Result<ContractCallResult, RpcError> {
        self.contract_call_exact(None, contract, &balance_of_call_data(*owner.as_bytes()))
    }

    /// Simulate the exact signer-visible pending-state ERC-20 transfer.
    ///
    /// Calldata is built locally and the request binds zero native value, type
    /// 2, nonce, frozen gas limit, both EIP-1559 fee fields, and an empty access
    /// list. No generic/raw calldata seam is exposed.
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn erc20_transfer_preflight(
        &self,
        sender: Address20,
        contract: Address20,
        recipient: Address20,
        amount: TokenAmount,
        nonce: Quantity256,
        gas_limit: Quantity256,
        max_priority_fee_per_gas: Quantity256,
        max_fee_per_gas: Quantity256,
    ) -> Result<ContractCallResult, RpcError> {
        self.require_verified()?;
        let calldata = transfer_call_data(*recipient.as_bytes(), amount);
        let call = ExactTokenTransferCall {
            from: encode_prefixed_hex(sender.as_bytes()),
            to: encode_prefixed_hex(contract.as_bytes()),
            value: "0x0",
            input: encode_prefixed_hex(&calldata),
            transaction_type: "0x2",
            nonce: encode_quantity(nonce),
            gas: encode_quantity(gas_limit),
            max_priority_fee_per_gas: encode_quantity(max_priority_fee_per_gas),
            max_fee_per_gas: encode_quantity(max_fee_per_gas),
            access_list: &[],
        };
        let result: String = self.call(RpcMethod::Call, json!([call, "pending"]))?;
        decode_bounded_hex(&result, MAX_CONTRACT_CALL_RESULT_BYTES).map(ContractCallResult)
    }

    fn contract_call_exact(
        &self,
        sender: Option<Address20>,
        contract: Address20,
        calldata: &[u8],
    ) -> Result<ContractCallResult, RpcError> {
        self.require_verified()?;
        let call = ContractCall {
            from: sender.map(|address| encode_prefixed_hex(address.as_bytes())),
            to: encode_prefixed_hex(contract.as_bytes()),
            input: encode_prefixed_hex(calldata),
        };
        let result: String = self.call(RpcMethod::Call, json!([call, "pending"]))?;
        decode_bounded_hex(&result, MAX_CONTRACT_CALL_RESULT_BYTES).map(ContractCallResult)
    }

    /// Estimate pending-state gas for exactly one unsigned ERC-20 transfer.
    /// This method constructs the fixed 68-byte calldata with the local strict
    /// ABI encoder. The request omits `gas`, and always sends zero ETH.
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn estimate_erc20_transfer_gas(
        &self,
        sender: Address20,
        contract: Address20,
        recipient: Address20,
        amount: TokenAmount,
        nonce: Quantity256,
        max_priority_fee_per_gas: Quantity256,
        max_fee_per_gas: Quantity256,
    ) -> Result<Quantity256, RpcError> {
        self.require_verified()?;
        let transfer_calldata = transfer_call_data(*recipient.as_bytes(), amount);
        let transaction = TokenTransferEstimate {
            from: encode_prefixed_hex(sender.as_bytes()),
            to: encode_prefixed_hex(contract.as_bytes()),
            value: "0x0",
            input: encode_prefixed_hex(&transfer_calldata),
            transaction_type: "0x2",
            nonce: encode_quantity(nonce),
            max_priority_fee_per_gas: encode_quantity(max_priority_fee_per_gas),
            max_fee_per_gas: encode_quantity(max_fee_per_gas),
        };
        let result: String = self.call(RpcMethod::EstimateGas, json!([transaction, "pending"]))?;
        parse_quantity(&result)
    }

    /// Reverify the chain immediately before submitting a small type-2 signed
    /// transaction. The backend must compare the returned hash to its local
    /// Keccak-256 hash before reporting success.
    pub fn send_raw_transaction(
        &self,
        signed_transaction: &[u8],
        permit: &SessionPermit<'_>,
    ) -> Result<TransactionHash, RpcError> {
        if signed_transaction.is_empty()
            || signed_transaction.len() > MAX_RAW_TRANSACTION_BYTES
            || signed_transaction.first() != Some(&0x02)
        {
            return Err(RpcError::RawTransactionRejected);
        }

        // Do not rely only on an earlier read-time verification. This still
        // cannot make two HTTPS calls atomic, but it sharply narrows stale or
        // accidentally changed endpoint state before the irreversible action.
        self.verify_sepolia()?;
        // The guard deliberately lives inside this sole broadcast API, after
        // all blocking chain/genesis verification and immediately before the
        // transport call. After it succeeds, that call is the external commit
        // point and cannot be recalled by a later session revocation.
        if !permit.is_current() {
            return Err(RpcError::SessionRevoked);
        }
        let returned_hash: String = self.call(
            RpcMethod::SendRawTransaction,
            json!([encode_prefixed_hex(signed_transaction)]),
        )?;
        Ok(TransactionHash(decode_fixed_hex::<32>(&returned_hash)?))
    }

    fn require_verified(&self) -> Result<(), RpcError> {
        if self.chain_verified.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(RpcError::ChainNotVerified)
        }
    }

    fn call<T: DeserializeOwned>(&self, method: RpcMethod, params: Value) -> Result<T, RpcError> {
        let request = RpcRequest {
            jsonrpc: JSON_RPC_VERSION,
            id: JSON_RPC_ID,
            method: method.as_str(),
            params,
        };
        let request_bytes = serde_json::to_vec(&request).map_err(|_| RpcError::InvalidResponse)?;
        if request_bytes.len() > MAX_REQUEST_BYTES {
            return Err(RpcError::RequestTooLarge);
        }

        let response_bytes = self.transport.send(&request_bytes)?;
        if response_bytes.len() > MAX_RESPONSE_BYTES {
            return Err(RpcError::ResponseTooLarge);
        }
        let envelope: RpcEnvelope<T> =
            serde_json::from_slice(&response_bytes).map_err(|_| RpcError::InvalidResponse)?;
        if envelope.jsonrpc != JSON_RPC_VERSION || envelope.id != JSON_RPC_ID {
            return Err(RpcError::InvalidResponse);
        }
        match (envelope.result, envelope.error) {
            (Some(result), None) => Ok(result),
            (None, Some(error)) if error.code == -32_601 => Err(RpcError::MethodUnavailable),
            (None, Some(_)) => Err(RpcError::RemoteRejected),
            _ => Err(RpcError::InvalidResponse),
        }
    }

    fn call_nullable<T: DeserializeOwned>(
        &self,
        method: RpcMethod,
        params: Value,
    ) -> Result<Option<T>, RpcError> {
        let request = RpcRequest {
            jsonrpc: JSON_RPC_VERSION,
            id: JSON_RPC_ID,
            method: method.as_str(),
            params,
        };
        let request_bytes = serde_json::to_vec(&request).map_err(|_| RpcError::InvalidResponse)?;
        if request_bytes.len() > MAX_REQUEST_BYTES {
            return Err(RpcError::RequestTooLarge);
        }

        let response_bytes = self.transport.send(&request_bytes)?;
        if response_bytes.len() > MAX_RESPONSE_BYTES {
            return Err(RpcError::ResponseTooLarge);
        }
        let envelope: NullableRpcEnvelope<T> =
            serde_json::from_slice(&response_bytes).map_err(|_| RpcError::InvalidResponse)?;
        if envelope.jsonrpc != JSON_RPC_VERSION || envelope.id != JSON_RPC_ID {
            return Err(RpcError::InvalidResponse);
        }
        match (envelope.result, envelope.error) {
            (OptionalNullable::Null, OptionalNullable::Missing) => Ok(None),
            (OptionalNullable::Value(result), OptionalNullable::Missing) => Ok(Some(result)),
            (OptionalNullable::Missing, OptionalNullable::Value(error)) => {
                if error.code == -32_601 {
                    Err(RpcError::MethodUnavailable)
                } else {
                    Err(RpcError::RemoteRejected)
                }
            }
            _ => Err(RpcError::InvalidResponse),
        }
    }

    #[cfg(test)]
    fn with_transport(transport: impl Transport + 'static) -> Self {
        Self {
            transport: Box::new(transport),
            chain_verified: AtomicBool::new(false),
        }
    }

    /// Test-only single-response seam used to exercise the complete
    /// JSON-to-typed-RPC-to-backend authentication bridge without networking.
    #[cfg(test)]
    pub(crate) fn verified_with_single_result(result: Value) -> Self {
        let response = serde_json::to_vec(&json!({
            "jsonrpc": JSON_RPC_VERSION,
            "id": JSON_RPC_ID,
            "result": result,
        }))
        .expect("serialize bounded scripted RPC response");
        Self {
            transport: Box::new(SingleResponseTransport {
                response: std::sync::Mutex::new(Some(response)),
            }),
            chain_verified: AtomicBool::new(true),
        }
    }
}

const fn is_retryable_verification_error(error: RpcError) -> bool {
    matches!(
        error,
        RpcError::Transport | RpcError::Timeout | RpcError::HttpStatus
    )
}

trait Transport: Send + Sync {
    fn send(&self, request: &[u8]) -> Result<Vec<u8>, RpcError>;
}

#[cfg(test)]
struct SingleResponseTransport {
    response: std::sync::Mutex<Option<Vec<u8>>>,
}

#[cfg(test)]
impl Transport for SingleResponseTransport {
    fn send(&self, _request: &[u8]) -> Result<Vec<u8>, RpcError> {
        self.response
            .lock()
            .map_err(|_| RpcError::Transport)?
            .take()
            .ok_or(RpcError::Transport)
    }
}

struct HttpTransport {
    agent: ureq::Agent,
}

impl HttpTransport {
    fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .https_only(true)
            .proxy(None)
            .max_redirects(0)
            .http_status_as_error(false)
            .max_response_header_size(16 * 1024)
            .input_buffer_size(32 * 1024)
            .output_buffer_size(8 * 1024)
            .timeout_global(Some(GLOBAL_TIMEOUT))
            .timeout_resolve(Some(RESOLVE_TIMEOUT))
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_send_request(Some(IO_TIMEOUT))
            .timeout_send_body(Some(IO_TIMEOUT))
            .timeout_recv_response(Some(IO_TIMEOUT))
            .timeout_recv_body(Some(IO_TIMEOUT))
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
        }
    }
}

impl fmt::Debug for HttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HttpTransport([FIXED HTTPS ENDPOINT])")
    }
}

impl Transport for HttpTransport {
    fn send(&self, request: &[u8]) -> Result<Vec<u8>, RpcError> {
        if request.len() > MAX_REQUEST_BYTES {
            return Err(RpcError::RequestTooLarge);
        }
        let mut response = self
            .agent
            .post(SEPOLIA_RPC_ENDPOINT)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .send(request)
            .map_err(map_transport_error)?;

        let status = response.status().as_u16();
        if (300..400).contains(&status) {
            return Err(RpcError::RedirectRejected);
        }
        if status != 200 {
            return Err(RpcError::HttpStatus);
        }
        if response
            .body()
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(RpcError::ResponseTooLarge);
        }

        let mut bytes = Vec::with_capacity(4 * 1024);
        response
            .body_mut()
            .as_reader()
            .take((MAX_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| RpcError::Transport)?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(RpcError::ResponseTooLarge);
        }
        Ok(bytes)
    }
}

fn map_transport_error(error: ureq::Error) -> RpcError {
    if matches!(error, ureq::Error::Timeout(_)) {
        RpcError::Timeout
    } else {
        RpcError::Transport
    }
}

#[derive(Clone, Copy)]
enum RpcMethod {
    ChainId,
    BlockByNumber,
    Balance,
    TransactionCount,
    TransactionByHash,
    TransactionReceipt,
    MaxPriorityFee,
    GasPrice,
    EstimateGas,
    #[cfg_attr(not(test), allow(dead_code))]
    GetCode,
    #[cfg_attr(not(test), allow(dead_code))]
    Call,
    SendRawTransaction,
}

impl RpcMethod {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ChainId => "eth_chainId",
            Self::BlockByNumber => "eth_getBlockByNumber",
            Self::Balance => "eth_getBalance",
            Self::TransactionCount => "eth_getTransactionCount",
            Self::TransactionByHash => "eth_getTransactionByHash",
            Self::TransactionReceipt => "eth_getTransactionReceipt",
            Self::MaxPriorityFee => "eth_maxPriorityFeePerGas",
            Self::GasPrice => "eth_gasPrice",
            Self::EstimateGas => "eth_estimateGas",
            Self::GetCode => "eth_getCode",
            Self::Call => "eth_call",
            Self::SendRawTransaction => "eth_sendRawTransaction",
        }
    }
}

#[derive(Clone, Copy)]
enum AccountStateTag {
    Latest,
    Pending,
}

impl AccountStateTag {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Latest => "latest",
            Self::Pending => "pending",
        }
    }
}

#[derive(Serialize)]
struct RpcRequest<'method> {
    jsonrpc: &'static str,
    id: u64,
    method: &'method str,
    params: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcEnvelope<T> {
    jsonrpc: String,
    id: u64,
    result: Option<T>,
    error: Option<RemoteError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "T: Deserialize<'de>"))]
struct NullableRpcEnvelope<T> {
    jsonrpc: String,
    id: u64,
    #[serde(default)]
    result: OptionalNullable<T>,
    #[serde(default)]
    error: OptionalNullable<BoundedRemoteError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundedRemoteError {
    code: i64,
    #[serde(rename = "message")]
    _message: BoundedText<MAX_REMOTE_ERROR_MESSAGE_BYTES>,
    #[serde(rename = "data")]
    _data: Option<IgnoredAny>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteError {
    code: i64,
    #[serde(rename = "message")]
    _message: String,
    #[serde(rename = "data")]
    _data: Option<Value>,
}

#[derive(Default)]
enum OptionalNullable<T> {
    #[default]
    Missing,
    Null,
    Value(T),
}

impl<'de, T> Deserialize<'de> for OptionalNullable<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OptionalNullableVisitor<T>(PhantomData<T>);

        impl<'de, T> Visitor<'de> for OptionalNullableVisitor<T>
        where
            T: Deserialize<'de>,
        {
            type Value = OptionalNullable<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("null or one strictly typed optional RPC value")
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(OptionalNullable::Null)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(OptionalNullable::Null)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                T::deserialize(deserializer).map(OptionalNullable::Value)
            }
        }

        deserializer.deserialize_option(OptionalNullableVisitor(PhantomData))
    }
}

fn deserialize_optional_non_null<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

trait StrictRpcString: Sized {
    fn decode(text: &str) -> Result<Self, RpcError>;

    fn expectation() -> &'static str;
}

struct StrictRpcStringVisitor<T>(PhantomData<T>);

impl<'de, T: StrictRpcString> Visitor<'de> for StrictRpcStringVisitor<T> {
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(T::expectation())
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        T::decode(value).map_err(|_| E::custom(T::expectation()))
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(value)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&value)
    }
}

#[derive(Clone, Copy)]
struct RpcQuantity(Quantity256);

impl StrictRpcString for RpcQuantity {
    fn decode(text: &str) -> Result<Self, RpcError> {
        parse_strict_quantity(text).map(Self)
    }

    fn expectation() -> &'static str {
        "one canonical lowercase RPC quantity"
    }
}

impl<'de> Deserialize<'de> for RpcQuantity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(StrictRpcStringVisitor(PhantomData))
    }
}

#[derive(Clone, Copy)]
struct RpcU64(u64);

impl StrictRpcString for RpcU64 {
    fn decode(text: &str) -> Result<Self, RpcError> {
        let quantity = parse_strict_quantity(text)?;
        quantity_to_u64(quantity).map(Self)
    }

    fn expectation() -> &'static str {
        "one canonical lowercase RPC quantity fitting in u64"
    }
}

impl<'de> Deserialize<'de> for RpcU64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(StrictRpcStringVisitor(PhantomData))
    }
}

#[derive(Clone, Copy)]
struct RpcAddress20(Address20);

impl StrictRpcString for RpcAddress20 {
    fn decode(text: &str) -> Result<Self, RpcError> {
        decode_fixed_hex::<20>(text).map(Address20).map(Self)
    }

    fn expectation() -> &'static str {
        "one fixed-width hexadecimal 20-byte RPC address"
    }
}

impl<'de> Deserialize<'de> for RpcAddress20 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(StrictRpcStringVisitor(PhantomData))
    }
}

#[derive(Clone, Copy)]
struct RpcHash32([u8; 32]);

impl StrictRpcString for RpcHash32 {
    fn decode(text: &str) -> Result<Self, RpcError> {
        decode_fixed_lower_hex::<32>(text).map(Self)
    }

    fn expectation() -> &'static str {
        "one canonical lowercase 32-byte RPC hash"
    }
}

impl<'de> Deserialize<'de> for RpcHash32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(StrictRpcStringVisitor(PhantomData))
    }
}

struct RpcData<const MAXIMUM_BYTES: usize>(Vec<u8>);

impl<const MAXIMUM_BYTES: usize> StrictRpcString for RpcData<MAXIMUM_BYTES> {
    fn decode(text: &str) -> Result<Self, RpcError> {
        decode_bounded_hex(text, MAXIMUM_BYTES).map(Self)
    }

    fn expectation() -> &'static str {
        "canonical lowercase bounded RPC data"
    }
}

impl<'de, const MAXIMUM_BYTES: usize> Deserialize<'de> for RpcData<MAXIMUM_BYTES> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(StrictRpcStringVisitor(PhantomData))
    }
}

struct RpcFixedData<const BYTES: usize>;

impl<const BYTES: usize> StrictRpcString for RpcFixedData<BYTES> {
    fn decode(text: &str) -> Result<Self, RpcError> {
        decode_fixed_lower_hex::<BYTES>(text)?;
        Ok(Self)
    }

    fn expectation() -> &'static str {
        "canonical lowercase fixed-width RPC data"
    }
}

impl<'de, const BYTES: usize> Deserialize<'de> for RpcFixedData<BYTES> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(StrictRpcStringVisitor(PhantomData))
    }
}

struct BoundedText<const MAXIMUM_BYTES: usize>;

impl<const MAXIMUM_BYTES: usize> StrictRpcString for BoundedText<MAXIMUM_BYTES> {
    fn decode(text: &str) -> Result<Self, RpcError> {
        (text.len() <= MAXIMUM_BYTES)
            .then_some(Self)
            .ok_or(RpcError::InvalidResponse)
    }

    fn expectation() -> &'static str {
        "bounded RPC text"
    }
}

impl<'de, const MAXIMUM_BYTES: usize> Deserialize<'de> for BoundedText<MAXIMUM_BYTES> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(StrictRpcStringVisitor(PhantomData))
    }
}

struct BoundedSequence<T, const MAXIMUM_ITEMS: usize> {
    _marker: PhantomData<T>,
}

impl<'de, T, const MAXIMUM_ITEMS: usize> Deserialize<'de> for BoundedSequence<T, MAXIMUM_ITEMS>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedSequenceVisitor<T, const MAXIMUM_ITEMS: usize>(PhantomData<T>);

        impl<'de, T, const MAXIMUM_ITEMS: usize> Visitor<'de> for BoundedSequenceVisitor<T, MAXIMUM_ITEMS>
        where
            T: Deserialize<'de>,
        {
            type Value = BoundedSequence<T, MAXIMUM_ITEMS>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an RPC array with at most {MAXIMUM_ITEMS} items")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut count = 0_usize;
                while sequence.next_element::<T>()?.is_some() {
                    count = count.saturating_add(1);
                    if count > MAXIMUM_ITEMS {
                        return Err(serde::de::Error::custom("RPC array exceeded its item cap"));
                    }
                }
                Ok(BoundedSequence {
                    _marker: PhantomData,
                })
            }
        }

        deserializer.deserialize_seq(BoundedSequenceVisitor(PhantomData))
    }
}

#[derive(Deserialize)]
struct GenesisBlock {
    hash: String,
}

#[derive(Deserialize)]
struct LatestBlock {
    #[serde(rename = "baseFeePerGas")]
    base_fee_per_gas: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ObservedTransactionWire {
    hash: RpcHash32,
    from: RpcAddress20,
    to: RpcAddress20,
    nonce: RpcQuantity,
    value: RpcQuantity,
    input: RpcData<MAX_RAW_TRANSACTION_BYTES>,
    gas: RpcQuantity,
    #[serde(rename = "type")]
    transaction_type: RpcQuantity,
    chain_id: RpcQuantity,
    max_priority_fee_per_gas: RpcQuantity,
    max_fee_per_gas: RpcQuantity,
    #[serde(rename = "accessList")]
    _access_list: BoundedSequence<IgnoredAny, 0>,
    #[serde(default)]
    block_number: OptionalNullable<RpcU64>,
    #[serde(default)]
    block_hash: OptionalNullable<RpcHash32>,
    #[serde(default)]
    block_timestamp: OptionalNullable<RpcU64>,
    #[serde(rename = "gasPrice")]
    _gas_price: RpcQuantity,
    #[serde(default)]
    transaction_index: OptionalNullable<RpcU64>,
    #[serde(rename = "r")]
    r: RpcQuantity,
    #[serde(rename = "s")]
    s: RpcQuantity,
    #[serde(
        rename = "v",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    v: Option<RpcQuantity>,
    #[serde(rename = "yParity")]
    y_parity: RpcQuantity,
}

impl ObservedTransactionWire {
    fn validate(self) -> Result<ObservedTransaction, RpcError> {
        let y_parity = quantity_to_u64(self.y_parity.0)?;
        if is_zero_hash(&self.hash.0)
            || quantity_to_u64(self.transaction_type.0)? != 2
            || self.chain_id.0 != quantity_from_u64(SEPOLIA_CHAIN_ID)
            || self.max_fee_per_gas.0 < self.max_priority_fee_per_gas.0
            || self.r.0 == Quantity256::ZERO
            || self.s.0 == Quantity256::ZERO
            || y_parity > 1
            || self
                .v
                .map(|v| quantity_to_u64(v.0))
                .transpose()?
                .is_some_and(|v| v != y_parity)
        {
            return Err(RpcError::InvalidResponse);
        }

        let (block, transaction_index) =
            match (self.block_number, self.block_hash, self.transaction_index) {
                (OptionalNullable::Null, OptionalNullable::Null, OptionalNullable::Null) => {
                    if matches!(self.block_timestamp, OptionalNullable::Value(_)) {
                        return Err(RpcError::InvalidResponse);
                    }
                    (None, None)
                }
                (
                    OptionalNullable::Value(number),
                    OptionalNullable::Value(hash),
                    OptionalNullable::Value(index),
                ) => {
                    if number.0 == 0
                        || is_zero_hash(&hash.0)
                        || matches!(self.block_timestamp, OptionalNullable::Null)
                    {
                        return Err(RpcError::InvalidResponse);
                    }
                    (
                        Some(BlockAnchor {
                            number: number.0,
                            hash: BlockHash(hash.0),
                        }),
                        Some(index.0),
                    )
                }
                _ => {
                    return Err(RpcError::InvalidResponse);
                }
            };

        Ok(ObservedTransaction {
            hash: TransactionHash(self.hash.0),
            from: self.from.0,
            to: self.to.0,
            nonce: self.nonce.0,
            value: self.value.0,
            input: TransactionInput(self.input.0),
            gas: self.gas.0,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas.0,
            max_fee_per_gas: self.max_fee_per_gas.0,
            y_parity: u8::try_from(y_parity).map_err(|_| RpcError::InvalidResponse)?,
            r: self.r.0,
            s: self.s.0,
            block,
            transaction_index,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TransactionReceiptWire {
    transaction_hash: RpcHash32,
    transaction_index: RpcU64,
    block_hash: RpcHash32,
    block_number: RpcU64,
    from: RpcAddress20,
    to: RpcAddress20,
    cumulative_gas_used: RpcQuantity,
    gas_used: RpcQuantity,
    #[serde(default)]
    contract_address: OptionalNullable<RpcAddress20>,
    logs: BoundedReceiptLogs,
    #[serde(rename = "logsBloom")]
    _logs_bloom: RpcFixedData<256>,
    status: RpcQuantity,
    #[serde(rename = "type")]
    transaction_type: RpcQuantity,
    effective_gas_price: RpcQuantity,
    #[serde(
        rename = "root",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    root: Option<RpcHash32>,
}

impl TransactionReceiptWire {
    fn validate(self) -> Result<TransactionReceipt, RpcError> {
        if is_zero_hash(&self.transaction_hash.0)
            || self.block_number.0 == 0
            || is_zero_hash(&self.block_hash.0)
            || quantity_to_u64(self.transaction_type.0)? != 2
            || matches!(self.contract_address, OptionalNullable::Value(_))
            || self.root.is_some()
            || self.gas_used.0 > self.cumulative_gas_used.0
        {
            return Err(RpcError::InvalidResponse);
        }
        let status = match quantity_to_u64(self.status.0)? {
            0 => TransactionStatus::Failed,
            1 => TransactionStatus::Succeeded,
            _ => return Err(RpcError::InvalidResponse),
        };
        let block = BlockAnchor {
            number: self.block_number.0,
            hash: BlockHash(self.block_hash.0),
        };
        for log in self.logs.0 {
            log.validate(
                self.transaction_hash.0,
                self.transaction_index.0,
                self.block_hash.0,
                self.block_number.0,
            )?;
        }

        Ok(TransactionReceipt {
            transaction_hash: TransactionHash(self.transaction_hash.0),
            transaction_index: self.transaction_index.0,
            from: self.from.0,
            to: self.to.0,
            status,
            block,
            gas_used: self.gas_used.0,
            cumulative_gas_used: self.cumulative_gas_used.0,
            effective_gas_price: self.effective_gas_price.0,
        })
    }
}

struct BoundedReceiptLogs(Vec<ReceiptLogWire>);

impl<'de> Deserialize<'de> for BoundedReceiptLogs {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ReceiptLogsVisitor;

        impl<'de> Visitor<'de> for ReceiptLogsVisitor {
            type Value = BoundedReceiptLogs;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "a receipt log array with at most {MAX_RECEIPT_LOGS} items"
                )
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let capacity = sequence.size_hint().unwrap_or(0).min(MAX_RECEIPT_LOGS);
                let mut logs = Vec::with_capacity(capacity);
                while let Some(log) = sequence.next_element::<ReceiptLogWire>()? {
                    if logs.len() == MAX_RECEIPT_LOGS {
                        return Err(serde::de::Error::custom(
                            "receipt log array exceeded its item cap",
                        ));
                    }
                    logs.push(log);
                }
                Ok(BoundedReceiptLogs(logs))
            }
        }

        deserializer.deserialize_seq(ReceiptLogsVisitor)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceiptLogWire {
    #[serde(rename = "address")]
    _address: RpcAddress20,
    #[serde(rename = "topics")]
    _topics: BoundedSequence<RpcHash32, MAX_RECEIPT_LOG_TOPICS>,
    #[serde(rename = "data")]
    _data: RpcData<MAX_RECEIPT_LOG_DATA_BYTES>,
    block_number: RpcU64,
    transaction_hash: RpcHash32,
    transaction_index: RpcU64,
    block_hash: RpcHash32,
    #[serde(rename = "logIndex")]
    _log_index: RpcU64,
    removed: bool,
    #[serde(
        rename = "blockTimestamp",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _block_timestamp: Option<RpcU64>,
}

impl ReceiptLogWire {
    fn validate(
        self,
        transaction_hash: [u8; 32],
        transaction_index: u64,
        block_hash: [u8; 32],
        block_number: u64,
    ) -> Result<(), RpcError> {
        if self.removed
            || self.transaction_hash.0 != transaction_hash
            || self.transaction_index.0 != transaction_index
            || self.block_hash.0 != block_hash
            || self.block_number.0 != block_number
        {
            return Err(RpcError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlockHeaderWire {
    number: RpcU64,
    hash: RpcHash32,
    #[serde(
        rename = "baseFeePerGas",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _base_fee_per_gas: Option<RpcQuantity>,
    #[serde(
        rename = "blobGasUsed",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _blob_gas_used: Option<RpcQuantity>,
    #[serde(
        rename = "difficulty",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _difficulty: Option<RpcQuantity>,
    #[serde(
        rename = "excessBlobGas",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _excess_blob_gas: Option<RpcQuantity>,
    #[serde(
        rename = "extraData",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _extra_data: Option<RpcData<MAX_BLOCK_EXTRA_DATA_BYTES>>,
    #[serde(
        rename = "gasLimit",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _gas_limit: Option<RpcQuantity>,
    #[serde(
        rename = "gasUsed",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _gas_used: Option<RpcQuantity>,
    #[serde(
        rename = "logsBloom",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _logs_bloom: Option<RpcFixedData<256>>,
    #[serde(
        rename = "miner",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _miner: Option<RpcAddress20>,
    #[serde(
        rename = "mixHash",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _mix_hash: Option<RpcHash32>,
    #[serde(
        rename = "nonce",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _nonce: Option<RpcFixedData<8>>,
    #[serde(
        rename = "parentBeaconBlockRoot",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _parent_beacon_block_root: Option<RpcHash32>,
    #[serde(
        rename = "parentHash",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _parent_hash: Option<RpcHash32>,
    #[serde(
        rename = "receiptsRoot",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _receipts_root: Option<RpcHash32>,
    #[serde(
        rename = "requestsHash",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _requests_hash: Option<RpcHash32>,
    #[serde(
        rename = "sha3Uncles",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _sha3_uncles: Option<RpcHash32>,
    #[serde(
        rename = "size",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _size: Option<RpcQuantity>,
    #[serde(
        rename = "stateRoot",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _state_root: Option<RpcHash32>,
    #[serde(
        rename = "timestamp",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _timestamp: Option<RpcU64>,
    #[serde(
        rename = "totalDifficulty",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _total_difficulty: Option<RpcQuantity>,
    #[serde(
        rename = "transactions",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _transactions: Option<BoundedSequence<RpcHash32, MAX_BLOCK_TRANSACTIONS>>,
    #[serde(
        rename = "transactionsRoot",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _transactions_root: Option<RpcHash32>,
    #[serde(
        rename = "uncles",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _uncles: Option<BoundedSequence<RpcHash32, MAX_BLOCK_UNCLES>>,
    #[serde(
        rename = "withdrawals",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _withdrawals: Option<BoundedSequence<WithdrawalWire, MAX_BLOCK_WITHDRAWALS>>,
    #[serde(
        rename = "withdrawalsRoot",
        default,
        deserialize_with = "deserialize_optional_non_null"
    )]
    _withdrawals_root: Option<RpcHash32>,
}

impl BlockHeaderWire {
    fn validate(self) -> Result<BlockHeader, RpcError> {
        if is_zero_hash(&self.hash.0) {
            return Err(RpcError::InvalidResponse);
        }
        Ok(BlockHeader {
            number: self.number.0,
            hash: BlockHash(self.hash.0),
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WithdrawalWire {
    #[serde(rename = "index")]
    _index: RpcU64,
    #[serde(rename = "validatorIndex")]
    _validator_index: RpcU64,
    #[serde(rename = "address")]
    _address: RpcAddress20,
    #[serde(rename = "amount")]
    _amount: RpcQuantity,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeTransferEstimate {
    from: String,
    to: String,
    value: String,
    input: &'static str,
    #[serde(rename = "type")]
    transaction_type: &'static str,
    nonce: String,
    max_priority_fee_per_gas: String,
    max_fee_per_gas: String,
}

#[derive(Serialize)]
#[cfg_attr(not(test), allow(dead_code))]
struct ContractCall {
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    to: String,
    input: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(not(test), allow(dead_code))]
struct TokenTransferEstimate {
    from: String,
    to: String,
    value: &'static str,
    input: String,
    #[serde(rename = "type")]
    transaction_type: &'static str,
    nonce: String,
    max_priority_fee_per_gas: String,
    max_fee_per_gas: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(not(test), allow(dead_code))]
struct ExactTokenTransferCall {
    from: String,
    to: String,
    value: &'static str,
    input: String,
    #[serde(rename = "type")]
    transaction_type: &'static str,
    nonce: String,
    gas: String,
    max_priority_fee_per_gas: String,
    max_fee_per_gas: String,
    access_list: &'static [(); 0],
}

fn parse_quantity(text: &str) -> Result<Quantity256, RpcError> {
    let digits = text.strip_prefix("0x").ok_or(RpcError::InvalidResponse)?;
    if digits.is_empty() || digits.len() > 64 || (digits.len() > 1 && digits.starts_with('0')) {
        return Err(RpcError::InvalidResponse);
    }

    let mut output = [0_u8; 32];
    for character in digits.bytes() {
        let nibble = hex_nibble(character).ok_or(RpcError::InvalidResponse)?;
        let mut carry = nibble;
        for byte in output.iter_mut().rev() {
            let shifted = (u16::from(*byte) << 4) | u16::from(carry);
            *byte = shifted as u8;
            carry = (shifted >> 8) as u8;
        }
        if carry != 0 {
            return Err(RpcError::InvalidResponse);
        }
    }
    Ok(Quantity256(output))
}

fn parse_strict_quantity(text: &str) -> Result<Quantity256, RpcError> {
    let digits = text.strip_prefix("0x").ok_or(RpcError::InvalidResponse)?;
    if !digits
        .bytes()
        .all(|byte| strict_lower_hex_nibble(byte).is_some())
    {
        return Err(RpcError::InvalidResponse);
    }
    parse_quantity(text)
}

fn quantity_from_u64(value: u64) -> Quantity256 {
    let mut bytes = [0_u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    Quantity256(bytes)
}

fn quantity_to_u64(quantity: Quantity256) -> Result<u64, RpcError> {
    if quantity.0[..24].iter().any(|byte| *byte != 0) {
        return Err(RpcError::InvalidResponse);
    }
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&quantity.0[24..]);
    Ok(u64::from_be_bytes(bytes))
}

fn encode_u64_quantity(value: u64) -> String {
    encode_quantity(quantity_from_u64(value))
}

fn is_zero_hash(hash: &[u8; 32]) -> bool {
    hash.iter().all(|byte| *byte == 0)
}

fn encode_quantity(quantity: Quantity256) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = quantity.as_be_bytes();
    let Some(first_index) = bytes.iter().position(|byte| *byte != 0) else {
        return "0x0".to_owned();
    };

    let first = bytes[first_index];
    let mut output = String::with_capacity(2 + (bytes.len() - first_index).saturating_mul(2));
    output.push_str("0x");
    if first >> 4 != 0 {
        output.push(char::from(HEX[usize::from(first >> 4)]));
    }
    output.push(char::from(HEX[usize::from(first & 0x0f)]));
    for byte in &bytes[first_index + 1..] {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_fixed_hex<const BYTES: usize>(text: &str) -> Result<[u8; BYTES], RpcError> {
    let digits = text.strip_prefix("0x").ok_or(RpcError::InvalidResponse)?;
    if digits.len() != BYTES.saturating_mul(2) {
        return Err(RpcError::InvalidResponse);
    }
    let mut output = [0_u8; BYTES];
    for (index, pair) in digits.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or(RpcError::InvalidResponse)?;
        let low = hex_nibble(pair[1]).ok_or(RpcError::InvalidResponse)?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn decode_fixed_lower_hex<const BYTES: usize>(text: &str) -> Result<[u8; BYTES], RpcError> {
    let digits = text.strip_prefix("0x").ok_or(RpcError::InvalidResponse)?;
    if digits.len() != BYTES.saturating_mul(2) {
        return Err(RpcError::InvalidResponse);
    }
    let mut output = [0_u8; BYTES];
    for (index, pair) in digits.as_bytes().chunks_exact(2).enumerate() {
        let high = strict_lower_hex_nibble(pair[0]).ok_or(RpcError::InvalidResponse)?;
        let low = strict_lower_hex_nibble(pair[1]).ok_or(RpcError::InvalidResponse)?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

#[cfg_attr(not(test), allow(dead_code))]
fn decode_bounded_hex(text: &str, maximum_bytes: usize) -> Result<Vec<u8>, RpcError> {
    let digits = text.strip_prefix("0x").ok_or(RpcError::InvalidResponse)?;
    if !digits.len().is_multiple_of(2) || digits.len() > maximum_bytes.saturating_mul(2) {
        return Err(RpcError::InvalidResponse);
    }

    let mut output = Vec::with_capacity(digits.len() / 2);
    for pair in digits.as_bytes().chunks_exact(2) {
        let high = strict_lower_hex_nibble(pair[0]).ok_or(RpcError::InvalidResponse)?;
        let low = strict_lower_hex_nibble(pair[1]).ok_or(RpcError::InvalidResponse)?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

#[cfg_attr(not(test), allow(dead_code))]
fn strict_lower_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn encode_prefixed_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(2 + bytes.len().saturating_mul(2));
    output.push_str("0x");
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicU64;
    use std::sync::{Arc, Mutex};

    use serde_json::{Value, json};

    use crate::erc20::{
        TokenAmount, balance_of_call_data, decimals_call_data, symbol_call_data, transfer_call_data,
    };
    use crate::ui::SessionPermit;

    use super::{
        Address20, FeeQuote, GLOBAL_TIMEOUT, HttpTransport, MAX_RESPONSE_BYTES, Quantity256,
        RpcError, SEPOLIA_CHAIN_ID_QUANTITY, SEPOLIA_GENESIS_HASH, SepoliaRpc, Transport,
        encode_prefixed_hex, encode_quantity, parse_quantity,
    };

    type MockResponses = Arc<Mutex<VecDeque<Result<Vec<u8>, RpcError>>>>;

    #[derive(Clone, Default)]
    struct MockTransport {
        responses: MockResponses,
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl MockTransport {
        fn new(responses: impl IntoIterator<Item = Result<Value, RpcError>>) -> Self {
            let responses = responses
                .into_iter()
                .map(|response| {
                    response.map(|value| serde_json::to_vec(&value).unwrap_or_default())
                })
                .collect();
            Self {
                responses: Arc::new(Mutex::new(responses)),
                requests: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn raw(response: Vec<u8>) -> Self {
            Self {
                responses: Arc::new(Mutex::new(VecDeque::from([Ok(response)]))),
                requests: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl Transport for MockTransport {
        fn send(&self, request: &[u8]) -> Result<Vec<u8>, RpcError> {
            self.requests
                .lock()
                .map_err(|_| RpcError::Transport)?
                .push(request.to_vec());
            self.responses
                .lock()
                .map_err(|_| RpcError::Transport)?
                .pop_front()
                .unwrap_or(Err(RpcError::Transport))
        }
    }

    fn success(result: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": 1, "result": result})
    }

    fn genesis_hex() -> String {
        encode_prefixed_hex(&SEPOLIA_GENESIS_HASH)
    }

    fn verification_responses() -> [Result<Value, RpcError>; 2] {
        [
            Ok(success(json!(SEPOLIA_CHAIN_ID_QUANTITY))),
            Ok(success(json!({"hash": genesis_hex()}))),
        ]
    }

    fn already_verified(transport: MockTransport) -> SepoliaRpc {
        let rpc = SepoliaRpc::with_transport(transport);
        rpc.chain_verified
            .store(true, std::sync::atomic::Ordering::Release);
        rpc
    }

    fn repeated_hex(byte: u8, bytes: usize) -> String {
        encode_prefixed_hex(&vec![byte; bytes])
    }

    fn typical_transaction(hash: [u8; 32], included: bool) -> Value {
        let (block_number, block_hash, block_timestamp, transaction_index) = if included {
            (
                json!("0x2a"),
                json!(repeated_hex(0x44, 32)),
                json!("0x60000000"),
                json!("0x1"),
            )
        } else {
            (Value::Null, Value::Null, Value::Null, Value::Null)
        };
        json!({
            "hash": encode_prefixed_hex(&hash),
            "from": repeated_hex(0x11, 20),
            "to": repeated_hex(0x22, 20),
            "nonce": "0x5",
            "value": "0x1234",
            "input": "0x",
            "gas": "0x5208",
            "type": "0x2",
            "chainId": SEPOLIA_CHAIN_ID_QUANTITY,
            "maxPriorityFeePerGas": "0x3",
            "maxFeePerGas": "0x64",
            "accessList": [],
            "blockNumber": block_number,
            "blockHash": block_hash,
            "blockTimestamp": block_timestamp,
            "transactionIndex": transaction_index,
            "gasPrice": "0x40",
            "r": "0x1",
            "s": "0x2",
            "v": "0x0",
            "yParity": "0x0"
        })
    }

    fn typical_receipt(hash: [u8; 32], status: &str, logs: Value) -> Value {
        json!({
            "transactionHash": encode_prefixed_hex(&hash),
            "transactionIndex": "0x1",
            "blockHash": repeated_hex(0x44, 32),
            "blockNumber": "0x2a",
            "from": repeated_hex(0x11, 20),
            "to": repeated_hex(0x22, 20),
            "cumulativeGasUsed": "0x10000",
            "gasUsed": "0x5208",
            "contractAddress": null,
            "logs": logs,
            "logsBloom": repeated_hex(0, 256),
            "status": status,
            "type": "0x2",
            "effectiveGasPrice": "0x40"
        })
    }

    fn typical_receipt_log(hash: [u8; 32]) -> Value {
        json!({
            "address": repeated_hex(0x22, 20),
            "topics": [repeated_hex(0x55, 32)],
            "data": repeated_hex(0x66, 32),
            "blockNumber": "0x2a",
            "transactionHash": encode_prefixed_hex(&hash),
            "transactionIndex": "0x1",
            "blockHash": repeated_hex(0x44, 32),
            "logIndex": "0x0",
            "removed": false
        })
    }

    fn minimal_block(number: &str, hash_byte: u8) -> Value {
        json!({
            "number": number,
            "hash": repeated_hex(hash_byte, 32)
        })
    }

    fn typical_block(number: &str, hash_byte: u8) -> Value {
        json!({
            "number": number,
            "hash": repeated_hex(hash_byte, 32),
            "baseFeePerGas": "0x20",
            "blobGasUsed": "0x0",
            "difficulty": "0x0",
            "excessBlobGas": "0x0",
            "extraData": "0x",
            "gasLimit": "0x1c9c380",
            "gasUsed": "0x5208",
            "logsBloom": repeated_hex(0, 256),
            "miner": repeated_hex(0x10, 20),
            "mixHash": repeated_hex(0x11, 32),
            "nonce": repeated_hex(0, 8),
            "parentBeaconBlockRoot": repeated_hex(0x12, 32),
            "parentHash": repeated_hex(0x13, 32),
            "receiptsRoot": repeated_hex(0x14, 32),
            "requestsHash": repeated_hex(0x15, 32),
            "sha3Uncles": repeated_hex(0x16, 32),
            "size": "0x400",
            "stateRoot": repeated_hex(0x17, 32),
            "timestamp": "0x60000000",
            "totalDifficulty": "0x0",
            "transactions": [repeated_hex(0x18, 32)],
            "transactionsRoot": repeated_hex(0x19, 32),
            "uncles": [],
            "withdrawals": [{
                "index": "0x1",
                "validatorIndex": "0x2",
                "address": repeated_hex(0x20, 20),
                "amount": "0x3"
            }],
            "withdrawalsRoot": repeated_hex(0x21, 32)
        })
    }

    #[test]
    fn quantities_are_canonical_and_bounded() -> Result<(), RpcError> {
        assert_eq!(parse_quantity("0x0")?, Quantity256::ZERO);
        assert_eq!(parse_quantity("0x1234")?.as_be_bytes()[30..], [0x12, 0x34]);
        assert_eq!(encode_quantity(Quantity256::ZERO), "0x0");
        assert_eq!(encode_quantity(parse_quantity("0x1")?), "0x1");
        assert_eq!(encode_quantity(parse_quantity("0x1234")?), "0x1234");
        let maximum = format!("0x{}", "f".repeat(64));
        assert_eq!(parse_quantity(&maximum)?.as_be_bytes(), &[0xff; 32]);
        assert_eq!(encode_quantity(parse_quantity(&maximum)?), maximum);

        for invalid in ["", "0x", "0x00", "0x01", "0X1", "0xgg"] {
            assert_eq!(parse_quantity(invalid), Err(RpcError::InvalidResponse));
        }
        assert_eq!(
            parse_quantity(&format!("0x1{}", "0".repeat(64))),
            Err(RpcError::InvalidResponse)
        );
        Ok(())
    }

    #[test]
    fn value_debug_output_is_redacted() {
        let address = Address20::new([0x41; 20]);
        let block_hash = super::BlockHash::new([0x43; 32]);
        assert_eq!(block_hash.as_bytes(), &[0x43; 32]);
        let quantity = Quantity256([0x42; 32]);
        let quote = FeeQuote {
            base_fee_per_gas: quantity,
            max_priority_fee_per_gas: quantity,
            max_fee_per_gas: quantity,
        };
        for rendered in [
            format!("{address:?}"),
            format!("{block_hash:?}"),
            format!("{quantity:?}"),
            format!("{quote:?}"),
        ] {
            assert!(rendered.contains("[REDACTED]"));
            assert!(!rendered.contains("414141"));
            assert!(!rendered.contains("424242"));
            assert!(!rendered.contains("434343"));
        }
    }

    #[test]
    fn verification_requires_exact_chain_and_genesis() {
        let wrong_chain = MockTransport::new([Ok(success(json!("0x1")))]);
        assert_eq!(
            SepoliaRpc::with_transport(wrong_chain).verify_sepolia(),
            Err(RpcError::ChainMismatch)
        );

        let wrong_genesis = MockTransport::new([
            Ok(success(json!(SEPOLIA_CHAIN_ID_QUANTITY))),
            Ok(success(json!({"hash": format!("0x{}", "00".repeat(32))}))),
        ]);
        assert_eq!(
            SepoliaRpc::with_transport(wrong_genesis).verify_sepolia(),
            Err(RpcError::ChainMismatch)
        );
    }

    #[test]
    fn verification_uses_only_exact_allowlisted_calls() -> Result<(), RpcError> {
        let transport = MockTransport::new(verification_responses());
        let observation = transport.clone();
        let rpc = SepoliaRpc::with_transport(transport);
        rpc.verify_sepolia()?;

        let requests = observation
            .requests
            .lock()
            .map_err(|_| RpcError::Transport)?;
        let first: Value = serde_json::from_slice(&requests[0]).map_err(|_| RpcError::Transport)?;
        let second: Value =
            serde_json::from_slice(&requests[1]).map_err(|_| RpcError::Transport)?;
        assert_eq!(first["method"], "eth_chainId");
        assert_eq!(first["params"], json!([]));
        assert_eq!(second["method"], "eth_getBlockByNumber");
        assert_eq!(second["params"], json!(["0x0", false]));
        Ok(())
    }

    #[test]
    fn verification_retries_only_transient_failures_and_restarts_the_pair() -> Result<(), RpcError>
    {
        let responses = [Err(RpcError::Transport)]
            .into_iter()
            .chain(verification_responses());
        let transport = MockTransport::new(responses);
        let observation = transport.clone();
        SepoliaRpc::with_transport(transport).verify_sepolia()?;
        assert_eq!(
            observation
                .requests
                .lock()
                .map_err(|_| RpcError::Transport)?
                .len(),
            3
        );

        let responses = [
            Ok(success(json!(SEPOLIA_CHAIN_ID_QUANTITY))),
            Err(RpcError::Timeout),
        ]
        .into_iter()
        .chain(verification_responses());
        let transport = MockTransport::new(responses);
        let observation = transport.clone();
        SepoliaRpc::with_transport(transport).verify_sepolia()?;
        let requests = observation
            .requests
            .lock()
            .map_err(|_| RpcError::Transport)?;
        assert_eq!(requests.len(), 4);
        let third: Value = serde_json::from_slice(&requests[2]).map_err(|_| RpcError::Transport)?;
        assert_eq!(third["method"], "eth_chainId");
        Ok(())
    }

    #[test]
    fn verification_never_retries_chain_or_schema_mismatches() -> Result<(), RpcError> {
        let transport = MockTransport::new(
            [Ok(success(json!("0x1")))]
                .into_iter()
                .chain(verification_responses()),
        );
        let observation = transport.clone();
        assert_eq!(
            SepoliaRpc::with_transport(transport).verify_sepolia(),
            Err(RpcError::ChainMismatch)
        );
        assert_eq!(
            observation
                .requests
                .lock()
                .map_err(|_| RpcError::Transport)?
                .len(),
            1
        );

        let transport = MockTransport::new([
            Err(RpcError::Transport),
            Err(RpcError::Timeout),
            Err(RpcError::HttpStatus),
        ]);
        let observation = transport.clone();
        assert_eq!(
            SepoliaRpc::with_transport(transport).verify_sepolia(),
            Err(RpcError::HttpStatus)
        );
        assert_eq!(
            observation
                .requests
                .lock()
                .map_err(|_| RpcError::Transport)?
                .len(),
            3
        );
        Ok(())
    }

    #[test]
    fn rpc_method_allowlist_is_exact() {
        use super::RpcMethod;

        let methods = [
            RpcMethod::ChainId.as_str(),
            RpcMethod::BlockByNumber.as_str(),
            RpcMethod::Balance.as_str(),
            RpcMethod::TransactionCount.as_str(),
            RpcMethod::TransactionByHash.as_str(),
            RpcMethod::TransactionReceipt.as_str(),
            RpcMethod::MaxPriorityFee.as_str(),
            RpcMethod::GasPrice.as_str(),
            RpcMethod::EstimateGas.as_str(),
            RpcMethod::GetCode.as_str(),
            RpcMethod::Call.as_str(),
            RpcMethod::SendRawTransaction.as_str(),
        ];
        assert_eq!(
            methods,
            [
                "eth_chainId",
                "eth_getBlockByNumber",
                "eth_getBalance",
                "eth_getTransactionCount",
                "eth_getTransactionByHash",
                "eth_getTransactionReceipt",
                "eth_maxPriorityFeePerGas",
                "eth_gasPrice",
                "eth_estimateGas",
                "eth_getCode",
                "eth_call",
                "eth_sendRawTransaction",
            ]
        );
    }

    #[test]
    fn reads_require_a_completed_chain_verification() {
        let rpc = SepoliaRpc::with_transport(MockTransport::default());
        let address = Address20::new([0x11; 20]);
        assert_eq!(rpc.balance(address), Err(RpcError::ChainNotVerified));
        assert_eq!(
            rpc.pending_balance(address),
            Err(RpcError::ChainNotVerified)
        );
        assert_eq!(rpc.pending_nonce(address), Err(RpcError::ChainNotVerified));
        assert_eq!(rpc.latest_nonce(address), Err(RpcError::ChainNotVerified));
        let hash = super::TransactionHash::new([0x22; 32]);
        assert_eq!(
            rpc.transaction_by_hash(hash),
            Err(RpcError::ChainNotVerified)
        );
        assert_eq!(
            rpc.transaction_receipt(hash),
            Err(RpcError::ChainNotVerified)
        );
        assert_eq!(
            rpc.block_header_by_number(1),
            Err(RpcError::ChainNotVerified)
        );
        assert_eq!(rpc.latest_block_header(), Err(RpcError::ChainNotVerified));
        assert_eq!(rpc.latest_base_fee(), Err(RpcError::ChainNotVerified));
        assert_eq!(rpc.fee_quote(), Err(RpcError::ChainNotVerified));
        assert_eq!(rpc.contract_code(address), Err(RpcError::ChainNotVerified));
        assert_eq!(rpc.erc20_decimals(address), Err(RpcError::ChainNotVerified));
        assert_eq!(rpc.erc20_symbol(address), Err(RpcError::ChainNotVerified));
        assert_eq!(
            rpc.erc20_balance_of(address, address),
            Err(RpcError::ChainNotVerified)
        );
        assert_eq!(
            rpc.erc20_transfer_preflight(
                address,
                address,
                address,
                TokenAmount::from_be_bytes([1; 32]),
                Quantity256::ZERO,
                Quantity256::ZERO,
                Quantity256::ZERO,
                Quantity256::ZERO,
            ),
            Err(RpcError::ChainNotVerified)
        );
        assert_eq!(
            rpc.estimate_native_transfer_gas(
                address,
                address,
                Quantity256::ZERO,
                Quantity256::ZERO,
                Quantity256::ZERO,
                Quantity256::ZERO,
            ),
            Err(RpcError::ChainNotVerified)
        );
        assert_eq!(
            rpc.estimate_erc20_transfer_gas(
                address,
                address,
                address,
                TokenAmount::from_be_bytes([1; 32]),
                Quantity256::ZERO,
                Quantity256::ZERO,
                Quantity256::ZERO,
            ),
            Err(RpcError::ChainNotVerified)
        );
    }

    #[test]
    fn pending_balance_and_latest_base_fee_use_exact_tags() -> Result<(), RpcError> {
        let address = Address20::new([0x11; 20]);
        let responses = verification_responses()
            .into_iter()
            .chain([Ok(success(json!("0x2a")))]);
        let transport = MockTransport::new(responses);
        let observation = transport.clone();
        let rpc = SepoliaRpc::with_transport(transport);
        rpc.verify_sepolia()?;
        assert_eq!(rpc.pending_balance(address)?, parse_quantity("0x2a")?);

        let requests = observation
            .requests
            .lock()
            .map_err(|_| RpcError::Transport)?;
        let request: Value =
            serde_json::from_slice(&requests[2]).map_err(|_| RpcError::Transport)?;
        assert_eq!(request["method"], "eth_getBalance");
        assert_eq!(
            request["params"],
            json!([encode_prefixed_hex(address.as_bytes()), "pending"])
        );
        drop(requests);

        let responses = verification_responses()
            .into_iter()
            .chain([Ok(success(json!({"baseFeePerGas": "0x64"})))]);
        let transport = MockTransport::new(responses);
        let observation = transport.clone();
        let rpc = SepoliaRpc::with_transport(transport);
        rpc.verify_sepolia()?;
        assert_eq!(rpc.latest_base_fee()?, parse_quantity("0x64")?);

        let requests = observation
            .requests
            .lock()
            .map_err(|_| RpcError::Transport)?;
        let request: Value =
            serde_json::from_slice(&requests[2]).map_err(|_| RpcError::Transport)?;
        assert_eq!(request["method"], "eth_getBlockByNumber");
        assert_eq!(request["params"], json!(["latest", false]));
        Ok(())
    }

    #[test]
    fn lifecycle_reads_use_exact_methods_params_and_typed_results() -> Result<(), RpcError> {
        let address = Address20::new([0x11; 20]);
        let hash_bytes = [0x33; 32];
        let hash = super::TransactionHash::new(hash_bytes);
        let responses = verification_responses().into_iter().chain([
            Ok(success(json!("0x6"))),
            Ok(success(json!("0x5"))),
            Ok(success(typical_transaction(hash_bytes, true))),
            Ok(success(typical_receipt(
                hash_bytes,
                "0x1",
                json!([typical_receipt_log(hash_bytes)]),
            ))),
            Ok(success(minimal_block("0x2a", 0x44))),
            Ok(success(typical_block("0x2b", 0x45))),
        ]);
        let transport = MockTransport::new(responses);
        let observation = transport.clone();
        let rpc = SepoliaRpc::with_transport(transport);
        rpc.verify_sepolia()?;

        assert_eq!(rpc.pending_nonce(address)?, parse_quantity("0x6")?);
        assert_eq!(rpc.latest_nonce(address)?, parse_quantity("0x5")?);
        let transaction = rpc
            .transaction_by_hash(hash)?
            .ok_or(RpcError::InvalidResponse)?;
        assert_eq!(transaction.hash, hash);
        assert_eq!(transaction.from, address);
        assert_eq!(transaction.to, Address20::new([0x22; 20]));
        assert!(transaction.input.as_bytes().is_empty());
        assert_eq!(transaction.block.map(|block| block.number), Some(42));
        assert_eq!(transaction.transaction_index, Some(1));
        let receipt = rpc
            .transaction_receipt(hash)?
            .ok_or(RpcError::InvalidResponse)?;
        assert_eq!(receipt.transaction_hash, hash);
        assert_eq!(receipt.status, super::TransactionStatus::Succeeded);
        assert_eq!(receipt.block.number, 42);
        assert_eq!(
            rpc.block_header_by_number(42)?.map(|header| header.number),
            Some(42)
        );
        assert_eq!(rpc.latest_block_header()?.number, 43);

        let requests = observation
            .requests
            .lock()
            .map_err(|_| RpcError::Transport)?;
        let decoded = requests
            .iter()
            .skip(2)
            .map(|request| serde_json::from_slice::<Value>(request))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RpcError::Transport)?;
        assert_eq!(decoded[0]["method"], "eth_getTransactionCount");
        assert_eq!(
            decoded[0]["params"],
            json!([encode_prefixed_hex(address.as_bytes()), "pending"])
        );
        assert_eq!(decoded[1]["method"], "eth_getTransactionCount");
        assert_eq!(
            decoded[1]["params"],
            json!([encode_prefixed_hex(address.as_bytes()), "latest"])
        );
        assert_eq!(decoded[2]["method"], "eth_getTransactionByHash");
        assert_eq!(
            decoded[2]["params"],
            json!([encode_prefixed_hex(&hash_bytes)])
        );
        assert_eq!(decoded[3]["method"], "eth_getTransactionReceipt");
        assert_eq!(
            decoded[3]["params"],
            json!([encode_prefixed_hex(&hash_bytes)])
        );
        assert_eq!(decoded[4]["method"], "eth_getBlockByNumber");
        assert_eq!(decoded[4]["params"], json!(["0x2a", false]));
        assert_eq!(decoded[5]["method"], "eth_getBlockByNumber");
        assert_eq!(decoded[5]["params"], json!(["latest", false]));
        Ok(())
    }

    #[test]
    fn lifecycle_null_is_allowed_only_for_absence_and_pending_anchor() -> Result<(), RpcError> {
        let hash = super::TransactionHash::new([0x33; 32]);
        let rpc = already_verified(MockTransport::new([
            Ok(success(Value::Null)),
            Ok(success(Value::Null)),
            Ok(success(Value::Null)),
            Ok(success(typical_transaction([0x33; 32], false))),
        ]));
        assert_eq!(rpc.transaction_by_hash(hash)?, None);
        assert_eq!(rpc.transaction_receipt(hash)?, None);
        assert_eq!(rpc.block_header_by_number(42)?, None);
        let pending = rpc
            .transaction_by_hash(hash)?
            .ok_or(RpcError::InvalidResponse)?;
        assert_eq!(pending.block, None);
        assert_eq!(pending.transaction_index, None);

        let mut pending_with_timestamp = typical_transaction([0x33; 32], false);
        pending_with_timestamp["blockTimestamp"] = json!("0x60000000");
        let rpc = already_verified(MockTransport::new([Ok(success(pending_with_timestamp))]));
        assert_eq!(
            rpc.transaction_by_hash(hash),
            Err(RpcError::InvalidResponse)
        );

        let mut included_with_null_timestamp = typical_transaction([0x33; 32], true);
        included_with_null_timestamp["blockTimestamp"] = Value::Null;
        let rpc = already_verified(MockTransport::new([Ok(success(
            included_with_null_timestamp,
        ))]));
        assert_eq!(
            rpc.transaction_by_hash(hash),
            Err(RpcError::InvalidResponse)
        );

        // Older standard providers predate Geth 1.17's blockTimestamp field.
        let mut included_without_timestamp = typical_transaction([0x33; 32], true);
        let _ = included_without_timestamp
            .as_object_mut()
            .and_then(|object| object.remove("blockTimestamp"));
        let rpc = already_verified(MockTransport::new([Ok(success(
            included_without_timestamp,
        ))]));
        assert!(rpc.transaction_by_hash(hash)?.is_some());

        let mut half_anchored = typical_transaction([0x33; 32], false);
        half_anchored["blockNumber"] = json!("0x2a");
        let rpc = already_verified(MockTransport::new([Ok(success(half_anchored))]));
        assert_eq!(
            rpc.transaction_by_hash(hash),
            Err(RpcError::InvalidResponse)
        );

        let mut null_recipient = typical_transaction([0x33; 32], false);
        null_recipient["to"] = Value::Null;
        let rpc = already_verified(MockTransport::new([Ok(success(null_recipient))]));
        assert_eq!(
            rpc.transaction_by_hash(hash),
            Err(RpcError::InvalidResponse)
        );
        Ok(())
    }

    #[test]
    fn latest_and_pending_nonce_share_the_strict_quantity_decoder() {
        let address = Address20::new([0x11; 20]);
        for (tag, response) in [("pending", "0x01"), ("latest", "0xA")] {
            let transport = MockTransport::new([Ok(success(json!(response)))]);
            let observation = transport.clone();
            let rpc = already_verified(transport);
            let result = match tag {
                "pending" => rpc.pending_nonce(address),
                "latest" => rpc.latest_nonce(address),
                _ => unreachable!(),
            };
            assert_eq!(result, Err(RpcError::InvalidResponse));
            let requests = observation
                .requests
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let request: Value = serde_json::from_slice(&requests[0]).unwrap_or(Value::Null);
            assert_eq!(
                request["params"],
                json!([encode_prefixed_hex(address.as_bytes()), tag])
            );
        }
    }

    #[test]
    fn nullable_lifecycle_envelopes_are_exact_and_bounded() {
        let hash = super::TransactionHash::new([0x33; 32]);
        for response in [
            br#"{"jsonrpc":"2.0","id":1}"#.to_vec(),
            br#"{"jsonrpc":"2.0","id":1,"result":null,"extra":true}"#.to_vec(),
            br#"{"jsonrpc":"2.0","id":1,"result":null,"error":{"code":-1,"message":"bad"}}"#
                .to_vec(),
        ] {
            let rpc = already_verified(MockTransport::raw(response));
            assert_eq!(
                rpc.transaction_by_hash(hash),
                Err(RpcError::InvalidResponse)
            );
        }

        let unavailable = already_verified(MockTransport::new([Ok(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32601, "message": "unsupported"}
        }))]));
        assert_eq!(
            unavailable.transaction_by_hash(hash),
            Err(RpcError::MethodUnavailable)
        );

        let oversized_message = already_verified(MockTransport::new([Ok(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -1,
                "message": "x".repeat(super::MAX_REMOTE_ERROR_MESSAGE_BYTES + 1)
            }
        }))]));
        assert_eq!(
            oversized_message.transaction_by_hash(hash),
            Err(RpcError::InvalidResponse)
        );

        let oversized_body = already_verified(MockTransport::raw(vec![
            b' ';
            super::MAX_RESPONSE_BYTES
                + 1
        ]));
        assert_eq!(
            oversized_body.transaction_by_hash(hash),
            Err(RpcError::ResponseTooLarge)
        );
    }

    #[test]
    fn lifecycle_rejects_schema_duplicates_unknowns_and_identity_mismatches() {
        let hash_bytes = [0x33; 32];
        let hash = super::TransactionHash::new(hash_bytes);

        let duplicate = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":null,\"result\":{}}}",
            typical_transaction(hash_bytes, false)
        );
        let rpc = already_verified(MockTransport::raw(duplicate.into_bytes()));
        assert_eq!(
            rpc.transaction_by_hash(hash),
            Err(RpcError::InvalidResponse)
        );

        let mut unknown = typical_transaction(hash_bytes, false);
        unknown["providerExtra"] = json!({"unbounded": []});
        let rpc = already_verified(MockTransport::new([Ok(success(unknown))]));
        assert_eq!(
            rpc.transaction_by_hash(hash),
            Err(RpcError::InvalidResponse)
        );

        let rpc = already_verified(MockTransport::new([Ok(success(typical_transaction(
            [0x34; 32], false,
        )))]));
        assert_eq!(
            rpc.transaction_by_hash(hash),
            Err(RpcError::InvalidResponse)
        );

        let zero_hash = super::TransactionHash::new([0; 32]);
        let rpc = already_verified(MockTransport::new([Ok(success(typical_transaction(
            [0; 32], false,
        )))]));
        assert_eq!(
            rpc.transaction_by_hash(zero_hash),
            Err(RpcError::InvalidResponse)
        );

        let rpc = already_verified(MockTransport::new([Ok(success(minimal_block(
            "0x2b", 0x44,
        )))]));
        assert_eq!(
            rpc.block_header_by_number(42),
            Err(RpcError::InvalidResponse)
        );
    }

    #[test]
    fn observed_transaction_rejects_noncanonical_or_wrong_type_two_fields() {
        let hash_bytes = [0x33; 32];
        let hash = super::TransactionHash::new(hash_bytes);
        let mut invalid_transactions = Vec::new();

        let mut noncanonical_nonce = typical_transaction(hash_bytes, false);
        noncanonical_nonce["nonce"] = json!("0x05");
        invalid_transactions.push(noncanonical_nonce);

        let mut uppercase_quantity = typical_transaction(hash_bytes, false);
        uppercase_quantity["gas"] = json!("0xA");
        invalid_transactions.push(uppercase_quantity);

        let mut wrong_type = typical_transaction(hash_bytes, false);
        wrong_type["type"] = json!("0x1");
        invalid_transactions.push(wrong_type);

        let mut wrong_chain = typical_transaction(hash_bytes, false);
        wrong_chain["chainId"] = json!("0x1");
        invalid_transactions.push(wrong_chain);

        let mut nonempty_access_list = typical_transaction(hash_bytes, false);
        nonempty_access_list["accessList"] = json!([{}]);
        invalid_transactions.push(nonempty_access_list);

        let mut missing_anchor_field = typical_transaction(hash_bytes, false);
        let _ = missing_anchor_field
            .as_object_mut()
            .and_then(|object| object.remove("blockHash"));
        invalid_transactions.push(missing_anchor_field);

        let mut zero_inclusion_height = typical_transaction(hash_bytes, true);
        zero_inclusion_height["blockNumber"] = json!("0x0");
        invalid_transactions.push(zero_inclusion_height);

        let mut zero_inclusion_hash = typical_transaction(hash_bytes, true);
        zero_inclusion_hash["blockHash"] = json!(repeated_hex(0, 32));
        invalid_transactions.push(zero_inclusion_hash);

        for field in ["gasPrice", "r", "s", "yParity"] {
            let mut missing = typical_transaction(hash_bytes, true);
            let _ = missing
                .as_object_mut()
                .and_then(|object| object.remove(field));
            invalid_transactions.push(missing);
        }

        for included in [false, true] {
            let mut missing_index = typical_transaction(hash_bytes, included);
            let _ = missing_index
                .as_object_mut()
                .and_then(|object| object.remove("transactionIndex"));
            invalid_transactions.push(missing_index);
        }

        for field in ["r", "s"] {
            let mut zero_signature_scalar = typical_transaction(hash_bytes, true);
            zero_signature_scalar[field] = json!("0x0");
            invalid_transactions.push(zero_signature_scalar);
        }

        let mut oversized_signature_scalar = typical_transaction(hash_bytes, true);
        oversized_signature_scalar["r"] = json!(format!("0x1{}", "0".repeat(64)));
        invalid_transactions.push(oversized_signature_scalar);

        let mut invalid_y_parity = typical_transaction(hash_bytes, true);
        invalid_y_parity["yParity"] = json!("0x2");
        invalid_transactions.push(invalid_y_parity);

        let mut mismatched_legacy_parity = typical_transaction(hash_bytes, true);
        mismatched_legacy_parity["v"] = json!("0x1");
        invalid_transactions.push(mismatched_legacy_parity);

        let mut short_address = typical_transaction(hash_bytes, false);
        short_address["from"] = json!("0x11");
        invalid_transactions.push(short_address);

        let mut nonhex_address = typical_transaction(hash_bytes, false);
        nonhex_address["from"] = json!(format!("0x{}", "g".repeat(40)));
        invalid_transactions.push(nonhex_address);

        for (index, invalid) in invalid_transactions.into_iter().enumerate() {
            let rpc = already_verified(MockTransport::new([Ok(success(invalid))]));
            assert_eq!(
                rpc.transaction_by_hash(hash),
                Err(RpcError::InvalidResponse),
                "invalid transaction fixture {index} was accepted"
            );
        }

        // `v` is deprecated and optional for a standard signed type-2 object;
        // when present it was checked for agreement with the required yParity.
        let mut without_legacy_v = typical_transaction(hash_bytes, true);
        let _ = without_legacy_v
            .as_object_mut()
            .and_then(|object| object.remove("v"));
        let rpc = already_verified(MockTransport::new([Ok(success(without_legacy_v))]));
        assert!(rpc.transaction_by_hash(hash).is_ok());

        // Execution-apis permits checksum/mixed-case addresses even though
        // quantities, hashes, and generic data remain lowercase-only.
        let mut mixed_case_address = typical_transaction(hash_bytes, false);
        mixed_case_address["from"] = json!(format!("0x{}", "Ab".repeat(20)));
        let rpc = already_verified(MockTransport::new([Ok(success(mixed_case_address))]));
        assert_eq!(
            rpc.transaction_by_hash(hash)
                .expect("mixed-case address response")
                .map(|transaction| transaction.from),
            Some(Address20::new([0xab; 20]))
        );
    }

    #[test]
    fn lifecycle_payloads_and_nested_arrays_are_hard_bounded() {
        let hash_bytes = [0x33; 32];
        let hash = super::TransactionHash::new(hash_bytes);

        let mut oversized_input = typical_transaction(hash_bytes, false);
        oversized_input["input"] = json!(repeated_hex(0x11, super::MAX_RAW_TRANSACTION_BYTES + 1));
        let rpc = already_verified(MockTransport::new([Ok(success(oversized_input))]));
        assert_eq!(
            rpc.transaction_by_hash(hash),
            Err(RpcError::InvalidResponse)
        );

        let logs = vec![typical_receipt_log(hash_bytes); super::MAX_RECEIPT_LOGS + 1];
        let rpc = already_verified(MockTransport::new([Ok(success(typical_receipt(
            hash_bytes,
            "0x1",
            json!(logs),
        )))]));
        assert_eq!(
            rpc.transaction_receipt(hash),
            Err(RpcError::InvalidResponse)
        );

        let mut log = typical_receipt_log(hash_bytes);
        log["topics"] = json!(vec![
            repeated_hex(0x55, 32);
            super::MAX_RECEIPT_LOG_TOPICS + 1
        ]);
        let rpc = already_verified(MockTransport::new([Ok(success(typical_receipt(
            hash_bytes,
            "0x1",
            json!([log]),
        )))]));
        assert_eq!(
            rpc.transaction_receipt(hash),
            Err(RpcError::InvalidResponse)
        );

        let mut log = typical_receipt_log(hash_bytes);
        log["data"] = json!(repeated_hex(0x66, super::MAX_RECEIPT_LOG_DATA_BYTES + 1));
        let rpc = already_verified(MockTransport::new([Ok(success(typical_receipt(
            hash_bytes,
            "0x1",
            json!([log]),
        )))]));
        assert_eq!(
            rpc.transaction_receipt(hash),
            Err(RpcError::InvalidResponse)
        );

        let transactions = vec![repeated_hex(0x77, 32); super::MAX_BLOCK_TRANSACTIONS + 1];
        let mut block = minimal_block("0x2a", 0x44);
        block["transactions"] = json!(transactions);
        let rpc = already_verified(MockTransport::new([Ok(success(block))]));
        assert_eq!(
            rpc.block_header_by_number(42),
            Err(RpcError::InvalidResponse)
        );

        let withdrawal = json!({
            "index": "0x1",
            "validatorIndex": "0x2",
            "address": repeated_hex(0x20, 20),
            "amount": "0x3"
        });
        let mut block = minimal_block("0x2a", 0x44);
        block["withdrawals"] = json!(vec![withdrawal; super::MAX_BLOCK_WITHDRAWALS + 1]);
        let rpc = already_verified(MockTransport::new([Ok(success(block))]));
        assert_eq!(
            rpc.block_header_by_number(42),
            Err(RpcError::InvalidResponse)
        );
    }

    #[test]
    fn receipt_status_zero_is_preserved_and_receipt_schema_is_strict() -> Result<(), RpcError> {
        let hash_bytes = [0x33; 32];
        let hash = super::TransactionHash::new(hash_bytes);
        let rpc = already_verified(MockTransport::new([Ok(success(typical_receipt(
            hash_bytes,
            "0x0",
            json!([]),
        )))]));
        let receipt = rpc
            .transaction_receipt(hash)?
            .ok_or(RpcError::InvalidResponse)?;
        assert_eq!(receipt.status, super::TransactionStatus::Failed);
        assert_eq!(receipt.block.number, 42);

        for (field, invalid) in [
            ("status", json!("0x2")),
            ("type", json!("0x1")),
            ("to", Value::Null),
            ("contractAddress", json!(repeated_hex(0x99, 20))),
        ] {
            let mut receipt = typical_receipt(hash_bytes, "0x1", json!([]));
            receipt[field] = invalid;
            let rpc = already_verified(MockTransport::new([Ok(success(receipt))]));
            assert_eq!(
                rpc.transaction_receipt(hash),
                Err(RpcError::InvalidResponse)
            );
        }
        let mut missing_contract_address = typical_receipt(hash_bytes, "0x1", json!([]));
        let _ = missing_contract_address
            .as_object_mut()
            .and_then(|object| object.remove("contractAddress"));
        let rpc = already_verified(MockTransport::new([Ok(success(missing_contract_address))]));
        assert!(rpc.transaction_receipt(hash)?.is_some());
        for (field, invalid) in [
            ("blockNumber", json!("0x0")),
            ("blockHash", json!(repeated_hex(0, 32))),
        ] {
            let mut receipt = typical_receipt(hash_bytes, "0x1", json!([]));
            receipt[field] = invalid;
            let rpc = already_verified(MockTransport::new([Ok(success(receipt))]));
            assert_eq!(
                rpc.transaction_receipt(hash),
                Err(RpcError::InvalidResponse)
            );
        }
        Ok(())
    }

    #[test]
    fn block_headers_reject_overflow_null_fields_and_provider_extras() {
        for invalid in [
            json!({"number": "0x10000000000000000", "hash": repeated_hex(0x44, 32)}),
            json!({"number": null, "hash": repeated_hex(0x44, 32)}),
            json!({"number": "0x2a", "hash": null}),
            json!({"number": "0x2a", "hash": repeated_hex(0, 32)}),
            json!({"number": "0x2a", "hash": repeated_hex(0x44, 32), "providerExtra": []}),
        ] {
            let rpc = already_verified(MockTransport::new([Ok(success(invalid))]));
            assert_eq!(
                rpc.block_header_by_number(42),
                Err(RpcError::InvalidResponse)
            );
        }
    }

    #[test]
    fn native_transfer_estimate_is_typed_exact_pending_and_has_no_gas_field() -> Result<(), RpcError>
    {
        let sender = Address20::new([0x11; 20]);
        let recipient = Address20::new([0x22; 20]);
        let value = parse_quantity("0x1234")?;
        let nonce = parse_quantity("0x5")?;
        let priority = parse_quantity("0xa")?;
        let maximum = parse_quantity("0xd2")?;
        let responses = verification_responses()
            .into_iter()
            .chain([Ok(success(json!("0x5208")))]);
        let transport = MockTransport::new(responses);
        let observation = transport.clone();
        let rpc = SepoliaRpc::with_transport(transport);
        rpc.verify_sepolia()?;
        assert_eq!(
            rpc.estimate_native_transfer_gas(sender, recipient, value, nonce, priority, maximum,)?,
            parse_quantity("0x5208")?
        );

        let requests = observation
            .requests
            .lock()
            .map_err(|_| RpcError::Transport)?;
        let request: Value =
            serde_json::from_slice(&requests[2]).map_err(|_| RpcError::Transport)?;
        assert_eq!(request["method"], "eth_estimateGas");
        assert_eq!(
            request["params"],
            json!([
                {
                    "from": encode_prefixed_hex(sender.as_bytes()),
                    "to": encode_prefixed_hex(recipient.as_bytes()),
                    "value": "0x1234",
                    "input": "0x",
                    "type": "0x2",
                    "nonce": "0x5",
                    "maxPriorityFeePerGas": "0xa",
                    "maxFeePerGas": "0xd2"
                },
                "pending"
            ])
        );
        assert!(request["params"][0].get("gas").is_none());
        assert!(request["params"][0].get("data").is_none());
        Ok(())
    }

    #[test]
    fn native_transfer_estimate_result_is_a_strict_quantity() -> Result<(), RpcError> {
        let address = Address20::new([0x11; 20]);
        let responses = verification_responses()
            .into_iter()
            .chain([Ok(success(json!("0x05208")))]);
        let rpc = SepoliaRpc::with_transport(MockTransport::new(responses));
        rpc.verify_sepolia()?;
        assert_eq!(
            rpc.estimate_native_transfer_gas(
                address,
                address,
                Quantity256::ZERO,
                Quantity256::ZERO,
                Quantity256::ZERO,
                Quantity256::ZERO,
            ),
            Err(RpcError::InvalidResponse)
        );
        Ok(())
    }

    #[test]
    fn token_reads_and_estimate_use_exact_pending_typed_requests() -> Result<(), RpcError> {
        let sender = Address20::new([0x11; 20]);
        let contract = Address20::new([0x22; 20]);
        let recipient = Address20::new([0x33; 20]);
        let mut amount_bytes = [0_u8; 32];
        amount_bytes[31] = 0x2a;
        let amount = TokenAmount::from_be_bytes(amount_bytes);
        let transfer = transfer_call_data(*recipient.as_bytes(), amount);
        let mut expected_true = [0_u8; 32];
        expected_true[31] = 1;
        let canonical_true = encode_prefixed_hex(&expected_true);
        let responses = verification_responses().into_iter().chain([
            Ok(success(json!("0x6001"))),
            Ok(success(json!("0x1234"))),
            Ok(success(json!(canonical_true))),
            Ok(success(json!("0xc350"))),
        ]);
        let transport = MockTransport::new(responses);
        let observation = transport.clone();
        let rpc = SepoliaRpc::with_transport(transport);
        rpc.verify_sepolia()?;

        let code = rpc.contract_code(contract)?;
        assert_eq!(code.as_bytes(), &[0x60, 0x01]);
        let result = rpc.erc20_balance_of(contract, sender)?;
        assert_eq!(result.as_bytes(), &[0x12, 0x34]);
        assert_eq!(
            rpc.erc20_transfer_preflight(
                sender,
                contract,
                recipient,
                amount,
                parse_quantity("0x5")?,
                parse_quantity("0xea60")?,
                parse_quantity("0xa")?,
                parse_quantity("0xd2")?,
            )?
            .as_bytes(),
            &expected_true
        );
        assert_eq!(
            rpc.estimate_erc20_transfer_gas(
                sender,
                contract,
                recipient,
                amount,
                parse_quantity("0x5")?,
                parse_quantity("0xa")?,
                parse_quantity("0xd2")?,
            )?,
            parse_quantity("0xc350")?
        );

        let requests = observation
            .requests
            .lock()
            .map_err(|_| RpcError::Transport)?;
        let get_code: Value =
            serde_json::from_slice(&requests[2]).map_err(|_| RpcError::Transport)?;
        assert_eq!(get_code["method"], "eth_getCode");
        assert_eq!(
            get_code["params"],
            json!([encode_prefixed_hex(contract.as_bytes()), "pending"])
        );

        let call: Value = serde_json::from_slice(&requests[3]).map_err(|_| RpcError::Transport)?;
        assert_eq!(call["method"], "eth_call");
        assert_eq!(
            call["params"],
            json!([{
                "to": encode_prefixed_hex(contract.as_bytes()),
                "input": encode_prefixed_hex(&balance_of_call_data(*sender.as_bytes()))
            }, "pending"])
        );

        let preflight: Value =
            serde_json::from_slice(&requests[4]).map_err(|_| RpcError::Transport)?;
        assert_eq!(preflight["method"], "eth_call");
        assert_eq!(
            preflight["params"],
            json!([{
                "from": encode_prefixed_hex(sender.as_bytes()),
                "to": encode_prefixed_hex(contract.as_bytes()),
                "value": "0x0",
                "input": encode_prefixed_hex(&transfer),
                "type": "0x2",
                "nonce": "0x5",
                "gas": "0xea60",
                "maxPriorityFeePerGas": "0xa",
                "maxFeePerGas": "0xd2",
                "accessList": []
            }, "pending"])
        );
        assert!(preflight["params"][0].get("data").is_none());
        assert!(preflight["params"][0].get("gasPrice").is_none());

        let estimate: Value =
            serde_json::from_slice(&requests[5]).map_err(|_| RpcError::Transport)?;
        assert_eq!(estimate["method"], "eth_estimateGas");
        assert_eq!(
            estimate["params"],
            json!([{
                "from": encode_prefixed_hex(sender.as_bytes()),
                "to": encode_prefixed_hex(contract.as_bytes()),
                "value": "0x0",
                "input": encode_prefixed_hex(&transfer),
                "type": "0x2",
                "nonce": "0x5",
                "maxPriorityFeePerGas": "0xa",
                "maxFeePerGas": "0xd2"
            }, "pending"])
        );
        assert!(estimate["params"][0].get("gas").is_none());
        assert!(estimate["params"][0].get("data").is_none());
        Ok(())
    }

    #[test]
    fn erc20_metadata_calls_are_exact_and_omit_sender() -> Result<(), RpcError> {
        let contract = Address20::new([0x22; 20]);
        let responses = verification_responses()
            .into_iter()
            .chain([Ok(success(json!("0x"))), Ok(success(json!("0x")))]);
        let transport = MockTransport::new(responses);
        let observation = transport.clone();
        let rpc = SepoliaRpc::with_transport(transport);
        rpc.verify_sepolia()?;
        assert!(rpc.erc20_decimals(contract)?.as_bytes().is_empty());
        assert!(rpc.erc20_symbol(contract)?.as_bytes().is_empty());

        let requests = observation
            .requests
            .lock()
            .map_err(|_| RpcError::Transport)?;
        let decimals: Value =
            serde_json::from_slice(&requests[2]).map_err(|_| RpcError::Transport)?;
        let symbol: Value =
            serde_json::from_slice(&requests[3]).map_err(|_| RpcError::Transport)?;
        for request in [&decimals, &symbol] {
            assert_eq!(request["method"], "eth_call");
            assert!(request["params"][0].get("from").is_none());
            assert_eq!(
                request["params"][0]["to"],
                encode_prefixed_hex(contract.as_bytes())
            );
            assert_eq!(request["params"][1], "pending");
        }
        assert_eq!(
            decimals["params"][0]["input"],
            encode_prefixed_hex(&decimals_call_data())
        );
        assert_eq!(
            symbol["params"][0]["input"],
            encode_prefixed_hex(&symbol_call_data())
        );
        Ok(())
    }

    #[test]
    fn bounded_contract_hex_is_canonical_and_allocation_bounded() -> Result<(), RpcError> {
        assert!(super::decode_bounded_hex("0x", 0)?.is_empty());
        assert_eq!(super::decode_bounded_hex("0x00ff", 2)?, [0x00, 0xff]);
        for invalid in ["", "0X00", "0x0", "0xGG", "0xAA"] {
            assert_eq!(
                super::decode_bounded_hex(invalid, 16),
                Err(RpcError::InvalidResponse)
            );
        }
        assert_eq!(
            super::decode_bounded_hex("0x0001", 1),
            Err(RpcError::InvalidResponse)
        );
        Ok(())
    }

    #[test]
    fn contract_results_are_bounded_and_debug_redacted() -> Result<(), RpcError> {
        let contract = Address20::new([0x22; 20]);
        let oversized = format!("0x{}", "aa".repeat(super::MAX_CONTRACT_CODE_BYTES + 1));
        let responses = verification_responses()
            .into_iter()
            .chain([Ok(success(json!(oversized)))]);
        let rpc = SepoliaRpc::with_transport(MockTransport::new(responses));
        rpc.verify_sepolia()?;
        assert_eq!(rpc.contract_code(contract), Err(RpcError::InvalidResponse));

        let responses = verification_responses()
            .into_iter()
            .chain([Ok(success(json!("0x")))]);
        let rpc = SepoliaRpc::with_transport(MockTransport::new(responses));
        rpc.verify_sepolia()?;
        let code = rpc.contract_code(contract)?;
        assert!(code.is_empty());
        assert_eq!(format!("{code:?}"), "ContractCode([REDACTED])");

        let responses = verification_responses()
            .into_iter()
            .chain([Ok(success(json!("0x746f6b656e")))]);
        let rpc = SepoliaRpc::with_transport(MockTransport::new(responses));
        rpc.verify_sepolia()?;
        let result = rpc.erc20_symbol(contract)?;
        assert_eq!(format!("{result:?}"), "ContractCallResult([REDACTED])");
        assert!(!format!("{result:?}").contains("token"));
        Ok(())
    }

    #[test]
    fn response_envelope_rejects_duplicates_unknown_fields_and_wrong_ids() {
        for bytes in [
            br#"{"jsonrpc":"2.0","id":1,"result":"0x1","result":"0x2"}"#.to_vec(),
            br#"{"jsonrpc":"2.0","id":1,"result":"0x1","extra":true}"#.to_vec(),
            br#"{"jsonrpc":"2.0","id":2,"result":"0x1"}"#.to_vec(),
            br#"{"jsonrpc":"2.0","id":1,"result":"0x1","error":{"code":-1,"message":"bad"}}"#
                .to_vec(),
        ] {
            let rpc = SepoliaRpc::with_transport(MockTransport::raw(bytes));
            assert!(matches!(
                rpc.call::<String>(super::RpcMethod::ChainId, json!([])),
                Err(RpcError::InvalidResponse)
            ));
        }
    }

    #[test]
    fn remote_errors_collapse_without_retaining_server_text() {
        let marker = "private-server-error-marker";
        let rpc = SepoliaRpc::with_transport(MockTransport::new([Ok(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32000, "message": marker, "data": {"detail": marker}}
        }))]));
        let error = rpc
            .call::<String>(super::RpcMethod::ChainId, json!([]))
            .expect_err("remote error must fail closed");
        assert_eq!(error, RpcError::RemoteRejected);
        assert!(!format!("{error:?}").contains(marker));
        assert!(!error.to_string().contains(marker));
    }

    #[test]
    fn only_method_not_found_gets_payload_free_unavailable_category() {
        let marker = "private-method-marker";
        let rpc = SepoliaRpc::with_transport(MockTransport::new([Ok(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32601, "message": marker, "data": {"detail": marker}}
        }))]));
        let error = rpc
            .call::<String>(super::RpcMethod::MaxPriorityFee, json!([]))
            .expect_err("method-not-found must be classified");
        assert_eq!(error, RpcError::MethodUnavailable);
        assert!(!format!("{error:?}").contains(marker));
        assert!(!error.to_string().contains(marker));

        for code in [-32_600, -32_000, -32_602, 1] {
            let rpc = SepoliaRpc::with_transport(MockTransport::new([Ok(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": code, "message": "rejected"}
            }))]));
            assert_eq!(
                rpc.call::<String>(super::RpcMethod::MaxPriorityFee, json!([])),
                Err(RpcError::RemoteRejected)
            );
        }
    }

    #[test]
    fn bounded_response_is_enforced_even_for_mock_transports() {
        let rpc =
            SepoliaRpc::with_transport(MockTransport::raw(vec![b' '; MAX_RESPONSE_BYTES + 1]));
        assert_eq!(
            rpc.call::<String>(super::RpcMethod::ChainId, json!([])),
            Err(RpcError::ResponseTooLarge)
        );
    }

    #[test]
    fn fee_quote_uses_twice_base_plus_priority() -> Result<(), RpcError> {
        let responses = verification_responses().into_iter().chain([
            Ok(success(json!({"baseFeePerGas": "0x64"}))),
            Ok(success(json!("0xa"))),
        ]);
        let rpc = SepoliaRpc::with_transport(MockTransport::new(responses));
        rpc.verify_sepolia()?;
        let quote = rpc.fee_quote()?;
        assert_eq!(quote.base_fee_per_gas.as_be_bytes()[31], 100);
        assert_eq!(quote.max_priority_fee_per_gas.as_be_bytes()[31], 10);
        assert_eq!(quote.max_fee_per_gas.as_be_bytes()[31], 210);
        Ok(())
    }

    #[test]
    fn fee_quote_legacy_fallback_derives_tip_and_same_conservative_maximum() -> Result<(), RpcError>
    {
        let responses = verification_responses().into_iter().chain([
            Ok(success(json!({"baseFeePerGas": "0x64"}))),
            Ok(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32601, "message": "unsupported"}
            })),
            Ok(success(json!("0xc8"))),
        ]);
        let rpc = SepoliaRpc::with_transport(MockTransport::new(responses));
        rpc.verify_sepolia()?;
        let quote = rpc.fee_quote()?;
        assert_eq!(quote.base_fee_per_gas.as_be_bytes()[31], 100);
        assert_eq!(quote.max_priority_fee_per_gas.as_be_bytes()[31], 100);
        assert_eq!(quote.max_fee_per_gas.as_be_bytes()[30..], [0x01, 0x2c]);
        Ok(())
    }

    #[test]
    fn fee_quote_legacy_tip_saturates_at_zero_below_base_fee() -> Result<(), RpcError> {
        let responses = verification_responses().into_iter().chain([
            Ok(success(json!({"baseFeePerGas": "0x64"}))),
            Ok(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32601, "message": "unsupported"}
            })),
            Ok(success(json!("0x32"))),
        ]);
        let rpc = SepoliaRpc::with_transport(MockTransport::new(responses));
        rpc.verify_sepolia()?;
        let quote = rpc.fee_quote()?;
        assert_eq!(quote.base_fee_per_gas.as_be_bytes()[31], 100);
        assert_eq!(quote.max_priority_fee_per_gas, Quantity256::ZERO);
        assert_eq!(quote.max_fee_per_gas.as_be_bytes()[31], 200);
        Ok(())
    }

    #[test]
    fn fee_quote_never_falls_back_for_other_remote_or_transport_errors() -> Result<(), RpcError> {
        let responses = verification_responses().into_iter().chain([
            Ok(success(json!({"baseFeePerGas": "0x64"}))),
            Ok(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32000, "message": "rejected"}
            })),
            Ok(success(json!("0xc8"))),
        ]);
        let transport = MockTransport::new(responses);
        let observation = transport.clone();
        let rpc = SepoliaRpc::with_transport(transport);
        rpc.verify_sepolia()?;
        assert_eq!(rpc.fee_quote(), Err(RpcError::RemoteRejected));
        assert_eq!(
            observation
                .requests
                .lock()
                .map_err(|_| RpcError::Transport)?
                .len(),
            4
        );

        let responses = verification_responses().into_iter().chain([
            Ok(success(json!({"baseFeePerGas": "0x64"}))),
            Err(RpcError::Timeout),
            Ok(success(json!("0xc8"))),
        ]);
        let transport = MockTransport::new(responses);
        let observation = transport.clone();
        let rpc = SepoliaRpc::with_transport(transport);
        rpc.verify_sepolia()?;
        assert_eq!(rpc.fee_quote(), Err(RpcError::Timeout));
        assert_eq!(
            observation
                .requests
                .lock()
                .map_err(|_| RpcError::Transport)?
                .len(),
            4
        );
        Ok(())
    }

    #[test]
    fn fee_quote_rejects_noncanonical_priority_and_fallback_gas_price() -> Result<(), RpcError> {
        let responses = verification_responses().into_iter().chain([
            Ok(success(json!({"baseFeePerGas": "0x64"}))),
            Ok(success(json!("0x00"))),
        ]);
        let rpc = SepoliaRpc::with_transport(MockTransport::new(responses));
        rpc.verify_sepolia()?;
        assert_eq!(rpc.fee_quote(), Err(RpcError::InvalidResponse));

        let responses = verification_responses().into_iter().chain([
            Ok(success(json!({"baseFeePerGas": "0x64"}))),
            Ok(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32601, "message": "unsupported"}
            })),
            Ok(success(json!("0x00"))),
        ]);
        let rpc = SepoliaRpc::with_transport(MockTransport::new(responses));
        rpc.verify_sepolia()?;
        assert_eq!(rpc.fee_quote(), Err(RpcError::InvalidResponse));
        Ok(())
    }

    #[test]
    fn fee_quote_checked_arithmetic_rejects_all_overflow_paths() -> Result<(), RpcError> {
        let maximum = format!("0x{}", "f".repeat(64));
        let responses = verification_responses()
            .into_iter()
            .chain([Ok(success(json!({"baseFeePerGas": maximum})))]);
        let transport = MockTransport::new(responses);
        let observation = transport.clone();
        let rpc = SepoliaRpc::with_transport(transport);
        rpc.verify_sepolia()?;
        assert_eq!(rpc.fee_quote(), Err(RpcError::NumericOverflow));
        assert_eq!(
            observation
                .requests
                .lock()
                .map_err(|_| RpcError::Transport)?
                .len(),
            3
        );

        let half_maximum = format!("0x7{}", "f".repeat(63));
        let responses = verification_responses().into_iter().chain([
            Ok(success(json!({"baseFeePerGas": half_maximum}))),
            Ok(success(json!("0x2"))),
        ]);
        let rpc = SepoliaRpc::with_transport(MockTransport::new(responses));
        rpc.verify_sepolia()?;
        assert_eq!(rpc.fee_quote(), Err(RpcError::NumericOverflow));

        let half_maximum = format!("0x7{}", "f".repeat(63));
        let maximum = format!("0x{}", "f".repeat(64));
        let responses = verification_responses().into_iter().chain([
            Ok(success(json!({"baseFeePerGas": half_maximum}))),
            Ok(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32601, "message": "unsupported"}
            })),
            Ok(success(json!(maximum))),
        ]);
        let rpc = SepoliaRpc::with_transport(MockTransport::new(responses));
        rpc.verify_sepolia()?;
        assert_eq!(rpc.fee_quote(), Err(RpcError::NumericOverflow));
        Ok(())
    }

    #[test]
    fn send_reverifies_chain_and_accepts_only_type_two() -> Result<(), RpcError> {
        let active_epoch = AtomicU64::new(0);
        let permit = SessionPermit::current_for_test(0, &active_epoch);
        let rpc = SepoliaRpc::with_transport(MockTransport::default());
        assert_eq!(
            rpc.send_raw_transaction(&[], &permit),
            Err(RpcError::RawTransactionRejected)
        );
        assert_eq!(
            rpc.send_raw_transaction(&[0x01, 0xc0], &permit),
            Err(RpcError::RawTransactionRejected)
        );

        let returned = [0x77; 32];
        let responses = verification_responses()
            .into_iter()
            .chain([Ok(success(json!(encode_prefixed_hex(&returned))))]);
        let rpc = SepoliaRpc::with_transport(MockTransport::new(responses));
        let hash = rpc.send_raw_transaction(&[0x02, 0xc0], &permit)?;
        assert_eq!(hash.as_bytes(), &returned);
        Ok(())
    }

    #[test]
    fn revocation_after_final_chain_reverify_prevents_broadcast_transport() -> Result<(), RpcError>
    {
        let returned = [0x77; 32];
        let responses = verification_responses()
            .into_iter()
            .chain([Ok(success(json!(encode_prefixed_hex(&returned))))]);
        let transport = MockTransport::new(responses);
        let observation = transport.clone();
        let rpc = SepoliaRpc::with_transport(transport);
        let active_epoch = AtomicU64::new(0);
        let permit = SessionPermit::revoke_on_check(0, &active_epoch, 1);

        assert_eq!(
            rpc.send_raw_transaction(&[0x02, 0xc0], &permit),
            Err(RpcError::SessionRevoked)
        );
        let requests = observation
            .requests
            .lock()
            .map_err(|_| RpcError::Transport)?;
        assert_eq!(requests.len(), 2, "only chain/genesis verification may run");
        for request in requests.iter() {
            let request: Value =
                serde_json::from_slice(request).map_err(|_| RpcError::Transport)?;
            assert_ne!(request["method"], "eth_sendRawTransaction");
        }
        Ok(())
    }

    #[test]
    fn concrete_http_client_disables_redirects_proxy_and_unbounded_waits() {
        let transport = HttpTransport::new();
        let config = transport.agent.config();
        assert!(config.https_only());
        assert_eq!(config.max_redirects(), 0);
        assert!(config.proxy().is_none());
        assert_eq!(config.timeouts().global, Some(GLOBAL_TIMEOUT));
    }
}
