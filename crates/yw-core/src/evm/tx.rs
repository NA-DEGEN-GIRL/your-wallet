//! EIP-1559 (type 2) transactions: model, invariants, signing preimage and the strict signed
//! decoder (spec/03 §3.1, §4.2–§4.3, D19).
//!
//! Field checks follow `archive/spec-v2.4:crates/key-agent/src/lib.rs:391-797`
//! (`validate_signed_fields` for type 2, `require_*`) and the type-2-only rules of
//! `archive/spec-v2.4:crates/wallet-protocol/src/validation.rs:35-441` (no deployment, no other
//! transaction types). The legacy encoder exists only in tests (EIP-155 vector).
#![deny(clippy::indexing_slicing)]

use core::fmt;

use sha3::{Digest, Keccak256};

use super::address::Address;
use super::amount::U256;
use super::rlp::{self, Item, RlpError};

/// Per-transaction gas cap (EIP-7825, D20).
pub const TX_GAS_CAP: u64 = 16_777_216;
/// Maximum calldata bytes (spec/03 §3.1).
pub const MAX_TX_DATA: usize = 131_072;
/// Maximum access-list entries.
pub const MAX_ACCESS_LIST_ITEMS: usize = 256;
/// Maximum storage keys per access-list entry.
pub const MAX_STORAGE_KEYS: usize = 256;
/// Maximum signed transaction size (geth txpool, spec/03 §4.3; E11).
pub const MAX_SIGNED_TX_BYTES: usize = 131_072;
/// Upper bound of the growth from the preimage to the signed encoding (3 signature fields and
/// the list header, spec/03 §3.7 step 7).
pub const SIGNATURE_OVERHEAD: usize = 70;
/// EIP-2718 type byte.
pub const TX_TYPE_EIP1559: u8 = 0x02;
/// secp256k1 group order n.
pub const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
/// n / 2 (low-s bound, spec/03 §4.3).
pub const SECP256K1_HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// One access-list entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessListItem {
    /// Accessed address.
    pub address: Address,
    /// Accessed storage keys.
    pub storage_keys: Vec<[u8; 32]>,
}

/// An EIP-1559 transaction. Field order is the RLP order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eip1559Tx {
    /// Chain id (a registered chain).
    pub chain_id: u64,
    /// Account nonce.
    pub nonce: u64,
    /// Priority fee cap.
    pub max_priority_fee_per_gas: U256,
    /// Total fee cap.
    pub max_fee_per_gas: U256,
    /// Gas limit (≤ 16,777,216).
    pub gas_limit: u64,
    /// Destination (no deployment, D19).
    pub to: Address,
    /// Native value.
    pub value: U256,
    /// Calldata (≤ 131,072 bytes).
    pub data: Vec<u8>,
    /// Access list (≤ 256 entries, ≤ 256 keys each, no duplicate address).
    pub access_list: Vec<AccessListItem>,
}

/// A decoded signed type-2 transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedEip1559 {
    /// The nine transaction fields.
    pub tx: Eip1559Tx,
    /// `y_parity` (0 or 1).
    pub y_parity: u8,
    /// `r` as a 32-byte big-endian integer.
    pub r: [u8; 32],
    /// `s` as a 32-byte big-endian integer.
    pub s: [u8; 32],
}

/// Transaction model or decoding failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxError {
    /// `max_priority_fee_per_gas > max_fee_per_gas`.
    FeeOrder,
    /// `gas_limit > 16,777,216`.
    GasLimit,
    /// Calldata longer than 131,072 bytes.
    DataTooLarge,
    /// Access list exceeds its entry or key bounds, or repeats an address.
    AccessList,
    /// Signed encoding longer than 131,072 bytes (E11).
    TooLarge,
    /// Not a type-2 envelope, wrong field count or field shape.
    Malformed,
    /// RLP-level error.
    Rlp(RlpError),
    /// `y_parity`, `r` or `s` out of range (high-s, zero, ≥ n).
    Signature,
}

impl fmt::Display for TxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FeeOrder => "priority fee exceeds max fee",
            Self::GasLimit => "gas limit exceeds the transaction cap",
            Self::DataTooLarge => "calldata too large",
            Self::AccessList => "access list out of bounds",
            Self::TooLarge => "signed transaction too large",
            Self::Malformed => "malformed type-2 transaction",
            Self::Rlp(_) => "malformed RLP",
            Self::Signature => "signature out of range",
        })
    }
}

impl std::error::Error for TxError {}

impl From<RlpError> for TxError {
    fn from(error: RlpError) -> Self {
        Self::Rlp(error)
    }
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

fn encode_access_list(out: &mut Vec<u8>, list: &[AccessListItem]) {
    let mut entries = Vec::new();
    for item in list {
        let mut entry = Vec::new();
        rlp::encode_bytes(&mut entry, item.address.as_bytes());
        let mut keys = Vec::new();
        for key in &item.storage_keys {
            rlp::encode_bytes(&mut keys, key);
        }
        rlp::encode_list(&mut entry, &keys);
        rlp::encode_list(&mut entries, &entry);
    }
    rlp::encode_list(out, &entries);
}

fn minimal(bytes: &[u8; 32]) -> &[u8] {
    let start = bytes.iter().position(|byte| *byte != 0).unwrap_or(32);
    bytes.get(start..).unwrap_or(&[])
}

impl Eip1559Tx {
    /// Checks the spec/03 §3.1 invariants (except chain registration, which the caller owns).
    ///
    /// # Errors
    ///
    /// [`TxError`] naming the first violated invariant.
    pub fn validate(&self) -> Result<(), TxError> {
        if self.max_priority_fee_per_gas > self.max_fee_per_gas {
            return Err(TxError::FeeOrder);
        }
        if self.gas_limit > TX_GAS_CAP {
            return Err(TxError::GasLimit);
        }
        if self.data.len() > MAX_TX_DATA {
            return Err(TxError::DataTooLarge);
        }
        if self.access_list.len() > MAX_ACCESS_LIST_ITEMS {
            return Err(TxError::AccessList);
        }
        for (index, item) in self.access_list.iter().enumerate() {
            if item.storage_keys.len() > MAX_STORAGE_KEYS {
                return Err(TxError::AccessList);
            }
            let earlier = self.access_list.get(..index).unwrap_or(&[]);
            if earlier.iter().any(|other| other.address == item.address) {
                return Err(TxError::AccessList);
            }
        }
        Ok(())
    }

    fn fields_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(self.data.len().saturating_add(128));
        rlp::encode_u64(&mut payload, self.chain_id);
        rlp::encode_u64(&mut payload, self.nonce);
        rlp::encode_u256(&mut payload, &self.max_priority_fee_per_gas);
        rlp::encode_u256(&mut payload, &self.max_fee_per_gas);
        rlp::encode_u64(&mut payload, self.gas_limit);
        rlp::encode_bytes(&mut payload, self.to.as_bytes());
        rlp::encode_u256(&mut payload, &self.value);
        rlp::encode_bytes(&mut payload, &self.data);
        encode_access_list(&mut payload, &self.access_list);
        payload
    }

    /// `0x02 ‖ rlp([chain_id, nonce, tip, max_fee, gas_limit, to, value, data, access_list])`.
    #[must_use]
    pub fn signing_preimage(&self) -> Vec<u8> {
        let payload = self.fields_payload();
        let mut out = Vec::with_capacity(payload.len().saturating_add(10));
        out.push(TX_TYPE_EIP1559);
        rlp::encode_list(&mut out, &payload);
        out
    }

    /// `keccak256(signing_preimage)`.
    #[must_use]
    pub fn signing_hash(&self) -> [u8; 32] {
        keccak(&self.signing_preimage())
    }

    /// `0x02 ‖ rlp([...9 fields, y_parity, r, s])` with minimal integers.
    #[must_use]
    pub fn encode_signed(&self, y_parity: u8, r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        let mut payload = self.fields_payload();
        rlp::encode_u64(&mut payload, u64::from(y_parity));
        rlp::encode_bytes(&mut payload, minimal(r));
        rlp::encode_bytes(&mut payload, minimal(s));
        let mut out = Vec::with_capacity(payload.len().saturating_add(10));
        out.push(TX_TYPE_EIP1559);
        rlp::encode_list(&mut out, &payload);
        out
    }
}

impl SignedEip1559 {
    /// Re-encodes the signed transaction.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.tx.encode_signed(self.y_parity, &self.r, &self.s)
    }
}

fn address_field(item: &Item<'_>) -> Result<Address, TxError> {
    let bytes = item.as_bytes()?;
    let array: [u8; 20] = bytes.try_into().map_err(|_| TxError::Malformed)?;
    Ok(Address::from_bytes(array))
}

fn decode_access_list(item: &Item<'_>) -> Result<Vec<AccessListItem>, TxError> {
    let entries = item.as_list()?;
    if entries.len() > MAX_ACCESS_LIST_ITEMS {
        return Err(TxError::AccessList);
    }
    let mut list = Vec::with_capacity(entries.len());
    for entry in entries {
        let [address, keys] = entry.as_list()? else {
            return Err(TxError::Malformed);
        };
        let keys = keys.as_list()?;
        if keys.len() > MAX_STORAGE_KEYS {
            return Err(TxError::AccessList);
        }
        let mut storage_keys = Vec::with_capacity(keys.len());
        for key in keys {
            let key: [u8; 32] = key.as_bytes()?.try_into().map_err(|_| TxError::Malformed)?;
            storage_keys.push(key);
        }
        list.push(AccessListItem {
            address: address_field(address)?,
            storage_keys,
        });
    }
    Ok(list)
}

fn signature_scalar(item: &Item<'_>) -> Result<[u8; 32], TxError> {
    let bytes = rlp::decode_uint(item, 32)?;
    if bytes.is_empty() {
        return Err(TxError::Signature);
    }
    let mut out = [0_u8; 32];
    let start = 32_usize.saturating_sub(bytes.len());
    out.get_mut(start..)
        .ok_or(TxError::Signature)?
        .copy_from_slice(bytes);
    Ok(out)
}

/// Strictly decodes a signed type-2 transaction (spec/03 §4.3 step 3).
///
/// # Errors
///
/// [`TxError`] for a non-`0x02` envelope, not exactly 12 fields, non-canonical fields, a `to`
/// that is not 20 bytes, `y_parity ∉ {0,1}`, `r ∉ (0, n)` or `s ∉ (0, n/2]`, or > 131,072 bytes.
pub fn decode_signed(raw: &[u8]) -> Result<SignedEip1559, TxError> {
    if raw.len() > MAX_SIGNED_TX_BYTES {
        return Err(TxError::TooLarge);
    }
    let (&kind, payload) = raw.split_first().ok_or(TxError::Malformed)?;
    if kind != TX_TYPE_EIP1559 {
        return Err(TxError::Malformed);
    }
    let item = rlp::decode_exact(payload)?;
    let [
        chain_id,
        nonce,
        tip,
        max_fee,
        gas_limit,
        to,
        value,
        data,
        access_list,
        y_parity,
        r,
        s,
    ] = item.as_list()?
    else {
        return Err(TxError::Malformed);
    };
    let data = data.as_bytes()?;
    if data.len() > MAX_TX_DATA {
        return Err(TxError::DataTooLarge);
    }
    let y_parity = rlp::decode_u64(y_parity)?;
    let y_parity = u8::try_from(y_parity)
        .ok()
        .filter(|parity| *parity <= 1)
        .ok_or(TxError::Signature)?;
    let r = signature_scalar(r)?;
    let s = signature_scalar(s)?;
    if r >= SECP256K1_N || s > SECP256K1_HALF_N {
        return Err(TxError::Signature);
    }
    Ok(SignedEip1559 {
        tx: Eip1559Tx {
            chain_id: rlp::decode_u64(chain_id)?,
            nonce: rlp::decode_u64(nonce)?,
            max_priority_fee_per_gas: rlp::decode_u256(tip)?,
            max_fee_per_gas: rlp::decode_u256(max_fee)?,
            gas_limit: rlp::decode_u64(gas_limit)?,
            to: address_field(to)?,
            value: rlp::decode_u256(value)?,
            data: data.to_vec(),
            access_list: decode_access_list(access_list)?,
        },
        y_parity,
        r,
        s,
    })
}

/// `keccak256(raw)`, the transaction hash.
#[must_use]
pub fn tx_hash(raw: &[u8]) -> [u8; 32] {
    keccak(raw)
}

#[cfg(test)]
mod tests {
    use super::{AccessListItem, Eip1559Tx, TxError, decode_signed};
    use crate::evm::address::Address;
    use crate::evm::amount::U256;

    fn sample() -> Eip1559Tx {
        Eip1559Tx {
            chain_id: 11_155_111,
            nonce: 7,
            max_priority_fee_per_gas: U256::from_u64(100_000_000),
            max_fee_per_gas: U256::from_u64(2_000_000_000),
            gas_limit: 21_000,
            to: Address::from_bytes([0x11; 20]),
            value: U256::from_u64(1),
            data: vec![1, 2, 3],
            access_list: vec![AccessListItem {
                address: Address::from_bytes([0x22; 20]),
                storage_keys: vec![[0x33; 32], [0; 32]],
            }],
        }
    }

    #[test]
    fn invariants() {
        let mut tx = sample();
        assert_eq!(tx.validate(), Ok(()));
        tx.max_priority_fee_per_gas = U256::from_u64(3_000_000_000);
        assert_eq!(tx.validate(), Err(TxError::FeeOrder));
        let mut tx = sample();
        tx.gas_limit = 16_777_217;
        assert_eq!(tx.validate(), Err(TxError::GasLimit));
        let mut tx = sample();
        tx.data = vec![0; 131_073];
        assert_eq!(tx.validate(), Err(TxError::DataTooLarge));
        let mut tx = sample();
        let duplicate = tx.access_list.first().unwrap().clone();
        tx.access_list.push(duplicate);
        assert_eq!(tx.validate(), Err(TxError::AccessList));
    }

    #[test]
    fn signed_round_trip_and_range_checks() {
        let tx = sample();
        let r = [0x01; 32];
        let mut s = [0x02; 32];
        let raw = tx.encode_signed(1, &r, &s);
        let decoded = decode_signed(&raw).unwrap();
        assert_eq!(decoded.tx, tx);
        assert_eq!(decoded.y_parity, 1);
        assert_eq!(decoded.encode(), raw);
        *s.first_mut().unwrap() = 0x80; // > n/2
        assert_eq!(
            decode_signed(&tx.encode_signed(0, &r, &s)),
            Err(TxError::Signature)
        );
        assert_eq!(
            decode_signed(&tx.encode_signed(0, &[0; 32], &[1; 32])),
            Err(TxError::Signature)
        );
        assert_eq!(
            decode_signed(&tx.encode_signed(2, &r, &[1; 32])),
            Err(TxError::Signature)
        );
        let mut legacy = raw.clone();
        *legacy.first_mut().unwrap() = 0x01;
        assert_eq!(decode_signed(&legacy), Err(TxError::Malformed));
    }
}
