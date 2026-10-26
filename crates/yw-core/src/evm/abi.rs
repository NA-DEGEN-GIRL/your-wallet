//! Canonical ABI decoding and the selector/topic tables (spec/03 §2.5, §6.4, §7.1–§7.2 R2).
//!
//! The ERC-20 helpers (`transfer` data, `decimals()`/`symbol()` result decoders) are ported from
//! `archive/spec-v2.4:demo/sepolia-wallet/src/erc20.rs:1-583` (logic unchanged, chain
//! parameterized by the callers). The decoder accepts only the canonical encoding: heads in
//! order, every dynamic tail at the canonical offset (first tail = head size, next tail = end of
//! the previous one), zero padding, no trailing bytes, arrays ≤ 64, bytes ≤ 131,072.
#![deny(clippy::indexing_slicing)]

use super::address::Address;
use super::amount::U256;
use crate::hex::const_decode;

/// Maximum array length accepted in calldata or logs (R2).
pub const MAX_ABI_ARRAY: usize = 64;
/// Maximum `bytes` argument length (R2).
pub const MAX_ABI_BYTES: usize = 131_072;
const WORD: usize = 32;

macro_rules! selectors {
    ($($name:ident = $hex:literal;)*) => {
        $(
            #[doc = concat!("Selector `0x", $hex, "`.")]
            pub const $name: [u8; 4] = const_decode::<4>($hex);
        )*
    };
}

selectors! {
    SEL_TRANSFER = "a9059cbb";
    SEL_APPROVE = "095ea7b3";
    SEL_TRANSFER_FROM = "23b872dd";
    SEL_INCREASE_ALLOWANCE = "39509351";
    SEL_DECREASE_ALLOWANCE = "a457c2d7";
    SEL_SET_APPROVAL_FOR_ALL = "a22cb465";
    SEL_SAFE_TRANSFER_FROM_721 = "42842e0e";
    SEL_SAFE_TRANSFER_FROM_721_DATA = "b88d4fde";
    SEL_SAFE_TRANSFER_FROM_1155 = "f242432a";
    SEL_SAFE_BATCH_TRANSFER_FROM_1155 = "2eb2c2d6";
    SEL_WETH_DEPOSIT = "d0e30db0";
    SEL_WETH_WITHDRAW = "2e1a7d4d";
    SEL_PERMIT2_APPROVE = "87517c45";
    SEL_PERMIT2_LOCKDOWN = "cc53287f";
    SEL_PERMIT2_INVALIDATE_NONCES = "65d9723c";
    SEL_PERMIT2_INVALIDATE_UNORDERED_NONCES = "3ff9dcb1";
    SEL_PERMIT2_PERMIT_SINGLE = "2b67b570";
    SEL_PERMIT2_PERMIT_BATCH = "2a2d80d1";
    SEL_PERMIT2_TRANSFER_FROM = "36c78516";
    SEL_PERMIT2_TRANSFER_FROM_BATCH = "0d58b1db";
    SEL_PERMIT2_PERMIT_TRANSFER_FROM = "30f28b7a";
    SEL_PERMIT2_PERMIT_BATCH_TRANSFER_FROM = "edd9444b";
    SEL_PERMIT2_PERMIT_WITNESS_TRANSFER_FROM = "137c29fe";
    SEL_PERMIT2_ALLOWANCE = "927da105";
    SEL_MULTICALL = "ac9650d8";
    SEL_MULTICALL_DEADLINE = "5ae401dc";
    SEL_MULTICALL_BLOCKHASH = "1f0464d1";
    SEL_ERC2612_PERMIT = "d505accf";
    SEL_DAI_PERMIT = "8fcbaf0c";
    SEL_UNIVERSAL_ROUTER_EXECUTE_DEADLINE = "3593564c";
    SEL_UNIVERSAL_ROUTER_EXECUTE = "24856bc3";
    SEL_SEAPORT_FULFILL_BASIC_ORDER = "fb0f3ee1";
    SEL_SEAPORT_FULFILL_BASIC_ORDER_EFFICIENT = "00000000";
    SEL_SEAPORT_CANCEL = "fd9f1e10";
    SEL_SEAPORT_INCREMENT_COUNTER = "5b34b966";
    SEL_DECIMALS = "313ce567";
    SEL_SYMBOL = "95d89b41";
    SEL_NAME = "06fdde03";
    SEL_BALANCE_OF = "70a08231";
    SEL_ALLOWANCE = "dd62ed3e";
    SEL_ERROR_STRING = "08c379a0";
    SEL_PANIC_UINT256 = "4e487b71";
}

macro_rules! topics {
    ($($name:ident = $hex:literal;)*) => {
        $(
            #[doc = concat!("Event topic0 `0x", $hex, "`.")]
            pub const $name: [u8; 32] = const_decode::<32>($hex);
        )*
    };
}

topics! {
    TOPIC_TRANSFER = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
    TOPIC_APPROVAL = "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
    TOPIC_APPROVAL_FOR_ALL = "17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31";
    TOPIC_TRANSFER_SINGLE = "c3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62";
    TOPIC_TRANSFER_BATCH = "4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb";
    TOPIC_WETH_DEPOSIT = "e1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c";
    TOPIC_WETH_WITHDRAWAL = "7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65";
    TOPIC_PERMIT2_APPROVAL = "da9fa7c1b00402c17d0161b249b1ab8bbec047c5a52207b9c112deffd817036b";
    TOPIC_PERMIT2_PERMIT = "c6a377bfc4eb120024a8ac08eef205be16b817020812c73223e81d1bdb9708ec";
    TOPIC_PERMIT2_LOCKDOWN = "89b1add15eff56b3dfe299ad94e01f2b52fbcb80ae1a3baea6ae8c04cb2b98a4";
    TOPIC_PERMIT2_NONCE_INVALIDATION = "55eb90d810e1700b35a8e7e25395ff7f2b2259abd7415ca2284dfb1c246418f3";
    TOPIC_PERMIT2_UNORDERED_NONCE_INVALIDATION = "3704902f963766a4e561bbaab6e6cdc1b1dd12f6e9e99648da8843b3f46b918d";
}

/// An ABI value (spec/03 §7.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbiValue {
    /// `address`.
    Address(Address),
    /// `uintN`.
    Uint(U256),
    /// `bool`.
    Bool(bool),
    /// `bytes`.
    Bytes(Vec<u8>),
    /// `bytes32`.
    Bytes32([u8; 32]),
    /// A dynamic array.
    Array(Vec<AbiValue>),
    /// A static tuple.
    Tuple(Vec<AbiValue>),
}

/// The argument types the decoder supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AbiType {
    Address,
    Bool,
    /// `uintN` with N bits.
    Uint(u16),
    Bytes32,
    Bytes,
    /// `uint256[]`.
    UintArray,
    /// `bytes[]`.
    BytesArray,
    /// `(address,address)[]`.
    AddressPairArray,
}

fn word(data: &[u8], offset: usize) -> Option<&[u8; WORD]> {
    data.get(offset..offset.checked_add(WORD)?)?.try_into().ok()
}

/// The 20-byte address of a canonical address word (upper 12 bytes zero).
#[must_use]
pub fn address_word(word: &[u8; 32]) -> Option<Address> {
    let (high, low) = word.split_at(12);
    if high.iter().any(|byte| *byte != 0) {
        return None;
    }
    let bytes: [u8; 20] = low.try_into().ok()?;
    Some(Address::from_bytes(bytes))
}

/// The address word of `address` (left-padded).
#[must_use]
pub fn pad_address(address: &Address) -> [u8; 32] {
    let mut word = [0_u8; 32];
    if let Some(low) = word.get_mut(12..) {
        low.copy_from_slice(address.as_bytes());
    }
    word
}

fn uint_word(word: &[u8; 32], bits: u16) -> Option<U256> {
    let value = U256::from_be_bytes(*word);
    value.fits_bits(bits).then_some(value)
}

fn small_word(word: &[u8; 32]) -> Option<usize> {
    let value = U256::from_be_bytes(*word).to_u64()?;
    usize::try_from(value).ok()
}

fn padded_len(length: usize) -> Option<usize> {
    length
        .checked_add(WORD - 1)
        .map(|value| value / WORD * WORD)
}

fn decode_bytes_at(data: &[u8], offset: usize) -> Option<(Vec<u8>, usize)> {
    let length = small_word(word(data, offset)?)?;
    if length > MAX_ABI_BYTES {
        return None;
    }
    let start = offset.checked_add(WORD)?;
    let end = start.checked_add(padded_len(length)?)?;
    let padded = data.get(start..end)?;
    let (value, padding) = padded.split_at(length);
    if padding.iter().any(|byte| *byte != 0) {
        return None;
    }
    Some((value.to_vec(), end))
}

fn decode_dynamic(kind: AbiType, data: &[u8], offset: usize) -> Option<(AbiValue, usize)> {
    match kind {
        AbiType::Bytes => {
            let (bytes, end) = decode_bytes_at(data, offset)?;
            Some((AbiValue::Bytes(bytes), end))
        }
        AbiType::UintArray => {
            let count = small_word(word(data, offset)?)?;
            if count > MAX_ABI_ARRAY {
                return None;
            }
            let mut items = Vec::with_capacity(count);
            let mut cursor = offset.checked_add(WORD)?;
            for _ in 0..count {
                items.push(AbiValue::Uint(U256::from_be_bytes(*word(data, cursor)?)));
                cursor = cursor.checked_add(WORD)?;
            }
            Some((AbiValue::Array(items), cursor))
        }
        AbiType::AddressPairArray => {
            let count = small_word(word(data, offset)?)?;
            if count > MAX_ABI_ARRAY {
                return None;
            }
            let mut items = Vec::with_capacity(count);
            let mut cursor = offset.checked_add(WORD)?;
            for _ in 0..count {
                let first = address_word(word(data, cursor)?)?;
                cursor = cursor.checked_add(WORD)?;
                let second = address_word(word(data, cursor)?)?;
                cursor = cursor.checked_add(WORD)?;
                items.push(AbiValue::Tuple(vec![
                    AbiValue::Address(first),
                    AbiValue::Address(second),
                ]));
            }
            Some((AbiValue::Array(items), cursor))
        }
        AbiType::BytesArray => {
            let count = small_word(word(data, offset)?)?;
            if count > MAX_ABI_ARRAY {
                return None;
            }
            let base = offset.checked_add(WORD)?;
            let mut next = count.checked_mul(WORD)?;
            let mut items = Vec::with_capacity(count);
            for index in 0..count {
                let head = base.checked_add(index.checked_mul(WORD)?)?;
                let element = small_word(word(data, head)?)?;
                if element != next {
                    return None;
                }
                let (bytes, end) = decode_bytes_at(data, base.checked_add(element)?)?;
                items.push(AbiValue::Bytes(bytes));
                next = end.checked_sub(base)?;
            }
            Some((AbiValue::Array(items), base.checked_add(next)?))
        }
        AbiType::Address | AbiType::Bool | AbiType::Uint(_) | AbiType::Bytes32 => None,
    }
}

/// Decodes canonical parameters (no selector). `None` is an R2 violation.
pub(crate) fn decode_params(types: &[AbiType], data: &[u8]) -> Option<Vec<AbiValue>> {
    let head_size = types.len().checked_mul(WORD)?;
    if data.len() < head_size {
        return None;
    }
    let mut next_tail = head_size;
    let mut values = Vec::with_capacity(types.len());
    for (index, kind) in types.iter().enumerate() {
        let head = word(data, index.checked_mul(WORD)?)?;
        let value = match kind {
            AbiType::Address => AbiValue::Address(address_word(head)?),
            AbiType::Bool => match small_word(head)? {
                0 => AbiValue::Bool(false),
                1 => AbiValue::Bool(true),
                _ => return None,
            },
            AbiType::Uint(bits) => AbiValue::Uint(uint_word(head, *bits)?),
            AbiType::Bytes32 => AbiValue::Bytes32(*head),
            dynamic => {
                if small_word(head)? != next_tail {
                    return None;
                }
                let (value, end) = decode_dynamic(*dynamic, data, next_tail)?;
                next_tail = end;
                value
            }
        };
        values.push(value);
    }
    (next_tail == data.len()).then_some(values)
}

fn is_dynamic_value(value: &AbiValue) -> bool {
    match value {
        AbiValue::Bytes(_) | AbiValue::Array(_) => true,
        AbiValue::Tuple(items) => items.iter().any(is_dynamic_value),
        AbiValue::Address(_) | AbiValue::Uint(_) | AbiValue::Bool(_) | AbiValue::Bytes32(_) => {
            false
        }
    }
}

fn usize_word(value: usize) -> [u8; 32] {
    U256::from_u64(u64::try_from(value).unwrap_or(u64::MAX)).to_be_bytes()
}

fn encode_static(out: &mut Vec<u8>, value: &AbiValue) {
    match value {
        AbiValue::Address(address) => out.extend_from_slice(&pad_address(address)),
        AbiValue::Uint(number) => out.extend_from_slice(number.as_be_bytes()),
        AbiValue::Bool(flag) => {
            out.extend_from_slice(&U256::from_u64(u64::from(*flag)).to_be_bytes());
        }
        AbiValue::Bytes32(bytes) => out.extend_from_slice(bytes),
        AbiValue::Tuple(items) => {
            for item in items {
                encode_static(out, item);
            }
        }
        AbiValue::Bytes(_) | AbiValue::Array(_) => {}
    }
}

fn encode_tail(value: &AbiValue) -> Vec<u8> {
    let mut out = Vec::new();
    match value {
        AbiValue::Bytes(bytes) => {
            out.extend_from_slice(&usize_word(bytes.len()));
            out.extend_from_slice(bytes);
            let padded = padded_len(bytes.len()).unwrap_or(bytes.len());
            out.resize(WORD.saturating_add(padded), 0);
        }
        AbiValue::Array(items) => {
            out.extend_from_slice(&usize_word(items.len()));
            out.extend_from_slice(&encode_params(items));
        }
        AbiValue::Address(_)
        | AbiValue::Uint(_)
        | AbiValue::Bool(_)
        | AbiValue::Bytes32(_)
        | AbiValue::Tuple(_) => encode_static(&mut out, value),
    }
    out
}

/// Canonical ABI encoding of `values` (inverse of the decoder; dynamic tuples unsupported).
#[must_use]
pub fn encode_params(values: &[AbiValue]) -> Vec<u8> {
    let head_words = |value: &AbiValue| match value {
        AbiValue::Tuple(items) if !is_dynamic_value(value) => items.len(),
        _ => 1,
    };
    let head_size: usize = values
        .iter()
        .map(head_words)
        .fold(0, usize::saturating_add)
        .saturating_mul(WORD);
    let mut head = Vec::with_capacity(head_size);
    let mut tails = Vec::new();
    for value in values {
        if is_dynamic_value(value) {
            head.extend_from_slice(&usize_word(head_size.saturating_add(tails.len())));
            tails.extend_from_slice(&encode_tail(value));
        } else {
            encode_static(&mut head, value);
        }
    }
    head.extend_from_slice(&tails);
    head
}

/// `selector ‖ encode_params(values)`.
#[must_use]
pub fn encode_call(selector: [u8; 4], values: &[AbiValue]) -> Vec<u8> {
    let mut out = selector.to_vec();
    out.extend_from_slice(&encode_params(values));
    out
}

/// ERC-20 `transfer(recipient, amount)` calldata, 68 bytes (spec/03 §3.3).
#[must_use]
pub fn erc20_transfer_data(recipient: &Address, amount: &U256) -> Vec<u8> {
    encode_call(
        SEL_TRANSFER,
        &[AbiValue::Address(*recipient), AbiValue::Uint(*amount)],
    )
}

/// `balanceOf(owner)` calldata.
#[must_use]
pub fn balance_of_data(owner: &Address) -> Vec<u8> {
    encode_call(SEL_BALANCE_OF, &[AbiValue::Address(*owner)])
}

/// Decodes a `decimals()` result: exactly one word, value ≤ 36 (spec/03 §2.5).
#[must_use]
pub fn decode_decimals(output: &[u8]) -> Option<u8> {
    let word: &[u8; 32] = output.try_into().ok()?;
    let value = U256::from_be_bytes(*word).to_u64()?;
    u8::try_from(value).ok().filter(|decimals| *decimals <= 36)
}

fn validated_symbol(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty()
        || bytes.len() > 16
        || !bytes.iter().all(|byte| (0x21..=0x7e).contains(byte))
    {
        return None;
    }
    String::from_utf8(bytes.to_vec()).ok()
}

/// Decodes a `symbol()` result: `bytes32` (NUL-padded) or a canonical dynamic `string`;
/// characters 0x21–0x7E, 1–16 bytes. `None` → `?` + E26.
#[must_use]
pub fn decode_symbol(output: &[u8]) -> Option<String> {
    if output.len() == WORD {
        let end = output.iter().position(|byte| *byte == 0).unwrap_or(WORD);
        let (symbol, rest) = output.split_at(end);
        if rest.iter().any(|byte| *byte != 0) {
            return None;
        }
        return validated_symbol(symbol);
    }
    match decode_params(&[AbiType::Bytes], output)?.first()? {
        AbiValue::Bytes(bytes) => validated_symbol(bytes),
        _ => None,
    }
}

/// Decodes a `balanceOf` result (exactly one word).
#[must_use]
pub fn decode_uint256_result(output: &[u8]) -> Option<U256> {
    let word: &[u8; 32] = output.try_into().ok()?;
    Some(U256::from_be_bytes(*word))
}

#[cfg(test)]
mod tests {
    use super::{
        AbiType, AbiValue, decode_decimals, decode_params, decode_symbol, encode_params,
        erc20_transfer_data,
    };
    use crate::evm::address::Address;
    use crate::evm::amount::U256;

    #[test]
    fn transfer_builder_is_68_bytes() {
        let data = erc20_transfer_data(&Address::from_bytes([0xab; 20]), &U256::from_u64(5));
        assert_eq!(data.len(), 68);
        assert_eq!(data.get(..4).unwrap(), &[0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(data.get(16..36).unwrap(), &[0xab; 20]);
        assert_eq!(data.last(), Some(&5));
    }

    #[test]
    fn canonical_round_trip_and_rejections() {
        let values = vec![
            AbiValue::Address(Address::from_bytes([1; 20])),
            AbiValue::Array(vec![AbiValue::Uint(U256::ONE), AbiValue::Uint(U256::MAX)]),
            AbiValue::Bytes(vec![7; 33]),
            AbiValue::Array(vec![AbiValue::Bytes(vec![1]), AbiValue::Bytes(vec![])]),
        ];
        let types = [
            AbiType::Address,
            AbiType::UintArray,
            AbiType::Bytes,
            AbiType::BytesArray,
        ];
        let encoded = encode_params(&values);
        assert_eq!(decode_params(&types, &encoded), Some(values));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(decode_params(&types, &trailing), None);
        let mut bad_padding = encoded.clone();
        *bad_padding.last_mut().unwrap() = 1;
        assert_eq!(decode_params(&types, &bad_padding), None);
        let mut bad_offset = encoded;
        *bad_offset.get_mut(63).unwrap() = 0xa0;
        assert_eq!(decode_params(&types, &bad_offset), None);
        // dirty address word
        let mut dirty = [0_u8; 32];
        dirty[0] = 1;
        assert_eq!(decode_params(&[AbiType::Address], &dirty), None);
        assert_eq!(decode_params(&[AbiType::Bool], &[0; 31]), None);
        let mut two = [0_u8; 32];
        two[31] = 2;
        assert_eq!(decode_params(&[AbiType::Bool], &two), None);
        let mut big = [0_u8; 32];
        big[0] = 1;
        assert_eq!(decode_params(&[AbiType::Uint(48)], &big), None);
    }

    #[test]
    fn erc20_result_decoders() {
        let mut word = [0_u8; 32];
        word[31] = 18;
        assert_eq!(decode_decimals(&word), Some(18));
        word[31] = 37;
        assert_eq!(decode_decimals(&word), None);
        let mut bytes32 = [0_u8; 32];
        bytes32[..3].copy_from_slice(b"MKR");
        assert_eq!(decode_symbol(&bytes32).as_deref(), Some("MKR"));
        let dynamic = encode_params(&[AbiValue::Bytes(b"USDC".to_vec())]);
        assert_eq!(decode_symbol(&dynamic).as_deref(), Some("USDC"));
        assert_eq!(
            decode_symbol(&encode_params(&[AbiValue::Bytes(b"US DC".to_vec())])),
            None
        );
        assert_eq!(
            decode_symbol(&encode_params(&[AbiValue::Bytes(vec![b'A'; 17])])),
            None
        );
        assert_eq!(decode_symbol(&[]), None);
    }
}
