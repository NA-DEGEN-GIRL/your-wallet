//! Calldata interpretation (spec/03 §7.1–§7.2, R1–R5) and revert reasons (§7.4).
//!
//! The selector + strict decode is the only basis of interpretation; public selector databases are
//! never consulted. Structure follows `archive/spec-v2.4:demo/sepolia-wallet/src/erc20.rs:1-583`
//! generalized to the spec/03 §7.1 table.
#![deny(clippy::indexing_slicing)]

use super::abi::{
    self, AbiType, AbiValue, SEL_APPROVE, SEL_DAI_PERMIT, SEL_DECREASE_ALLOWANCE,
    SEL_ERC2612_PERMIT, SEL_ERROR_STRING, SEL_INCREASE_ALLOWANCE, SEL_MULTICALL,
    SEL_MULTICALL_BLOCKHASH, SEL_MULTICALL_DEADLINE, SEL_PANIC_UINT256, SEL_PERMIT2_APPROVE,
    SEL_PERMIT2_INVALIDATE_NONCES, SEL_PERMIT2_INVALIDATE_UNORDERED_NONCES, SEL_PERMIT2_LOCKDOWN,
    SEL_PERMIT2_PERMIT_BATCH, SEL_PERMIT2_PERMIT_BATCH_TRANSFER_FROM, SEL_PERMIT2_PERMIT_SINGLE,
    SEL_PERMIT2_PERMIT_TRANSFER_FROM, SEL_PERMIT2_PERMIT_WITNESS_TRANSFER_FROM,
    SEL_PERMIT2_TRANSFER_FROM, SEL_PERMIT2_TRANSFER_FROM_BATCH, SEL_SAFE_BATCH_TRANSFER_FROM_1155,
    SEL_SAFE_TRANSFER_FROM_721, SEL_SAFE_TRANSFER_FROM_721_DATA, SEL_SAFE_TRANSFER_FROM_1155,
    SEL_SEAPORT_CANCEL, SEL_SEAPORT_FULFILL_BASIC_ORDER, SEL_SEAPORT_FULFILL_BASIC_ORDER_EFFICIENT,
    SEL_SEAPORT_INCREMENT_COUNTER, SEL_SET_APPROVAL_FOR_ALL, SEL_TRANSFER, SEL_TRANSFER_FROM,
    SEL_UNIVERSAL_ROUTER_EXECUTE, SEL_UNIVERSAL_ROUTER_EXECUTE_DEADLINE, SEL_WETH_DEPOSIT,
    SEL_WETH_WITHDRAW,
};
use super::address::Address;
use super::chain::{ChainInfo, ContractRole};
use super::simulate::LogEvent;
use super::tx::Eip1559Tx;

/// Maximum inner calls of a multicall (R5).
pub const MAX_MULTICALL_INNER: usize = 16;

/// Ambiguous ERC-20/ERC-721 argument name until R4 resolves it.
pub const AMOUNT_OR_TOKEN_ID: &str = "amount_or_token_id";

/// Interpreted calldata (spec/03 §7.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodedCall {
    /// Empty calldata.
    NativeTransfer,
    /// A table entry with canonical arguments.
    Known {
        /// Fixed kind string (spec/03 §7.1).
        kind: &'static str,
        /// Fixed title; `{native}`/`{wrapped}` are substituted at display time.
        title: &'static str,
        /// Named arguments in table order.
        args: Vec<(&'static str, AbiValue)>,
    },
    /// A one-level multicall (R5).
    Multicall {
        /// `"multicall"`.
        kind: &'static str,
        /// Head arguments (`deadline` or `previous_block_hash`).
        head: Vec<(&'static str, AbiValue)>,
        /// Inner calls interpreted against the same `to`.
        inner: Vec<DecodedCall>,
    },
    /// Not interpreted (E12).
    Uninterpreted {
        /// The selector when the data has at least 4 bytes.
        selector: Option<[u8; 4]>,
        /// Registry label for label-only selectors.
        label: Option<&'static str>,
    },
}

/// A transaction with its interpretation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedTx {
    /// The transaction to sign.
    pub tx: Eip1559Tx,
    /// Its interpretation.
    pub call: DecodedCall,
}

impl DecodedCall {
    /// Whether this call or any inner call is uninterpreted (E12). A multicall without inner
    /// calls counts as uninterpreted: its effect is not described by any interpreted call.
    #[must_use]
    pub fn has_uninterpreted(&self) -> bool {
        match self {
            Self::Uninterpreted { .. } => true,
            Self::Multicall { inner, .. } => {
                inner.is_empty() || inner.iter().any(Self::has_uninterpreted)
            }
            Self::NativeTransfer | Self::Known { .. } => false,
        }
    }

    /// The named argument of a `Known` call.
    #[must_use]
    pub fn arg(&self, name: &str) -> Option<&AbiValue> {
        match self {
            Self::Known { args, .. } => args
                .iter()
                .find_map(|(arg, value)| (*arg == name).then_some(value)),
            _ => None,
        }
    }

    /// The `Known` kind string.
    #[must_use]
    pub const fn kind(&self) -> Option<&'static str> {
        match self {
            Self::Known { kind, .. } | Self::Multicall { kind, .. } => Some(kind),
            Self::NativeTransfer => Some("native_transfer"),
            Self::Uninterpreted { .. } => None,
        }
    }
}

fn known(
    kind: &'static str,
    title: &'static str,
    names: &[&'static str],
    values: Vec<AbiValue>,
) -> DecodedCall {
    DecodedCall::Known {
        kind,
        title,
        args: names.iter().copied().zip(values).collect(),
    }
}

const fn uninterpreted(selector: [u8; 4]) -> DecodedCall {
    DecodedCall::Uninterpreted {
        selector: Some(selector),
        label: None,
    }
}

fn label_only(chain: &ChainInfo, to: &Address, selector: [u8; 4]) -> Option<&'static str> {
    let contract = chain.contract(to)?;
    let listed: &[[u8; 4]] = match contract.role {
        ContractRole::Permit2 => &[
            SEL_PERMIT2_PERMIT_SINGLE,
            SEL_PERMIT2_PERMIT_BATCH,
            SEL_PERMIT2_TRANSFER_FROM,
            SEL_PERMIT2_TRANSFER_FROM_BATCH,
            SEL_PERMIT2_PERMIT_TRANSFER_FROM,
            SEL_PERMIT2_PERMIT_BATCH_TRANSFER_FROM,
            SEL_PERMIT2_PERMIT_WITNESS_TRANSFER_FROM,
        ],
        ContractRole::Seaport15 | ContractRole::Seaport16 => &[
            SEL_SEAPORT_FULFILL_BASIC_ORDER,
            SEL_SEAPORT_FULFILL_BASIC_ORDER_EFFICIENT,
            SEL_SEAPORT_CANCEL,
            SEL_SEAPORT_INCREMENT_COUNTER,
        ],
        ContractRole::LabelOnly if contract.label == "Uniswap Universal Router" => &[
            SEL_UNIVERSAL_ROUTER_EXECUTE_DEADLINE,
            SEL_UNIVERSAL_ROUTER_EXECUTE,
        ],
        ContractRole::LabelOnly => &[],
    };
    listed.contains(&selector).then_some(contract.label)
}

/// Interprets calldata sent to `to` on `chain` (spec/03 §7.1–§7.2). R4 ambiguity is resolved
/// later by [`resolve_token_standard`] with simulation logs.
#[must_use]
pub fn decode_call(chain: &ChainInfo, to: &Address, data: &[u8]) -> DecodedCall {
    decode_level(chain, to, data, true)
}

fn decode_level(
    chain: &ChainInfo,
    to: &Address,
    data: &[u8],
    allow_multicall: bool,
) -> DecodedCall {
    if data.is_empty() {
        // Only the top level is a plain native transfer; an empty inner multicall entry is a
        // call to `to` with no data (fallback/receive), never "보내기" (E12).
        return if allow_multicall {
            DecodedCall::NativeTransfer
        } else {
            DecodedCall::Uninterpreted {
                selector: None,
                label: None,
            }
        };
    }
    let Some((selector, params)) = data.split_first_chunk::<4>() else {
        return DecodedCall::Uninterpreted {
            selector: None,
            label: None,
        };
    };
    let selector = *selector;
    if let Some(label) = label_only(chain, to, selector) {
        return DecodedCall::Uninterpreted {
            selector: Some(selector),
            label: Some(label),
        };
    }
    decode_selector(chain, to, selector, params, allow_multicall).unwrap_or(uninterpreted(selector))
}

#[expect(
    clippy::too_many_lines,
    reason = "one arm per row of the spec/03 §7.1 table"
)]
fn decode_selector(
    chain: &ChainInfo,
    to: &Address,
    selector: [u8; 4],
    params: &[u8],
    allow_multicall: bool,
) -> Option<DecodedCall> {
    use AbiType::{
        Address as A, AddressPairArray, Bool, Bytes, Bytes32, BytesArray, Uint, UintArray,
    };
    let decode = |types: &[AbiType]| abi::decode_params(types, params);
    let u256 = Uint(256);
    let call = match selector {
        SEL_TRANSFER => known(
            "erc20_transfer",
            "토큰 전송",
            &["to", "amount"],
            decode(&[A, u256])?,
        ),
        SEL_APPROVE => known(
            "erc20_approve",
            "토큰 사용 승인",
            &["spender", AMOUNT_OR_TOKEN_ID],
            decode(&[A, u256])?,
        ),
        SEL_TRANSFER_FROM => known(
            "erc20_transfer_from",
            "토큰 이체",
            &["from", "to", AMOUNT_OR_TOKEN_ID],
            decode(&[A, A, u256])?,
        ),
        SEL_INCREASE_ALLOWANCE => known(
            "erc20_increase_allowance",
            "토큰 승인 증가",
            &["spender", "added"],
            decode(&[A, u256])?,
        ),
        SEL_DECREASE_ALLOWANCE => known(
            "erc20_decrease_allowance",
            "토큰 승인 감소",
            &["spender", "subtracted"],
            decode(&[A, u256])?,
        ),
        SEL_SET_APPROVAL_FOR_ALL => known(
            "set_approval_for_all",
            "컬렉션 전체 권한",
            &["operator", "approved"],
            decode(&[A, Bool])?,
        ),
        SEL_SAFE_TRANSFER_FROM_721 => known(
            "erc721_safe_transfer",
            "NFT 이체",
            &["from", "to", "token_id"],
            decode(&[A, A, u256])?,
        ),
        SEL_SAFE_TRANSFER_FROM_721_DATA => known(
            "erc721_safe_transfer",
            "NFT 이체",
            &["from", "to", "token_id", "data"],
            decode(&[A, A, u256, Bytes])?,
        ),
        SEL_SAFE_TRANSFER_FROM_1155 => known(
            "erc1155_safe_transfer",
            "멀티 토큰 이체",
            &["from", "to", "id", "amount", "data"],
            decode(&[A, A, u256, u256, Bytes])?,
        ),
        SEL_SAFE_BATCH_TRANSFER_FROM_1155 => {
            let values = decode(&[A, A, UintArray, UintArray, Bytes])?;
            match (values.get(2), values.get(3)) {
                (Some(AbiValue::Array(ids)), Some(AbiValue::Array(amounts)))
                    if ids.len() == amounts.len() => {}
                _ => return None,
            }
            known(
                "erc1155_safe_batch_transfer",
                "멀티 토큰 일괄 이체",
                &["from", "to", "ids", "amounts", "data"],
                values,
            )
        }
        SEL_WETH_DEPOSIT if chain.is_weth(to) => {
            decode(&[])?;
            known("weth_deposit", "{native} → {wrapped} 변환", &[], Vec::new())
        }
        SEL_WETH_WITHDRAW if chain.is_weth(to) => known(
            "weth_withdraw",
            "{wrapped} → {native} 변환",
            &["amount"],
            decode(&[u256])?,
        ),
        SEL_PERMIT2_APPROVE if chain.is_permit2(to) => known(
            "permit2_approve",
            "Permit2 승인",
            &["token", "spender", "amount", "expiration"],
            decode(&[A, A, Uint(160), Uint(48)])?,
        ),
        SEL_PERMIT2_LOCKDOWN if chain.is_permit2(to) => known(
            "permit2_lockdown",
            "Permit2 승인 해제",
            &["pairs"],
            decode(&[AddressPairArray])?,
        ),
        SEL_PERMIT2_INVALIDATE_NONCES if chain.is_permit2(to) => known(
            "permit2_invalidate_nonces",
            "Permit2 nonce 무효화",
            &["token", "spender", "new_nonce"],
            decode(&[A, A, Uint(48)])?,
        ),
        SEL_PERMIT2_INVALIDATE_UNORDERED_NONCES if chain.is_permit2(to) => known(
            "permit2_invalidate_unordered_nonces",
            "Permit2 서명 무효화",
            &["word_pos", "mask"],
            decode(&[u256, u256])?,
        ),
        SEL_ERC2612_PERMIT => {
            let mut values = decode(&[A, A, u256, u256, Uint(8), Bytes32, Bytes32])?;
            values.truncate(4);
            known(
                "erc2612_permit_submit",
                "permit 제출",
                &["owner", "spender", "value", "deadline"],
                values,
            )
        }
        SEL_DAI_PERMIT => {
            let values = decode(&[A, A, u256, u256, Bool, Uint(8), Bytes32, Bytes32])?;
            let mut values = values;
            values.truncate(5);
            known(
                "dai_permit_submit",
                "DAI permit 제출",
                &["holder", "spender", "nonce", "expiry", "allowed"],
                values,
            )
        }
        SEL_MULTICALL | SEL_MULTICALL_DEADLINE | SEL_MULTICALL_BLOCKHASH => {
            if !allow_multicall {
                return None;
            }
            let (types, head_name): (&[AbiType], Option<&'static str>) = match selector {
                SEL_MULTICALL_DEADLINE => (&[u256, BytesArray], Some("deadline")),
                SEL_MULTICALL_BLOCKHASH => (&[Bytes32, BytesArray], Some("previous_block_hash")),
                _ => (&[BytesArray], None),
            };
            let mut values = decode(types)?;
            let Some(AbiValue::Array(calls)) = values.pop() else {
                return None;
            };
            if calls.len() > MAX_MULTICALL_INNER {
                return None;
            }
            let mut inner = Vec::with_capacity(calls.len());
            for call in calls {
                let AbiValue::Bytes(bytes) = call else {
                    return None;
                };
                inner.push(decode_level(chain, to, &bytes, false));
            }
            let head = head_name.into_iter().zip(values).collect();
            DecodedCall::Multicall {
                kind: "multicall",
                head,
                inner,
            }
        }
        _ => return None,
    };
    Some(call)
}

/// R4: decides ERC-20 vs ERC-721 for `approve`/`transferFrom` from `to`'s simulation logs.
/// Returns the resolved call and whether an ambiguity remains (E13 when logs were usable).
#[must_use]
pub fn resolve_token_standard(
    call: &DecodedCall,
    to: &Address,
    events: Option<&[LogEvent]>,
) -> (DecodedCall, bool) {
    match call {
        DecodedCall::Known { kind, args, .. }
            if args.iter().any(|(name, _)| *name == AMOUNT_OR_TOKEN_ID) =>
        {
            let standard = events.and_then(|events| detect_standard(kind, to, events));
            let values: Vec<AbiValue> = args.iter().map(|(_, value)| value.clone()).collect();
            match (*kind, standard) {
                ("erc20_approve", Some(false)) => (
                    known(
                        "erc20_approve",
                        "토큰 사용 승인",
                        &["spender", "amount"],
                        values,
                    ),
                    false,
                ),
                ("erc20_approve", Some(true)) => (
                    known(
                        "erc721_approve",
                        "NFT 개별 승인",
                        &["approved", "token_id"],
                        values,
                    ),
                    false,
                ),
                ("erc20_transfer_from", Some(false)) => (
                    known(
                        "erc20_transfer_from",
                        "토큰 이체",
                        &["from", "to", "amount"],
                        values,
                    ),
                    false,
                ),
                ("erc20_transfer_from", Some(true)) => (
                    known(
                        "erc721_transfer_from",
                        "NFT 이체",
                        &["from", "to", "token_id"],
                        values,
                    ),
                    false,
                ),
                _ => (call.clone(), true),
            }
        }
        DecodedCall::Multicall { kind, head, inner } => {
            let mut ambiguous = false;
            let inner = inner
                .iter()
                .map(|call| {
                    let (resolved, unresolved) = resolve_token_standard(call, to, events);
                    ambiguous |= unresolved;
                    resolved
                })
                .collect();
            (
                DecodedCall::Multicall {
                    kind,
                    head: head.clone(),
                    inner,
                },
                ambiguous,
            )
        }
        _ => (call.clone(), false),
    }
}

/// `Some(true)` = ERC-721, `Some(false)` = ERC-20, `None` = no deciding log from `to`.
fn detect_standard(kind: &str, to: &Address, events: &[LogEvent]) -> Option<bool> {
    events.iter().find_map(|event| match (kind, event) {
        ("erc20_approve", LogEvent::Erc20Approval { token, .. })
        | ("erc20_transfer_from", LogEvent::Erc20Transfer { token, .. })
            if token == to =>
        {
            Some(false)
        }
        ("erc20_approve", LogEvent::Erc721Approval { token, .. })
        | ("erc20_transfer_from", LogEvent::Erc721Transfer { token, .. })
            if token == to =>
        {
            Some(true)
        }
        _ => None,
    })
}

fn panic_text(code: &abi::AbiValue) -> String {
    let AbiValue::Uint(code) = code else {
        return "메시지 형식 불명".to_owned();
    };
    let description = match code.to_u64() {
        Some(0x00) => Some("일반"),
        Some(0x01) => Some("assert 실패"),
        Some(0x11) => Some("산술 오버플로"),
        Some(0x12) => Some("0으로 나눔"),
        Some(0x21) => Some("잘못된 enum 변환"),
        Some(0x22) => Some("저장소 바이트 배열 인코딩 오류"),
        Some(0x31) => Some("빈 배열 pop"),
        Some(0x32) => Some("배열 범위 초과"),
        Some(0x41) => Some("메모리 과다 할당"),
        Some(0x51) => Some("초기화되지 않은 함수 호출"),
        _ => None,
    };
    let hex = code.to_quantity();
    let digits = hex.trim_start_matches("0x");
    let padded = if digits.len() % 2 == 1 {
        format!("0{digits}")
    } else {
        digits.to_owned()
    };
    match description {
        Some(text) => format!("Panic 0x{padded} ({text})"),
        None => format!("Panic 0x{padded}"),
    }
}

/// The token recipient of an ERC-20 `transfer(to, amount)` (`a9059cbb`) or
/// `transferFrom(from, to, amount)` (`23b872dd`) call: the same strict decode as the §7.1 table
/// rows (exact length, clean address words), without the registry lookup. `None` for any other
/// calldata.
#[must_use]
pub fn token_transfer_recipient(data: &[u8]) -> Option<Address> {
    let (selector, params) = data.split_first_chunk::<4>()?;
    let u256 = AbiType::Uint(256);
    let values = match *selector {
        SEL_TRANSFER => abi::decode_params(&[AbiType::Address, u256], params)?,
        SEL_TRANSFER_FROM => {
            abi::decode_params(&[AbiType::Address, AbiType::Address, u256], params)?
        }
        _ => return None,
    };
    match values.as_slice() {
        [AbiValue::Address(to), _] | [_, AbiValue::Address(to), _] => Some(*to),
        _ => None,
    }
}

/// Human-readable revert reason of `error.data` (spec/03 §7.4).
#[must_use]
pub fn revert_reason(data: &[u8]) -> String {
    if data.is_empty() {
        return "이유 없이 되돌려짐".to_owned();
    }
    let Some((selector, params)) = data.split_first_chunk::<4>() else {
        return "메시지 형식 불명".to_owned();
    };
    match *selector {
        SEL_ERROR_STRING => {
            let message = abi::decode_params(&[AbiType::Bytes], params)
                .and_then(|mut values| values.pop())
                .and_then(|value| match value {
                    AbiValue::Bytes(bytes) => String::from_utf8(bytes).ok(),
                    _ => None,
                })
                .filter(|text| {
                    text.len() <= 160 && text.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
                });
            match message {
                Some(text) => format!("(검증되지 않은 컨트랙트 메시지) \"{text}\""),
                None => "메시지 형식 불명".to_owned(),
            }
        }
        SEL_PANIC_UINT256 => abi::decode_params(&[AbiType::Uint(256)], params)
            .and_then(|values| values.first().map(panic_text))
            .unwrap_or_else(|| "메시지 형식 불명".to_owned()),
        other => format!(
            "사용자 정의 오류 0x{} ({}바이트)",
            crate::hex::encode(&other),
            data.len()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{DecodedCall, revert_reason, token_transfer_recipient};
    use crate::evm::abi::{
        AbiValue, SEL_APPROVE, SEL_ERROR_STRING, SEL_PANIC_UINT256, SEL_TRANSFER,
        SEL_TRANSFER_FROM, encode_call,
    };
    use crate::evm::address::Address;
    use crate::evm::amount::U256;

    #[test]
    fn token_transfer_recipients() {
        let from = Address::from_bytes([0x11; 20]);
        let to = Address::from_bytes([0x22; 20]);
        let amount = AbiValue::Uint(U256::from_u64(5));
        let transfer = encode_call(SEL_TRANSFER, &[AbiValue::Address(to), amount.clone()]);
        assert_eq!(token_transfer_recipient(&transfer), Some(to));
        let transfer_from = encode_call(
            SEL_TRANSFER_FROM,
            &[
                AbiValue::Address(from),
                AbiValue::Address(to),
                amount.clone(),
            ],
        );
        assert_eq!(token_transfer_recipient(&transfer_from), Some(to));
        // Other selectors, trailing bytes, short data and dirty address words: none.
        let approve = encode_call(SEL_APPROVE, &[AbiValue::Address(to), amount]);
        assert_eq!(token_transfer_recipient(&approve), None);
        let mut long = transfer.clone();
        long.push(0);
        assert_eq!(token_transfer_recipient(&long), None);
        assert_eq!(
            token_transfer_recipient(transfer.get(..40).unwrap_or(&[])),
            None
        );
        assert_eq!(token_transfer_recipient(&[]), None);
        let mut dirty = transfer;
        if let Some(byte) = dirty.get_mut(4) {
            *byte = 1;
        }
        assert_eq!(token_transfer_recipient(&dirty), None);
    }

    #[test]
    fn revert_reasons() {
        assert_eq!(revert_reason(&[]), "이유 없이 되돌려짐");
        let message = encode_call(
            SEL_ERROR_STRING,
            &[AbiValue::Bytes(b"insufficient balance".to_vec())],
        );
        assert_eq!(
            revert_reason(&message),
            "(검증되지 않은 컨트랙트 메시지) \"insufficient balance\""
        );
        let control = encode_call(SEL_ERROR_STRING, &[AbiValue::Bytes(b"a\nb".to_vec())]);
        assert_eq!(revert_reason(&control), "메시지 형식 불명");
        let long = encode_call(SEL_ERROR_STRING, &[AbiValue::Bytes(vec![b'a'; 161])]);
        assert_eq!(revert_reason(&long), "메시지 형식 불명");
        let panic = encode_call(SEL_PANIC_UINT256, &[AbiValue::Uint(U256::from_u64(0x11))]);
        assert_eq!(revert_reason(&panic), "Panic 0x11 (산술 오버플로)");
        let other_panic = encode_call(SEL_PANIC_UINT256, &[AbiValue::Uint(U256::from_u64(0x99))]);
        assert_eq!(revert_reason(&other_panic), "Panic 0x99");
        assert_eq!(
            revert_reason(&[0xde, 0xad, 0xbe, 0xef]),
            "사용자 정의 오류 0xdeadbeef (4바이트)"
        );
        assert_eq!(revert_reason(&[1, 2]), "메시지 형식 불명");
    }

    #[test]
    fn uninterpreted_detection() {
        let nested = DecodedCall::Multicall {
            kind: "multicall",
            head: Vec::new(),
            inner: vec![
                DecodedCall::NativeTransfer,
                DecodedCall::Uninterpreted {
                    selector: None,
                    label: None,
                },
            ],
        };
        assert!(nested.has_uninterpreted());
        assert!(!DecodedCall::NativeTransfer.has_uninterpreted());
        let empty = DecodedCall::Multicall {
            kind: "multicall",
            head: Vec::new(),
            inner: Vec::new(),
        };
        assert!(empty.has_uninterpreted());
    }
}
