//! Calldata interpretation (spec/03 §7.1–§7.2, EVM-V10): every table selector decoded, R1/R2
//! violations, R3 registry gating, R4 ambiguity, R5 multicall rules and label-only selectors.

use yw_core::evm::abi::*;
use yw_core::evm::address::{Address, AddressError, parse_address};
use yw_core::evm::amount::U256;
use yw_core::evm::chain::{ChainInfo, ethereum_mainnet, sepolia};
use yw_core::evm::decode::{AMOUNT_OR_TOKEN_ID, DecodedCall, decode_call, resolve_token_standard};
use yw_core::evm::simulate::LogEvent;

fn a(byte: u8) -> Address {
    Address::from_bytes([byte; 20])
}

fn weth(chain: &ChainInfo) -> Option<Address> {
    chain.weth().map(|token| token.address)
}

fn permit2() -> Result<Address, AddressError> {
    parse_address("0x000000000022D473030F116dDEE9F6B43aC78BA3")
}

fn kind(call: &DecodedCall) -> Option<&'static str> {
    call.kind()
}

fn uninterpreted(call: &DecodedCall) -> bool {
    matches!(call, DecodedCall::Uninterpreted { .. })
}

fn uint(value: u64) -> AbiValue {
    AbiValue::Uint(U256::from_u64(value))
}

#[test]
#[expect(clippy::too_many_lines, reason = "one case per spec/03 §7.1 row")]
fn each_selector_decodes() {
    let chain = sepolia();
    let token = a(0x11);
    let bytes = AbiValue::Bytes(vec![1, 2, 3]);
    let cases: Vec<(Address, Vec<u8>, &str)> = vec![
        (
            token,
            encode_call(SEL_TRANSFER, &[AbiValue::Address(a(2)), uint(5)]),
            "erc20_transfer",
        ),
        (
            token,
            encode_call(SEL_APPROVE, &[AbiValue::Address(a(2)), uint(5)]),
            "erc20_approve",
        ),
        (
            token,
            encode_call(
                SEL_TRANSFER_FROM,
                &[AbiValue::Address(a(1)), AbiValue::Address(a(2)), uint(5)],
            ),
            "erc20_transfer_from",
        ),
        (
            token,
            encode_call(SEL_INCREASE_ALLOWANCE, &[AbiValue::Address(a(2)), uint(5)]),
            "erc20_increase_allowance",
        ),
        (
            token,
            encode_call(SEL_DECREASE_ALLOWANCE, &[AbiValue::Address(a(2)), uint(5)]),
            "erc20_decrease_allowance",
        ),
        (
            token,
            encode_call(
                SEL_SET_APPROVAL_FOR_ALL,
                &[AbiValue::Address(a(2)), AbiValue::Bool(true)],
            ),
            "set_approval_for_all",
        ),
        (
            token,
            encode_call(
                SEL_SAFE_TRANSFER_FROM_721,
                &[AbiValue::Address(a(1)), AbiValue::Address(a(2)), uint(7)],
            ),
            "erc721_safe_transfer",
        ),
        (
            token,
            encode_call(
                SEL_SAFE_TRANSFER_FROM_721_DATA,
                &[
                    AbiValue::Address(a(1)),
                    AbiValue::Address(a(2)),
                    uint(7),
                    bytes.clone(),
                ],
            ),
            "erc721_safe_transfer",
        ),
        (
            token,
            encode_call(
                SEL_SAFE_TRANSFER_FROM_1155,
                &[
                    AbiValue::Address(a(1)),
                    AbiValue::Address(a(2)),
                    uint(7),
                    uint(3),
                    bytes.clone(),
                ],
            ),
            "erc1155_safe_transfer",
        ),
        (
            token,
            encode_call(
                SEL_SAFE_BATCH_TRANSFER_FROM_1155,
                &[
                    AbiValue::Address(a(1)),
                    AbiValue::Address(a(2)),
                    AbiValue::Array(vec![uint(1), uint(2)]),
                    AbiValue::Array(vec![uint(3), uint(4)]),
                    bytes.clone(),
                ],
            ),
            "erc1155_safe_batch_transfer",
        ),
        (
            weth(&chain).unwrap(),
            SEL_WETH_DEPOSIT.to_vec(),
            "weth_deposit",
        ),
        (
            weth(&chain).unwrap(),
            encode_call(SEL_WETH_WITHDRAW, &[uint(9)]),
            "weth_withdraw",
        ),
        (
            permit2().unwrap(),
            encode_call(
                SEL_PERMIT2_APPROVE,
                &[
                    AbiValue::Address(a(3)),
                    AbiValue::Address(a(2)),
                    uint(5),
                    uint(1_800_000_000),
                ],
            ),
            "permit2_approve",
        ),
        (
            permit2().unwrap(),
            encode_call(
                SEL_PERMIT2_LOCKDOWN,
                &[AbiValue::Array(vec![AbiValue::Tuple(vec![
                    AbiValue::Address(a(3)),
                    AbiValue::Address(a(2)),
                ])])],
            ),
            "permit2_lockdown",
        ),
        (
            permit2().unwrap(),
            encode_call(
                SEL_PERMIT2_INVALIDATE_NONCES,
                &[AbiValue::Address(a(3)), AbiValue::Address(a(2)), uint(4)],
            ),
            "permit2_invalidate_nonces",
        ),
        (
            permit2().unwrap(),
            encode_call(SEL_PERMIT2_INVALIDATE_UNORDERED_NONCES, &[uint(1), uint(2)]),
            "permit2_invalidate_unordered_nonces",
        ),
        (
            token,
            encode_call(
                SEL_ERC2612_PERMIT,
                &[
                    AbiValue::Address(a(1)),
                    AbiValue::Address(a(2)),
                    uint(5),
                    uint(6),
                    uint(27),
                    AbiValue::Bytes32([1; 32]),
                    AbiValue::Bytes32([2; 32]),
                ],
            ),
            "erc2612_permit_submit",
        ),
        (
            token,
            encode_call(
                SEL_DAI_PERMIT,
                &[
                    AbiValue::Address(a(1)),
                    AbiValue::Address(a(2)),
                    uint(5),
                    uint(6),
                    AbiValue::Bool(true),
                    uint(28),
                    AbiValue::Bytes32([1; 32]),
                    AbiValue::Bytes32([2; 32]),
                ],
            ),
            "dai_permit_submit",
        ),
    ];
    for (to, data, expected) in cases {
        let call = decode_call(&chain, &to, &data);
        assert_eq!(kind(&call), Some(expected), "{expected}: {call:?}");
        // Canonical round trip (fuzz invariant): re-encoding the decoded args gives the input
        // for every fully-listed call.
        if let DecodedCall::Known { args, .. } = &call
            && !matches!(expected, "erc2612_permit_submit" | "dai_permit_submit")
        {
            let values: Vec<AbiValue> = args.iter().map(|(_, value)| value.clone()).collect();
            let mut selector = [0_u8; 4];
            selector.copy_from_slice(&data[..4]);
            assert_eq!(encode_call(selector, &values), data, "{expected}");
        }
    }
    assert_eq!(
        decode_call(&chain, &token, &[]),
        DecodedCall::NativeTransfer
    );
}

#[test]
fn r1_r2_violations_are_uninterpreted() {
    let chain = sepolia();
    let token = a(0x11);
    let good = encode_call(SEL_TRANSFER, &[AbiValue::Address(a(2)), uint(5)]);
    let mut trailing = good.clone();
    trailing.push(0);
    let short = good[..67].to_vec();
    let mut dirty_address = good.clone();
    dirty_address[4] = 1;
    let mut bad_bool = encode_call(
        SEL_SET_APPROVAL_FOR_ALL,
        &[AbiValue::Address(a(2)), AbiValue::Bool(true)],
    );
    *bad_bool.last_mut().unwrap() = 2;
    let mut big_uint48 = encode_call(
        SEL_PERMIT2_APPROVE,
        &[
            AbiValue::Address(a(3)),
            AbiValue::Address(a(2)),
            uint(5),
            uint(6),
        ],
    );
    big_uint48[4 + 3 * 32 + 5] = 1;
    let batch_mismatch = encode_call(
        SEL_SAFE_BATCH_TRANSFER_FROM_1155,
        &[
            AbiValue::Address(a(1)),
            AbiValue::Address(a(2)),
            AbiValue::Array(vec![uint(1), uint(2)]),
            AbiValue::Array(vec![uint(3)]),
            AbiValue::Bytes(vec![]),
        ],
    );
    let too_long_array = encode_call(
        SEL_SAFE_BATCH_TRANSFER_FROM_1155,
        &[
            AbiValue::Address(a(1)),
            AbiValue::Address(a(2)),
            AbiValue::Array(vec![uint(1); 65]),
            AbiValue::Array(vec![uint(3); 65]),
            AbiValue::Bytes(vec![]),
        ],
    );
    let mut noncanonical_offset = encode_call(
        SEL_SAFE_TRANSFER_FROM_721_DATA,
        &[
            AbiValue::Address(a(1)),
            AbiValue::Address(a(2)),
            uint(7),
            AbiValue::Bytes(vec![9]),
        ],
    );
    noncanonical_offset[4 + 3 * 32 + 31] = 0xa0;
    let mut dirty_padding = encode_call(
        SEL_SAFE_TRANSFER_FROM_721_DATA,
        &[
            AbiValue::Address(a(1)),
            AbiValue::Address(a(2)),
            uint(7),
            AbiValue::Bytes(vec![9]),
        ],
    );
    *dirty_padding.last_mut().unwrap() = 1;
    for (name, data) in [
        ("trailing", trailing),
        ("short", short),
        ("dirty address", dirty_address),
        ("bool 2", bad_bool),
        ("uint48 overflow", big_uint48),
        ("batch length mismatch", batch_mismatch),
        ("array > 64", too_long_array),
        ("offset", noncanonical_offset),
        ("padding", dirty_padding),
        ("3 bytes", vec![0xa9, 0x05, 0x9c]),
        ("unknown selector", vec![0xde, 0xad, 0xbe, 0xef]),
    ] {
        let to = if name == "uint48 overflow" {
            permit2().unwrap()
        } else {
            token
        };
        assert!(uninterpreted(&decode_call(&chain, &to, &data)), "{name}");
    }
}

#[test]
fn r3_registry_only_selectors() {
    let chain = sepolia();
    let not_registry = a(0x42);
    assert!(uninterpreted(&decode_call(
        &chain,
        &not_registry,
        &SEL_WETH_DEPOSIT
    )));
    assert!(uninterpreted(&decode_call(
        &chain,
        &not_registry,
        &encode_call(SEL_WETH_WITHDRAW, &[uint(1)])
    )));
    assert!(uninterpreted(&decode_call(
        &chain,
        &not_registry,
        &encode_call(
            SEL_PERMIT2_APPROVE,
            &[
                AbiValue::Address(a(3)),
                AbiValue::Address(a(2)),
                uint(5),
                uint(6)
            ]
        )
    )));
    // A user chain has no registry: WETH/Permit2 selectors are never interpreted there.
    let user = yw_core::evm::chain::user_chain_info(
        &yw_core::evm::chain::UserChainInput {
            chain_id: 8_453,
            name: "Test L2".to_owned(),
            native_symbol: "ETH".to_owned(),
            native_decimals: 18,
            explorer: None,
            simulation: yw_core::evm::chain::SimulationSupport::Unsupported,
        },
        [0; 32],
    );
    assert!(uninterpreted(&decode_call(
        &user,
        &permit2().unwrap(),
        &encode_call(SEL_PERMIT2_INVALIDATE_UNORDERED_NONCES, &[uint(1), uint(2)])
    )));
    // ERC-20 selectors are interpreted on any chain.
    assert_eq!(
        kind(&decode_call(
            &user,
            &a(1),
            &encode_call(SEL_TRANSFER, &[AbiValue::Address(a(2)), uint(5)])
        )),
        Some("erc20_transfer")
    );
    // Wrong-chain WETH: mainnet WETH address on Sepolia is not the registry WETH.
    let mainnet_weth = weth(&ethereum_mainnet()).unwrap();
    assert!(uninterpreted(&decode_call(
        &chain,
        &mainnet_weth,
        &SEL_WETH_DEPOSIT
    )));
}

#[test]
fn r4_ambiguity_resolution() {
    let token = a(0x11);
    let user = a(0x01);
    let approve = decode_call(
        &sepolia(),
        &token,
        &encode_call(SEL_APPROVE, &[AbiValue::Address(a(2)), uint(5)]),
    );
    assert!(approve.arg(AMOUNT_OR_TOKEN_ID).is_some());
    let erc20_log = [LogEvent::Erc20Approval {
        token,
        owner: user,
        spender: a(2),
        amount: U256::from_u64(5),
    }];
    let (resolved, ambiguous) = resolve_token_standard(&approve, &token, Some(&erc20_log));
    assert!(!ambiguous);
    assert_eq!(kind(&resolved), Some("erc20_approve"));
    assert!(resolved.arg("amount").is_some());
    let erc721_log = [LogEvent::Erc721Approval {
        token,
        owner: user,
        approved: a(2),
        id: U256::from_u64(5),
    }];
    let (resolved, ambiguous) = resolve_token_standard(&approve, &token, Some(&erc721_log));
    assert!(!ambiguous);
    assert_eq!(kind(&resolved), Some("erc721_approve"));
    assert!(resolved.arg("token_id").is_some());
    // A log from another emitter does not decide.
    let (_, ambiguous) = resolve_token_standard(&approve, &a(0x99), Some(&erc20_log));
    assert!(ambiguous);
    // No logs (simulation unusable): still ambiguous; E13 is skipped by the risk rules.
    let (unresolved, ambiguous) = resolve_token_standard(&approve, &token, None);
    assert!(ambiguous);
    assert_eq!(unresolved, approve);

    let transfer_from = decode_call(
        &sepolia(),
        &token,
        &encode_call(
            SEL_TRANSFER_FROM,
            &[AbiValue::Address(a(1)), AbiValue::Address(a(2)), uint(5)],
        ),
    );
    let nft = [LogEvent::Erc721Transfer {
        token,
        from: a(1),
        to: a(2),
        id: U256::from_u64(5),
    }];
    let (resolved, _) = resolve_token_standard(&transfer_from, &token, Some(&nft));
    assert_eq!(kind(&resolved), Some("erc721_transfer_from"));
}

#[test]
fn r5_multicall_rules() {
    let chain = sepolia();
    let to = a(0x11);
    let inner_transfer = encode_call(SEL_TRANSFER, &[AbiValue::Address(a(2)), uint(5)]);
    let inner_unknown = vec![0xde, 0xad, 0xbe, 0xef];
    let multicall = encode_call(
        SEL_MULTICALL,
        &[AbiValue::Array(vec![
            AbiValue::Bytes(inner_transfer.clone()),
            AbiValue::Bytes(inner_unknown),
        ])],
    );
    let call = decode_call(&chain, &to, &multicall);
    let DecodedCall::Multicall { inner, head, .. } = &call else {
        unreachable!("{call:?}");
    };
    assert!(head.is_empty());
    assert_eq!(kind(&inner[0]), Some("erc20_transfer"));
    assert!(uninterpreted(&inner[1]));
    assert!(call.has_uninterpreted());

    let with_deadline = encode_call(
        SEL_MULTICALL_DEADLINE,
        &[
            uint(1_800_000_000),
            AbiValue::Array(vec![AbiValue::Bytes(inner_transfer.clone())]),
        ],
    );
    let DecodedCall::Multicall { head, .. } = decode_call(&chain, &to, &with_deadline) else {
        unreachable!("deadline multicall");
    };
    assert_eq!(head[0].0, "deadline");
    let with_hash = encode_call(
        SEL_MULTICALL_BLOCKHASH,
        &[
            AbiValue::Bytes32([7; 32]),
            AbiValue::Array(vec![AbiValue::Bytes(inner_transfer.clone())]),
        ],
    );
    let DecodedCall::Multicall { head, .. } = decode_call(&chain, &to, &with_hash) else {
        unreachable!("blockhash multicall");
    };
    assert_eq!(head[0].0, "previous_block_hash");

    // Nested multicall: the inner one is uninterpreted.
    let nested = encode_call(
        SEL_MULTICALL,
        &[AbiValue::Array(vec![AbiValue::Bytes(multicall)])],
    );
    let DecodedCall::Multicall { inner, .. } = decode_call(&chain, &to, &nested) else {
        unreachable!("nested");
    };
    assert!(uninterpreted(&inner[0]));
    // More than 16 inner calls: the whole call is uninterpreted.
    let seventeen = encode_call(
        SEL_MULTICALL,
        &[AbiValue::Array(vec![AbiValue::Bytes(inner_transfer); 17])],
    );
    assert!(uninterpreted(&decode_call(&chain, &to, &seventeen)));
}

#[test]
fn label_only_selectors() {
    let chain = ethereum_mainnet();
    let router = parse_address("0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af").unwrap();
    let seaport = parse_address("0x0000000000000068F116a894984e2DB1123eB395").unwrap();
    for (to, selector, label) in [
        (
            permit2().unwrap(),
            SEL_PERMIT2_PERMIT_SINGLE,
            "Uniswap Permit2",
        ),
        (
            permit2().unwrap(),
            SEL_PERMIT2_PERMIT_WITNESS_TRANSFER_FROM,
            "Uniswap Permit2",
        ),
        (
            router,
            SEL_UNIVERSAL_ROUTER_EXECUTE_DEADLINE,
            "Uniswap Universal Router",
        ),
        (
            router,
            SEL_UNIVERSAL_ROUTER_EXECUTE,
            "Uniswap Universal Router",
        ),
        (
            seaport,
            SEL_SEAPORT_FULFILL_BASIC_ORDER,
            "OpenSea Seaport 1.6",
        ),
        (
            seaport,
            SEL_SEAPORT_FULFILL_BASIC_ORDER_EFFICIENT,
            "OpenSea Seaport 1.6",
        ),
        (seaport, SEL_SEAPORT_CANCEL, "OpenSea Seaport 1.6"),
        (
            seaport,
            SEL_SEAPORT_INCREMENT_COUNTER,
            "OpenSea Seaport 1.6",
        ),
    ] {
        let mut data = selector.to_vec();
        data.extend_from_slice(&[0; 64]);
        assert_eq!(
            decode_call(&chain, &to, &data),
            DecodedCall::Uninterpreted {
                selector: Some(selector),
                label: Some(label)
            }
        );
    }
}
