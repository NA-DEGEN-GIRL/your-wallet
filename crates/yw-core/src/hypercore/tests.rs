//! `HyperCore` vectors (spec/11 §9): the official Python SDK's published signatures
//! (`tests/signing_test.py`: `test_sign_usd_transfer_action`,
//! `test_sign_withdraw_from_bridge_action`, key `0x0123…0123`, Testnet, `signatureChainId
//! 0x66eee`), the generic EIP-712 implementation as a second encoder for every kind, and the
//! `spotMeta` / balance / `/exchange` reply shapes of the API docs.
#![expect(clippy::indexing_slicing, reason = "fixed-size test vectors")]

use secp256k1::{Secp256k1, SecretKey};

use super::{
    HYPE_SYSTEM_ADDRESS, HcAction, HcExchangeReply, HcKind, HcNetwork, HcPayload, is_wire_amount,
    parse_amount, parse_exchange_reply, parse_perp_state, parse_spot_meta, parse_spot_state,
    system_address, system_address_index, wire_amount,
};
use crate::evm::address::{Address, parse_address};
use crate::evm::amount::U256;
use crate::evm::eip712::{
    HlL1Requester, HlUserAction, KnownSchema, validate_typed_data_v4, validate_typed_data_v4_from,
};

const SDK_KEY: &str = "0123456789012345678901234567890123456789012345678901234567890123";
const SDK_DESTINATION: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";
const SDK_TIME: u64 = 1_687_816_341_423;

fn address(text: &str) -> Address {
    parse_address(text).unwrap()
}

/// A dApp's (app.hyperliquid.xyz) `eth_signTypedData_v4` of a transfer and of `approveAgent`
/// gets the structured Hyperliquid display (spec/11 §7): H01 resp. H06, no T04/T10.
#[test]
fn dapp_typed_data_gets_the_hyperliquid_display() {
    use crate::approval::{ApprovalId, ApprovalKind, ApprovalOrigin, ChainFacts, FieldKey};
    use crate::evm::display::build_typed_request;
    use crate::evm::risk::{H01, H06, T04, T10};
    use crate::policy::BrowserOrigin;

    let chain = crate::evm::chain::builtin_chain(42_161).unwrap();
    let account = address(SDK_DESTINATION);
    let origin = ApprovalOrigin::Site(BrowserOrigin::parse("https://app.hyperliquid.xyz").unwrap());
    let build = |source: &[u8]| {
        let value = yw_json::parse(source, &yw_json::Limits::REQUEST).unwrap();
        let typed = validate_typed_data_v4(source, &value, 42_161).unwrap();
        build_typed_request(
            ApprovalId([9; 16]),
            origin.clone(),
            crate::vault::EvmKeySource::Derived(crate::bip32::path::AccountIndex::new(0).unwrap()),
            account,
            ApprovalKind::EvmTypedData,
            &chain,
            &typed,
            &ChainFacts::default(),
            1_790_000_000_000,
        )
        .unwrap()
    };
    let mut action = every_kind(HcNetwork::Mainnet).remove(0);
    action.signature_chain_id = 42_161;
    let draft = build(&yw_json::to_vec(&action.typed_data_json()));
    let rules: Vec<_> = draft.display.warnings.iter().map(|w| w.rule).collect();
    assert!(
        rules.contains(&H01) && !rules.contains(&T04) && !rules.contains(&T10),
        "{rules:?}"
    );
    assert!(
        draft
            .display
            .fields
            .iter()
            .any(|field| field.key == FieldKey::TD_FIELD && field.value == "1.5 USDC")
    );

    let agent = br#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"HyperliquidTransaction:ApproveAgent":[{"name":"hyperliquidChain","type":"string"},{"name":"agentAddress","type":"address"},{"name":"agentName","type":"string"},{"name":"nonce","type":"uint64"}]},"primaryType":"HyperliquidTransaction:ApproveAgent","domain":{"name":"HyperliquidSignTransaction","version":"1","chainId":42161,"verifyingContract":"0x0000000000000000000000000000000000000000"},"message":{"hyperliquidChain":"Mainnet","agentAddress":"0x1111111111111111111111111111111111111111","agentName":"","nonce":1790000000000}}"#;
    let draft = build(agent);
    let rules: Vec<_> = draft.display.warnings.iter().map(|w| w.rule).collect();
    assert!(rules.contains(&H06) && !rules.contains(&T04), "{rules:?}");
}

/// dApp-requested transfers get the S-HC checks (spec/11 §7): a destination outside own accounts
/// and the address book is high risk (H10), a look-alike H03, `withdraw3` elsewhere H11, a token
/// not matching `spotMeta` H12, a system address without its linked token H13; facts missing
/// fail closed; the destination never shows the EVM "일반 계정(EOA)" note.
#[test]
#[expect(clippy::too_many_lines, reason = "one case per rule of spec/11 §7")]
fn dapp_transfers_get_the_site_checks() {
    use crate::approval::{
        ApprovalId, ApprovalKind, ApprovalOrigin, ChainFacts, CodeKind, FieldKey, RuleId,
    };
    use crate::evm::display::build_typed_request;
    use crate::evm::risk::{H03, H04, H10, H11, H12, H13};
    use crate::hypercore::display::{HcRecipient, HlSiteFacts};
    use crate::hypercore::{HcEvmLink, HcToken};
    use crate::policy::BrowserOrigin;

    let chain = crate::evm::chain::builtin_chain(42_161).unwrap();
    let account = address("0x1111111111111111111111111111111111111111");
    let destination = address(SDK_DESTINATION);
    let origin = ApprovalOrigin::Site(BrowserOrigin::parse("https://evil.example").unwrap());
    let purr = HcToken {
        name: "PURR".to_owned(),
        index: 1,
        token_id: "0xc4bf3f870c0e9465323c0b6ed28096c2".to_owned(),
        sz_decimals: 0,
        wei_decimals: 5,
        evm: Some(HcEvmLink {
            address: address("0x9b498c3c8a0b8cd8ba1d9851d40d186f1872b44e"),
            extra_wei_decimals: 13,
        }),
        full_name: None,
    };
    let run = |payload: HcPayload, hyperliquid: Option<HlSiteFacts>| {
        let mut action = HcAction::new(HcNetwork::Mainnet, SDK_TIME, payload);
        action.signature_chain_id = 42_161;
        let source = yw_json::to_vec(&action.typed_data_json());
        let value = yw_json::parse(&source, &yw_json::Limits::REQUEST).unwrap();
        let typed = validate_typed_data_v4(&source, &value, 42_161).unwrap();
        let facts = ChainFacts {
            code: vec![(destination, CodeKind::Eoa)],
            hyperliquid,
            ..ChainFacts::default()
        };
        let draft = build_typed_request(
            ApprovalId([9; 16]),
            origin.clone(),
            crate::vault::EvmKeySource::Derived(crate::bip32::path::AccountIndex::new(0).unwrap()),
            account,
            ApprovalKind::EvmTypedData,
            &chain,
            &typed,
            &facts,
            1_790_000_000_000,
        )
        .unwrap();
        let rules: Vec<RuleId> = draft.display.warnings.iter().map(|w| w.rule).collect();
        let fields: Vec<String> = draft
            .display
            .fields
            .iter()
            .filter(|field| field.key == FieldKey::TD_FIELD)
            .map(|field| field.value.clone())
            .collect();
        (rules, fields)
    };
    let usd = || HcPayload::UsdSend {
        destination,
        amount: "1".to_owned(),
    };
    let checked = |recipient: HcRecipient| HlSiteFacts {
        recipient: Some(recipient),
        spot_meta: Some(vec![purr.clone()]),
    };

    let (rules, fields) = run(usd(), None);
    assert!(rules.contains(&H10), "{rules:?}");
    assert!(
        fields.iter().all(|value| !value.contains("EOA")),
        "{fields:?}"
    );
    let (rules, _) = run(
        usd(),
        Some(checked(HcRecipient {
            notes: vec!["새 주소".to_owned()],
            look_alike: false,
            not_in_book: true,
        })),
    );
    assert!(rules.contains(&H10), "{rules:?}");
    let (rules, _) = run(
        usd(),
        Some(checked(HcRecipient {
            notes: Vec::new(),
            look_alike: true,
            not_in_book: false,
        })),
    );
    assert!(rules.contains(&H03) && !rules.contains(&H10), "{rules:?}");
    let (rules, fields) = run(
        usd(),
        Some(checked(HcRecipient {
            notes: vec!["주소록: 친구".to_owned()],
            look_alike: false,
            not_in_book: false,
        })),
    );
    assert!(!rules.contains(&H10) && !rules.contains(&H03), "{rules:?}");
    assert!(fields.iter().any(|value| value.contains("주소록: 친구")));

    let (rules, fields) = run(
        HcPayload::Withdraw {
            destination,
            amount: "5".to_owned(),
        },
        Some(HlSiteFacts::default()),
    );
    assert!(rules.contains(&H11), "{rules:?}");
    assert!(
        fields.iter().any(|value| value.contains("= 4 USDC")),
        "{fields:?}"
    );

    let to_evm = |token: &str| HcPayload::SpotSend {
        destination: system_address(1),
        token: token.to_owned(),
        amount: "1".to_owned(),
    };
    let (rules, _) = run(to_evm(&purr.wire()), Some(checked(HcRecipient::default())));
    assert!(
        rules.contains(&H04) && !rules.contains(&H13) && !rules.contains(&H12),
        "{rules:?}"
    );
    // spotMeta unavailable, a renamed token and another token's system address.
    let (rules, _) = run(to_evm(&purr.wire()), Some(HlSiteFacts::default()));
    assert!(rules.contains(&H12) && rules.contains(&H13), "{rules:?}");
    let (rules, _) = run(
        to_evm("USDC:0xc4bf3f870c0e9465323c0b6ed28096c2"),
        Some(checked(HcRecipient::default())),
    );
    assert!(rules.contains(&H12) && rules.contains(&H13), "{rules:?}");
    let (rules, _) = run(
        HcPayload::SpotSend {
            destination: system_address(2),
            token: purr.wire(),
            amount: "1".to_owned(),
        },
        Some(checked(HcRecipient::default())),
    );
    assert!(rules.contains(&H13) && !rules.contains(&H04), "{rules:?}");
}

fn sign(action: &HcAction) -> [u8; 65] {
    let ctx = Secp256k1::new();
    let secret =
        SecretKey::from_byte_array(crate::hex::decode_array::<32>(SDK_KEY).unwrap()).unwrap();
    let (y_parity, compact) =
        crate::evm::sign::sign_digest(&ctx, &secret, action.digest()).unwrap();
    let mut out = [0_u8; 65];
    out[..64].copy_from_slice(&compact);
    out[64] = 27 + y_parity;
    out
}

/// The SDK prints `r`/`s` with `to_hex(int)` (no leading zeros).
fn sdk_hex(bytes: &[u8]) -> String {
    let digits = crate::hex::encode(bytes);
    format!("0x{}", digits.trim_start_matches('0'))
}

fn check_sdk(action: &HcAction, r: &str, s: &str, v: u8) {
    let signature = sign(action);
    assert_eq!(sdk_hex(&signature[..32]), r);
    assert_eq!(sdk_hex(&signature[32..64]), s);
    assert_eq!(signature[64], v);
}

#[test]
fn sdk_usd_send_vector() {
    let action = HcAction::new(
        HcNetwork::Testnet,
        SDK_TIME,
        HcPayload::UsdSend {
            destination: address(SDK_DESTINATION),
            amount: "1".to_owned(),
        },
    );
    assert_eq!(action.signature_chain_hex(), "0x66eee");
    check_sdk(
        &action,
        "0x637b37dd731507cdd24f46532ca8ba6eec616952c56218baeff04144e4a77073",
        "0x11a6a24900e6e314136d2592e2f8d502cd89b7c15b198e1bee043c9589f9fad7",
        27,
    );
}

#[test]
fn sdk_withdraw_vector() {
    let action = HcAction::new(
        HcNetwork::Testnet,
        SDK_TIME,
        HcPayload::Withdraw {
            destination: address(SDK_DESTINATION),
            amount: "1".to_owned(),
        },
    );
    check_sdk(
        &action,
        "0x8363524c799e90ce9bc41022f7c39b4e9bdba786e5f9c72b20e43e1462c37cf9",
        "0x58b1411a775938b83e29182e8ef74975f9054c8e97ebf5ec2dc8d51bfc893881",
        28,
    );
}

fn every_kind(network: HcNetwork) -> Vec<HcAction> {
    let destination = address(SDK_DESTINATION);
    let purr = "PURR:0xc4bf3f870c0e9465323c0b6ed28096c2".to_owned();
    [
        HcPayload::UsdSend {
            destination,
            amount: "1.5".to_owned(),
        },
        HcPayload::SpotSend {
            destination,
            token: purr.clone(),
            amount: "0.1".to_owned(),
        },
        HcPayload::Withdraw {
            destination,
            amount: "2".to_owned(),
        },
        HcPayload::UsdClassTransfer {
            amount: "3.25".to_owned(),
            to_perp: true,
        },
        HcPayload::SendAsset {
            destination: system_address(1),
            source_dex: "spot".to_owned(),
            destination_dex: "spot".to_owned(),
            token: purr,
            amount: "0.01".to_owned(),
        },
    ]
    .into_iter()
    .map(|payload| HcAction::new(network, SDK_TIME, payload))
    .collect()
}

/// The direct encoding equals the generic EIP-712 validator's for every kind and both networks,
/// and the validator recognizes the schema (the dApp path, spec/11 §7).
#[test]
fn typed_data_document_hashes_to_the_same_preimage() {
    for network in [HcNetwork::Mainnet, HcNetwork::Testnet] {
        for action in every_kind(network) {
            action.validate().unwrap();
            let source = yw_json::to_vec(&action.typed_data_json());
            let value = yw_json::parse(&source, &yw_json::Limits::REQUEST).unwrap();
            let typed =
                validate_typed_data_v4(&source, &value, network.signature_chain_id()).unwrap();
            assert_eq!(typed.preimage, action.preimage(), "{:?}", action.kind());
            assert_eq!(
                typed.schema,
                Some(KnownSchema::HyperliquidUser(HlUserAction::Transfer(
                    action.kind()
                )))
            );
            // The wire action carries the same fields plus type and signatureChainId.
            let wire = action.action_json();
            let wire = wire.as_object().unwrap();
            assert_eq!(
                wire.get("type").and_then(yw_json::Value::as_str),
                Some(action.kind().wire_type())
            );
            assert_eq!(
                wire.get("hyperliquidChain")
                    .and_then(yw_json::Value::as_str),
                Some(network.chain_name())
            );
        }
    }
}

/// The SDK `l1_payload` (phantom agent, chainId 1337) is recognized on any active chain; any other
/// `Agent` shape keeps the chain-id rejection (T01).
#[test]
fn l1_agent_is_recognized_only_with_the_exact_schema() {
    let document = |fields: &str| {
        format!(
            r#"{{"domain":{{"chainId":1337,"name":"Exchange","verifyingContract":"0x0000000000000000000000000000000000000000","version":"1"}},"types":{{"Agent":[{fields}],"EIP712Domain":[{{"name":"name","type":"string"}},{{"name":"version","type":"string"}},{{"name":"chainId","type":"uint256"}},{{"name":"verifyingContract","type":"address"}}]}},"primaryType":"Agent","message":{{"source":"a","connectionId":"0x0fcbeda5ae3c4950a548021552a4fea2226858c4453571bf3f24ba017eac2908"}}}}"#
        )
    };
    let exact =
        document(r#"{"name":"source","type":"string"},{"name":"connectionId","type":"bytes32"}"#);
    let value = yw_json::parse(exact.as_bytes(), &yw_json::Limits::REQUEST).unwrap();
    let from = |requester| {
        validate_typed_data_v4_from(exact.as_bytes(), &value, 42_161, requester)
            .map(|typed| typed.schema)
    };
    assert_eq!(
        from(HlL1Requester::Origin("https://app.hyperliquid.xyz")),
        Ok(Some(KnownSchema::HyperliquidL1Agent))
    );
    // Any other origin, the testnet app for a mainnet (`a`) action, an unattested requester and
    // the plain validator keep T01 (spec/11 §7).
    for requester in [
        HlL1Requester::Origin("https://evil.example"),
        HlL1Requester::Origin("https://app.hyperliquid-testnet.xyz"),
        HlL1Requester::Nobody,
    ] {
        assert_eq!(
            from(requester),
            Err(crate::evm::eip712::TypedDataError::ChainIdMismatch)
        );
    }
    assert!(validate_typed_data_v4(exact.as_bytes(), &value, 42_161).is_err());
    let typed =
        validate_typed_data_v4_from(exact.as_bytes(), &value, 42_161, HlL1Requester::Deferred)
            .unwrap();
    assert_eq!(typed.schema, Some(KnownSchema::HyperliquidL1Agent));
    let other = document(
        r#"{"name":"source","type":"string"},{"name":"connectionId","type":"bytes32"},{"name":"x","type":"uint8"}"#,
    )
    .replace(r#""connectionId":"0x0f"#, r#""x":1,"connectionId":"0x0f"#);
    let value = yw_json::parse(other.as_bytes(), &yw_json::Limits::REQUEST).unwrap();
    assert_eq!(
        validate_typed_data_v4_from(
            other.as_bytes(),
            &value,
            42_161,
            HlL1Requester::Origin("https://app.hyperliquid.xyz")
        )
        .map(|typed| typed.schema),
        Err(crate::evm::eip712::TypedDataError::ChainIdMismatch)
    );
}

#[test]
fn encode_types_match_the_sdk() {
    assert_eq!(
        HcKind::UsdSend.encode_type(),
        "HyperliquidTransaction:UsdSend(string hyperliquidChain,string destination,string amount,uint64 time)"
    );
    assert_eq!(
        HcKind::SpotSend.encode_type(),
        "HyperliquidTransaction:SpotSend(string hyperliquidChain,string destination,string token,string amount,uint64 time)"
    );
    assert_eq!(
        HcKind::UsdClassTransfer.encode_type(),
        "HyperliquidTransaction:UsdClassTransfer(string hyperliquidChain,string amount,bool toPerp,uint64 nonce)"
    );
    assert_eq!(
        HcKind::SendAsset.encode_type(),
        "HyperliquidTransaction:SendAsset(string hyperliquidChain,string destination,string sourceDex,string destinationDex,string token,string amount,string fromSubAccount,uint64 nonce)"
    );
}

#[test]
fn exchange_body_shape() {
    let action = &every_kind(HcNetwork::Testnet)[0];
    let body = action.exchange_body(&sign(action));
    let value = yw_json::parse(&body, &yw_json::Limits::REQUEST).unwrap();
    let object = value.as_object().unwrap();
    assert_eq!(
        object
            .get("nonce")
            .and_then(yw_json::Value::as_number)
            .and_then(yw_json::Number::as_u64),
        Some(SDK_TIME)
    );
    let signature = object
        .get("signature")
        .and_then(yw_json::Value::as_object)
        .unwrap();
    assert_eq!(
        signature
            .get("r")
            .and_then(yw_json::Value::as_str)
            .unwrap()
            .len(),
        66
    );
    let text = String::from_utf8(body).unwrap();
    assert!(text.contains(r#""type":"usdSend","signatureChainId":"0x66eee","hyperliquidChain":"Testnet","destination":"0x5e9ee1089755c3435139848e47e6635505d5a13a","amount":"1.5","time":1687816341423"#), "{text}");
}

#[test]
fn amounts_and_system_addresses() {
    assert!(is_wire_amount("1", 6));
    assert!(is_wire_amount("0.000001", 6));
    for bad in [
        "",
        "0",
        "0.0",
        "1.",
        "1.50",
        "01",
        "1e3",
        "-1",
        "0.0000001",
        " 1",
    ] {
        assert!(!is_wire_amount(bad, 6), "{bad}");
    }
    assert_eq!(wire_amount(&U256::from_u64(1_500_000), 6), "1.5");
    assert_eq!(wire_amount(&U256::from_u64(5), 8), "0.00000005");
    assert_eq!(parse_amount("2.50", 6).unwrap().1, "2.5");
    assert!(parse_amount("0", 6).is_err());
    assert!(parse_amount("1.0000001", 6).is_err());
    assert_eq!(
        system_address(200).to_lower_hex(),
        "0x20000000000000000000000000000000000000c8"
    );
    assert_eq!(system_address_index(&system_address(1105)), Some(1105));
    assert_eq!(system_address_index(&HYPE_SYSTEM_ADDRESS), None);
}

/// The docs' response examples and a testnet-like `spotMeta` token list.
#[test]
fn info_and_exchange_shapes() {
    let meta = br#"{"tokens":[{"name":"USDC","szDecimals":8,"weiDecimals":8,"index":0,"tokenId":"0xeb62eee3685fc4c43992febcd9e75443","isCanonical":true,"evmContract":{"address":"0x0b80659a4076e9e93c7dbe0f10675a16a3e5c206","evm_extra_wei_decimals":-2},"fullName":null,"deployerTradingFeeShare":"0.0"},{"name":"HYPE","szDecimals":2,"weiDecimals":8,"index":1105,"tokenId":"0x7317beb7cceed72ef0b346074cc8e7ab","isCanonical":false,"evmContract":{"address":"0x0000000000000000000000000000000000000000","evm_extra_wei_decimals":10},"fullName":"Hyperliquid"}],"universe":[{"name":"PURR/USDC","tokens":[1,0],"index":0,"isCanonical":true}]}"#;
    let value = yw_json::parse(meta, &yw_json::Limits::RESPONSE).unwrap();
    let tokens = parse_spot_meta(&value).unwrap();
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0].evm_transfer_decimals(), Some(6));
    assert!(tokens[1].is_hype());
    assert_eq!(tokens[1].system_address(), HYPE_SYSTEM_ADDRESS);
    assert_eq!(tokens[1].wire(), "HYPE:0x7317beb7cceed72ef0b346074cc8e7ab");

    let spot = br#"{"balances":[{"coin":"USDC","token":0,"hold":"0.0","total":"14.625485","entryNtl":"0.0"}]}"#;
    let balances =
        parse_spot_state(&yw_json::parse(spot, &yw_json::Limits::RESPONSE).unwrap()).unwrap();
    assert_eq!(balances[0].total, "14.625485");

    let perp = br#"{"assetPositions":[],"crossMaintenanceMarginUsed":"0.0","crossMarginSummary":{"accountValue":"13104.514502","totalMarginUsed":"0.0","totalNtlPos":"0.0","totalRawUsd":"13104.514502"},"marginSummary":{"accountValue":"13109.482328","totalMarginUsed":"4.967826","totalNtlPos":"100.02765","totalRawUsd":"13009.454678"},"time":1708622398623,"withdrawable":"13104.514502"}"#;
    let state =
        parse_perp_state(&yw_json::parse(perp, &yw_json::Limits::RESPONSE).unwrap()).unwrap();
    assert_eq!(state.account_value, "13109.482328");
    assert_eq!(state.withdrawable, "13104.514502");

    let ok = br#"{"status":"ok","response":{"type":"default"}}"#;
    assert_eq!(
        parse_exchange_reply(&yw_json::parse(ok, &yw_json::Limits::RESPONSE).unwrap()),
        Ok(HcExchangeReply::Ok)
    );
    let err = br#"{"status":"err","response":"User or API Wallet 0x0000000000000000000000000000000000000001 does not exist."}"#;
    assert!(matches!(
        parse_exchange_reply(&yw_json::parse(err, &yw_json::Limits::RESPONSE).unwrap()),
        Ok(HcExchangeReply::Err(message)) if message.contains("does not exist")
    ));
}
