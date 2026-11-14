//! EIP-712 (spec/03 §8, EVM-V03/V11, spec/09 X-6–X-8). Ported from
//! `archive/spec-v2.4:crates/eip712/tests/vectors.rs:1-371` with the v3 changes of spec/03 §8.1:
//! missing chainId/verifyingContract are accepted with T03/T10 (archive 212-256 rejected them),
//! unreachable types are allowed, hex integers may carry leading zeros/uppercase, and mixed-case
//! addresses must pass EIP-55.

use yw_core::approval::{
    ApprovalDraft, ApprovalId, ApprovalKind, ApprovalOrigin, ChainFacts, CodeKind, FieldKey,
    RiskLevel, TokenMeta, build_typed_request,
};
use yw_core::bip32::path::AccountIndex;
use yw_core::evm::address::{Address, parse_address};
use yw_core::evm::chain::{ChainInfo, ethereum_mainnet, sepolia};
use yw_core::evm::eip712::{
    DecodedTypedData, KnownSchema, LimitKind, TypedDataError, eip712_digest, validate_typed_data_v4,
};
use yw_core::evm::risk::T08;
use yw_core::hex;
use yw_core::policy::BrowserOrigin;
use yw_core::vault::EvmKeySource;
use yw_json::{Limits, ParseError};

const ETHER_MAIL: &str = r#"{
  "types": {
    "EIP712Domain": [
      {"name": "name", "type": "string"},
      {"name": "version", "type": "string"},
      {"name": "chainId", "type": "uint256"},
      {"name": "verifyingContract", "type": "address"}
    ],
    "Person": [
      {"name": "name", "type": "string"},
      {"name": "wallet", "type": "address"}
    ],
    "Mail": [
      {"name": "from", "type": "Person"},
      {"name": "to", "type": "Person"},
      {"name": "contents", "type": "string"}
    ]
  },
  "primaryType": "Mail",
  "domain": {
    "name": "Ether Mail",
    "version": "1",
    "chainId": 1,
    "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
  },
  "message": {
    "from": {
      "name": "Cow",
      "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
    },
    "to": {
      "name": "Bob",
      "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
    },
    "contents": "Hello, Bob!"
  }
}"#;

const SEPOLIA: u64 = 11_155_111;
const NOW_MS: u64 = 1_791_381_216_000;
const NOW: u64 = 1_791_381_216;
const ACC1: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
const PERMIT2: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const SEAPORT16: &str = "0x0000000000000068F116a894984e2DB1123eB395";
const SEAPORT15: &str = "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC";
const SEAPORT11: &str = "0x00000000006c3852cbEf3e08E8dF289169EdE581";

fn validate(source: &str, chain_id: u64) -> Result<DecodedTypedData, TypedDataError> {
    let value = yw_json::parse(source.as_bytes(), &Limits::REQUEST)
        .map_err(|_| TypedDataError::InvalidEnvelope)?;
    validate_typed_data_v4(source.as_bytes(), &value, chain_id)
}

fn bound_document(message_fields: &str, message: &str) -> String {
    format!(
        r#"{{"types":{{"EIP712Domain":[{{"name":"chainId","type":"uint256"}},{{"name":"verifyingContract","type":"address"}}],"Message":[{message_fields}]}},"primaryType":"Message","domain":{{"chainId":1,"verifyingContract":"0x1111111111111111111111111111111111111111"}},"message":{message}}}"#
    )
}

#[test]
fn ether_mail_vector() {
    let typed = validate(ETHER_MAIL, 1).unwrap();
    assert_eq!(
        hex::encode(&typed.domain_separator()),
        "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
    );
    assert_eq!(
        hex::encode(&typed.message_hash()),
        "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
    );
    assert_eq!(
        hex::encode(&eip712_digest(&typed)),
        "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
    );
    assert_eq!(typed.schema, None);
    // X-6 / T01: the same document on Sepolia is rejected.
    assert_eq!(
        validate(ETHER_MAIL, SEPOLIA),
        Err(TypedDataError::ChainIdMismatch)
    );
}

#[test]
fn x8_duplicate_keys_cycles_and_number_forms() {
    let duplicate = br#"{"types":{"EIP712Domain":[],"Message":[],"Message":[]},"primaryType":"Message","domain":{},"message":{}}"#;
    assert!(matches!(
        yw_json::parse(duplicate, &Limits::REQUEST),
        Err(ParseError::DuplicateKey { .. })
    ));
    let cyclic = r#"{"types":{"EIP712Domain":[],"Node":[{"name":"next","type":"Node"}]},"primaryType":"Node","domain":{},"message":{"next":{}}}"#;
    assert_eq!(validate(cyclic, 1), Err(TypedDataError::CyclicType));
    for number in ["-0", "1.0", "1e0"] {
        let source = bound_document(
            r#"{"name":"value","type":"int256"}"#,
            &format!(r#"{{"value":{number}}}"#),
        );
        assert_eq!(
            validate(&source, 1),
            Err(TypedDataError::InvalidValue),
            "{number}"
        );
    }
}

#[test]
fn archive_rejections_kept() {
    let undefined = r#"{"types":{"EIP712Domain":[],"Message":[{"name":"person","type":"Person"}]},"primaryType":"Message","domain":{},"message":{"person":{}}}"#;
    assert_eq!(validate(undefined, 1), Err(TypedDataError::UndefinedType));
    let duplicate_field = r#"{"types":{"EIP712Domain":[],"Message":[{"name":"value","type":"uint256"},{"name":"value","type":"uint256"}]},"primaryType":"Message","domain":{},"message":{"value":"1"}}"#;
    assert_eq!(
        validate(duplicate_field, 1),
        Err(TypedDataError::DuplicateField)
    );
    let dimensions = bound_document(
        r#"{"name":"values","type":"uint256[][][][][][][][][]"}"#,
        r#"{"values":[]}"#,
    );
    assert_eq!(
        validate(&dimensions, 1),
        Err(TypedDataError::LimitExceeded(LimitKind::ArrayDimensions))
    );
    let huge = bound_document(
        r#"{"name":"value","type":"uint256"}"#,
        r#"{"value":"115792089237316195423570985008687907853269984665640564039457584007913129639936"}"#,
    );
    assert_eq!(validate(&huge, 1), Err(TypedDataError::InvalidValue));
    let ambiguous = bound_document(
        r#"{"name":"value","type":"uint256"}"#,
        r#"{"value":9007199254740992}"#,
    );
    assert_eq!(validate(&ambiguous, 1), Err(TypedDataError::InvalidValue));
    let decimal_leading_zero =
        bound_document(r#"{"name":"value","type":"uint256"}"#, r#"{"value":"01"}"#);
    assert_eq!(
        validate(&decimal_leading_zero, 1),
        Err(TypedDataError::InvalidValue)
    );
    for value in [r#""256""#, r#""0x100""#] {
        let source = bound_document(
            r#"{"name":"value","type":"uint8"}"#,
            &format!(r#"{{"value":{value}}}"#),
        );
        assert_eq!(
            validate(&source, 1),
            Err(TypedDataError::InvalidValue),
            "{value}"
        );
    }
    for value in [r#""128""#, r#""-129""#, r#""-0""#] {
        let source = bound_document(
            r#"{"name":"value","type":"int8"}"#,
            &format!(r#"{{"value":{value}}}"#),
        );
        assert_eq!(
            validate(&source, 1),
            Err(TypedDataError::InvalidValue),
            "{value}"
        );
    }
    let primary_domain =
        r#"{"types":{"EIP712Domain":[]},"primaryType":"EIP712Domain","domain":{},"message":{}}"#;
    assert_eq!(
        validate(primary_domain, 1),
        Err(TypedDataError::InvalidEnvelope)
    );
    let extra = bound_document(r#"{"name":"a","type":"uint256"}"#, r#"{"a":"1","b":"2"}"#);
    assert_eq!(validate(&extra, 1), Err(TypedDataError::ExtraValue));
    let missing = bound_document(r#"{"name":"a","type":"uint256"}"#, r"{}");
    assert_eq!(validate(&missing, 1), Err(TypedDataError::MissingValue));
    let chain_type = r#"{"types":{"EIP712Domain":[{"name":"chainId","type":"uint64"}],"Message":[]},"primaryType":"Message","domain":{"chainId":1},"message":{}}"#;
    assert_eq!(
        validate(chain_type, 1),
        Err(TypedDataError::InvalidDomainBindingType)
    );
    let source = " ".repeat(131_073);
    let value = yw_json::parse(b"{}", &Limits::REQUEST).unwrap();
    assert_eq!(
        validate_typed_data_v4(source.as_bytes(), &value, 1),
        Err(TypedDataError::LimitExceeded(LimitKind::SourceBytes))
    );
}

#[test]
fn v3_relaxations() {
    // #2: missing bindings are accepted (T03/T10 come from the rules).
    let unbound = r#"{"types":{"EIP712Domain":[],"Message":[{"name":"contents","type":"string"}]},"primaryType":"Message","domain":{},"message":{"contents":"hello"}}"#;
    let typed = validate(unbound, 1).unwrap();
    assert_eq!(typed.domain.chain_id, None);
    assert_eq!(typed.domain.verifying_contract, None);
    let zero = r#"{"types":{"EIP712Domain":[{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Message":[]},"primaryType":"Message","domain":{"chainId":1,"verifyingContract":"0x0000000000000000000000000000000000000000"},"message":{}}"#;
    assert_eq!(validate(zero, 1).unwrap().domain.verifying_contract, None);
    // #4: unreachable types are allowed.
    let unreachable = r#"{"types":{"EIP712Domain":[],"Message":[],"Unused":[{"name":"x","type":"uint8"}]},"primaryType":"Message","domain":{},"message":{}}"#;
    assert!(validate(unreachable, 1).is_ok());
    // #5: hex integers with leading zeros and uppercase digits.
    let leading = bound_document(
        r#"{"name":"value","type":"uint8"}"#,
        r#"{"value":"0x00FF"}"#,
    );
    let canonical = bound_document(r#"{"name":"value","type":"uint8"}"#, r#"{"value":"0xff"}"#);
    assert_eq!(
        validate(&leading, 1).unwrap().preimage,
        validate(&canonical, 1).unwrap().preimage
    );
    // #6: mixed-case addresses follow EIP-55.
    let bad_checksum = bound_document(
        r#"{"name":"owner","type":"address"}"#,
        r#"{"owner":"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"}"#,
    );
    assert_eq!(
        validate(&bad_checksum, 1),
        Err(TypedDataError::InvalidValue)
    );
}

#[test]
fn hashing_properties_from_archive() {
    let fields = r#"{"name":"a","type":"uint256"},{"name":"b","type":"string"}"#;
    let first = validate(&bound_document(fields, r#"{"a":"7","b":"hello"}"#), 1).unwrap();
    let second = validate(&bound_document(fields, r#"{"b":"hello","a":"7"}"#), 1).unwrap();
    assert_eq!(first.preimage, second.preimage);
    let bit_a = validate(
        &bound_document(r#"{"name":"data","type":"bytes1"}"#, r#"{"data":"0x00"}"#),
        1,
    )
    .unwrap();
    let bit_b = validate(
        &bound_document(r#"{"name":"data","type":"bytes1"}"#, r#"{"data":"0x01"}"#),
        1,
    )
    .unwrap();
    assert_ne!(eip712_digest(&bit_a), eip712_digest(&bit_b));
    let rich = r#"{"types":{"EIP712Domain":[{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Point":[{"name":"x","type":"int16"},{"name":"y","type":"int16"}],"Message":[{"name":"owner","type":"address"},{"name":"enabled","type":"bool"},{"name":"label","type":"string"},{"name":"payload","type":"bytes"},{"name":"tag","type":"bytes4"},{"name":"small","type":"uint8"},{"name":"negative","type":"int8"},{"name":"points","type":"Point[2]"},{"name":"matrix","type":"uint16[][2]"}]},"primaryType":"Message","domain":{"chainId":"0x1","verifyingContract":"0x1111111111111111111111111111111111111111"},"message":{"owner":"0x2222222222222222222222222222222222222222","enabled":true,"label":"bounded","payload":"0x010203","tag":"0xaabbccdd","small":"255","negative":"-128","points":[{"x":"-1","y":"2"},{"x":"3","y":"-4"}],"matrix":[[1,2,3],[4]]}}"#;
    let typed = validate(rich, 1).unwrap();
    assert_ne!(typed.message_hash(), [0; 32]);
    // Digest is deterministic (fuzz invariant).
    assert_eq!(
        eip712_digest(&typed),
        eip712_digest(&validate(rich, 1).unwrap())
    );
}

// ------------------------------------------------------------ schemas (spec/03 §8.2)

fn permit2_doc(primary: &str, extra_types: &str, message: &str, contract: &str) -> String {
    format!(
        r#"{{"types":{{"EIP712Domain":[{{"name":"name","type":"string"}},{{"name":"chainId","type":"uint256"}},{{"name":"verifyingContract","type":"address"}}]{extra_types}}},"primaryType":"{primary}","domain":{{"name":"Permit2","chainId":{SEPOLIA},"verifyingContract":"{contract}"}},"message":{message}}}"#
    )
}

const PD_TYPES: &str = r#","PermitDetails":[{"name":"token","type":"address"},{"name":"amount","type":"uint160"},{"name":"expiration","type":"uint48"},{"name":"nonce","type":"uint48"}]"#;
const TP_TYPES: &str =
    r#","TokenPermissions":[{"name":"token","type":"address"},{"name":"amount","type":"uint256"}]"#;

fn permit_single(contract: &str, expiration: u64, sig_deadline: u64, spender: &str) -> String {
    permit2_doc(
        "PermitSingle",
        &format!(
            r#"{PD_TYPES},"PermitSingle":[{{"name":"details","type":"PermitDetails"}},{{"name":"spender","type":"address"}},{{"name":"sigDeadline","type":"uint256"}}]"#
        ),
        &format!(
            r#"{{"details":{{"token":"0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238","amount":"1461501637330902918203684832716283019655932542975","expiration":"{expiration}","nonce":"0"}},"spender":"{spender}","sigDeadline":"{sig_deadline}"}}"#
        ),
        contract,
    )
}

/// `PermitBatch` with `count` copies of one detail.
fn permit_batch_of(count: usize) -> String {
    let detail = format!(
        r#"{{"token":"0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238","amount":"5","expiration":"{}","nonce":"1"}}"#,
        NOW + 86_400
    );
    permit2_doc(
        "PermitBatch",
        &format!(
            r#"{PD_TYPES},"PermitBatch":[{{"name":"details","type":"PermitDetails[]"}},{{"name":"spender","type":"address"}},{{"name":"sigDeadline","type":"uint256"}}]"#
        ),
        &format!(
            r#"{{"details":[{}],"spender":"0x3A9D48AB9751398BbFa63ad67599Bb04e4BdF98b","sigDeadline":"{}"}}"#,
            vec![detail; count].join(","),
            NOW + 600
        ),
        PERMIT2,
    )
}

fn permit_batch() -> String {
    permit2_doc(
        "PermitBatch",
        &format!(
            r#"{PD_TYPES},"PermitBatch":[{{"name":"details","type":"PermitDetails[]"}},{{"name":"spender","type":"address"}},{{"name":"sigDeadline","type":"uint256"}}]"#
        ),
        &format!(
            r#"{{"details":[{{"token":"0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238","amount":"5","expiration":"{}","nonce":"1"}}],"spender":"0x3A9D48AB9751398BbFa63ad67599Bb04e4BdF98b","sigDeadline":"{}"}}"#,
            NOW + 86_400,
            NOW + 600
        ),
        PERMIT2,
    )
}

fn permit_transfer(batch: bool, witness: bool) -> String {
    let permitted = if batch {
        "TokenPermissions[]"
    } else {
        "TokenPermissions"
    };
    let (primary, witness_field, witness_type, witness_value) = match (batch, witness) {
        (false, false) => ("PermitTransferFrom", "", "", ""),
        (true, false) => ("PermitBatchTransferFrom", "", "", ""),
        (false, true) => (
            "PermitWitnessTransferFrom",
            r#",{"name":"witness","type":"ExampleWitness"}"#,
            r#","ExampleWitness":[{"name":"user","type":"address"},{"name":"note","type":"string"}]"#,
            r#","witness":{"user":"0x2222222222222222222222222222222222222222","note":"swap"}"#,
        ),
        (true, true) => (
            "PermitBatchWitnessTransferFrom",
            r#",{"name":"witness","type":"ExampleWitness"}"#,
            r#","ExampleWitness":[{"name":"user","type":"address"},{"name":"note","type":"string"}]"#,
            r#","witness":{"user":"0x2222222222222222222222222222222222222222","note":"swap"}"#,
        ),
    };
    let item = r#"{"token":"0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238","amount":"5"}"#;
    let permitted_value = if batch {
        format!("[{item}]")
    } else {
        item.to_owned()
    };
    permit2_doc(
        primary,
        &format!(
            r#"{TP_TYPES}{witness_type},"{primary}":[{{"name":"permitted","type":"{permitted}"}},{{"name":"spender","type":"address"}},{{"name":"nonce","type":"uint256"}},{{"name":"deadline","type":"uint256"}}{witness_field}]"#
        ),
        &format!(
            r#"{{"permitted":{permitted_value},"spender":"0x3A9D48AB9751398BbFa63ad67599Bb04e4BdF98b","nonce":"1","deadline":"{}"{witness_value}}}"#,
            NOW + 600
        ),
        PERMIT2,
    )
}

fn erc2612(owner: &str, value: &str, deadline: u64) -> String {
    format!(
        r#"{{"types":{{"EIP712Domain":[{{"name":"name","type":"string"}},{{"name":"version","type":"string"}},{{"name":"chainId","type":"uint256"}},{{"name":"verifyingContract","type":"address"}}],"Permit":[{{"name":"owner","type":"address"}},{{"name":"spender","type":"address"}},{{"name":"value","type":"uint256"}},{{"name":"nonce","type":"uint256"}},{{"name":"deadline","type":"uint256"}}]}},"primaryType":"Permit","domain":{{"name":"USDC","version":"2","chainId":{SEPOLIA},"verifyingContract":"0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"}},"message":{{"owner":"{owner}","spender":"0x2222222222222222222222222222222222222222","value":"{value}","nonce":"0","deadline":"{deadline}"}}}}"#
    )
}

/// Mainnet registry DAI.
const MAINNET_DAI: &str = "0x6B175474E89094C44Da98b954EedeAC495271d0F";

fn dai_on(chain_id: u64, contract: &str, allowed: bool, expiry: u64) -> String {
    format!(
        r#"{{"types":{{"EIP712Domain":[{{"name":"name","type":"string"}},{{"name":"version","type":"string"}},{{"name":"chainId","type":"uint256"}},{{"name":"verifyingContract","type":"address"}}],"Permit":[{{"name":"holder","type":"address"}},{{"name":"spender","type":"address"}},{{"name":"nonce","type":"uint256"}},{{"name":"expiry","type":"uint256"}},{{"name":"allowed","type":"bool"}}]}},"primaryType":"Permit","domain":{{"name":"Dai Stablecoin","version":"1","chainId":{chain_id},"verifyingContract":"{contract}"}},"message":{{"holder":"{ACC1}","spender":"0x2222222222222222222222222222222222222222","nonce":"0","expiry":"{expiry}","allowed":{allowed}}}}}"#
    )
}

/// DAI permit at the mainnet registry DAI (the only place the layout is recognized).
fn dai(allowed: bool, expiry: u64) -> String {
    dai_on(1, MAINNET_DAI, allowed, expiry)
}

const SEAPORT_TYPES: &str = r#""OrderComponents":[{"name":"offerer","type":"address"},{"name":"zone","type":"address"},{"name":"offer","type":"OfferItem[]"},{"name":"consideration","type":"ConsiderationItem[]"},{"name":"orderType","type":"uint8"},{"name":"startTime","type":"uint256"},{"name":"endTime","type":"uint256"},{"name":"zoneHash","type":"bytes32"},{"name":"salt","type":"uint256"},{"name":"conduitKey","type":"bytes32"},{"name":"counter","type":"uint256"}],"OfferItem":[{"name":"itemType","type":"uint8"},{"name":"token","type":"address"},{"name":"identifierOrCriteria","type":"uint256"},{"name":"startAmount","type":"uint256"},{"name":"endAmount","type":"uint256"}],"ConsiderationItem":[{"name":"itemType","type":"uint8"},{"name":"token","type":"address"},{"name":"identifierOrCriteria","type":"uint256"},{"name":"startAmount","type":"uint256"},{"name":"endAmount","type":"uint256"},{"name":"recipient","type":"address"}]"#;

fn seaport(
    version: &str,
    contract: &str,
    recipient: &str,
    order_type: u8,
    end: u64,
    offer_kind: u8,
    primary: &str,
) -> String {
    format!(
        r#"{{"types":{{"EIP712Domain":[{{"name":"name","type":"string"}},{{"name":"version","type":"string"}},{{"name":"chainId","type":"uint256"}},{{"name":"verifyingContract","type":"address"}}],{SEAPORT_TYPES}}},"primaryType":"{primary}","domain":{{"name":"Seaport","version":"{version}","chainId":{SEPOLIA},"verifyingContract":"{contract}"}},"message":{{"offerer":"{ACC1}","zone":"0x0000000000000000000000000000000000000000","offer":[{{"itemType":"{offer_kind}","token":"0x4444444444444444444444444444444444444444","identifierOrCriteria":"0","startAmount":"1","endAmount":"1"}}],"consideration":[{{"itemType":"0","token":"0x0000000000000000000000000000000000000000","identifierOrCriteria":"0","startAmount":"1000000000000000000","endAmount":"1000000000000000000","recipient":"{recipient}"}}],"orderType":"{order_type}","startTime":"{NOW}","endTime":"{end}","zoneHash":"0x0000000000000000000000000000000000000000000000000000000000000000","salt":"7","conduitKey":"0x0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000","counter":"0"}}}}"#
    )
}

#[test]
#[expect(clippy::too_many_lines, reason = "table-driven test")]
fn schema_recognition_table() {
    let cases: Vec<(String, Option<KnownSchema>)> = vec![
        (
            erc2612(ACC1, "5", NOW + 600),
            Some(KnownSchema::Eip2612Permit),
        ),
        // The DAI layout away from a registry DAI is unrecognized (T04), so an unknown
        // contract cannot borrow DAI's "허용 해제" (T15 info) reading.
        (
            dai_on(
                SEPOLIA,
                "0x3333333333333333333333333333333333333333",
                true,
                NOW + 600,
            ),
            None,
        ),
        (
            permit_single(PERMIT2, NOW + 86_400, NOW + 600, ACC1),
            Some(KnownSchema::Permit2Single),
        ),
        (permit_batch(), Some(KnownSchema::Permit2Batch)),
        (
            permit_transfer(false, false),
            Some(KnownSchema::Permit2Transfer),
        ),
        (
            permit_transfer(true, false),
            Some(KnownSchema::Permit2BatchTransfer),
        ),
        (
            permit_transfer(false, true),
            Some(KnownSchema::Permit2WitnessTransfer {
                witness_type: "ExampleWitness".to_owned(),
            }),
        ),
        (
            permit_transfer(true, true),
            Some(KnownSchema::Permit2BatchWitnessTransfer {
                witness_type: "ExampleWitness".to_owned(),
            }),
        ),
        (
            seaport(
                "1.6",
                SEAPORT16,
                ACC1,
                0,
                NOW + 86_400,
                2,
                "OrderComponents",
            ),
            Some(KnownSchema::SeaportOrder),
        ),
        (
            seaport(
                "1.5",
                SEAPORT15,
                ACC1,
                0,
                NOW + 86_400,
                2,
                "OrderComponents",
            ),
            Some(KnownSchema::SeaportOrder),
        ),
        // Seaport 1.1 is outside the registry roles: unrecognized (T04).
        (
            seaport(
                "1.1",
                SEAPORT11,
                ACC1,
                0,
                NOW + 86_400,
                2,
                "OrderComponents",
            ),
            None,
        ),
        // A Permit2 schema at another contract: unrecognized (T04).
        (
            permit_single(
                "0x1111111111111111111111111111111111111111",
                NOW + 86_400,
                NOW + 600,
                ACC1,
            ),
            None,
        ),
    ];
    for (source, expected) in cases {
        let typed = validate(&source, SEPOLIA).unwrap();
        assert_eq!(typed.schema, expected, "{source}");
    }
    // DAI: recognized only at the chain's registry DAI.
    assert_eq!(
        validate(&dai(true, NOW + 600), 1).unwrap().schema,
        Some(KnownSchema::DaiPermit)
    );
    assert_eq!(
        validate(
            &dai_on(
                1,
                "0x3333333333333333333333333333333333333333",
                false,
                NOW + 600
            ),
            1
        )
        .unwrap()
        .schema,
        None
    );
}

#[test]
fn domain_allows_only_the_standard_fields() {
    let with_domain = |fields: &str, domain: &str| {
        format!(
            r#"{{"types":{{"EIP712Domain":[{fields}],"Inner":[{{"name":"x","type":"uint256"}}],"Message":[{{"name":"a","type":"uint256"}}]}},"primaryType":"Message","domain":{domain},"message":{{"a":"1"}}}}"#
        )
    };
    let all = with_domain(
        r#"{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"},{"name":"salt","type":"bytes32"}"#,
        &format!(
            r#"{{"name":"n","version":"1","chainId":1,"verifyingContract":"0x1111111111111111111111111111111111111111","salt":"0x{}"}}"#,
            "ab".repeat(32)
        ),
    );
    let typed = validate(&all, 1).unwrap();
    assert_eq!(typed.domain.salt, Some([0xab; 32]));
    for (fields, domain) in [
        // An unknown scalar field.
        (
            r#"{"name":"name","type":"string"},{"name":"chain","type":"string"}"#,
            r#"{"name":"n","chain":"1"}"#,
        ),
        // A nested struct and an array would be signed without being shown.
        (
            r#"{"name":"name","type":"string"},{"name":"extra","type":"Inner"}"#,
            r#"{"name":"n","extra":{"x":"1"}}"#,
        ),
        (
            r#"{"name":"name","type":"string"},{"name":"list","type":"uint256[]"}"#,
            r#"{"name":"n","list":["1"]}"#,
        ),
        // Standard names with non-standard types.
        (
            r#"{"name":"name","type":"bytes32"}"#,
            &*format!(r#"{{"name":"0x{}"}}"#, "00".repeat(32)),
        ),
        (
            r#"{"name":"version","type":"uint256"}"#,
            r#"{"version":"1"}"#,
        ),
        (r#"{"name":"salt","type":"bytes"}"#, r#"{"salt":"0x01"}"#),
    ] {
        assert_eq!(
            validate(&with_domain(fields, domain), 1),
            Err(TypedDataError::NonStandardDomain),
            "{fields}"
        );
    }
    // A non-standard chainId/verifyingContract type keeps its own error.
    assert_eq!(
        validate(
            &with_domain(
                r#"{"name":"verifyingContract","type":"bytes20"}"#,
                &format!(r#"{{"verifyingContract":"0x{}"}}"#, "11".repeat(20))
            ),
            1
        ),
        Err(TypedDataError::InvalidDomainBindingType)
    );
}

#[test]
fn identifier_and_type_string_limits() {
    let name = |length: usize| "a".repeat(length);
    let ok = bound_document(
        &format!(r#"{{"name":"{}","type":"uint256"}}"#, name(256)),
        &format!(r#"{{"{}":"1"}}"#, name(256)),
    );
    assert!(validate(&ok, 1).is_ok());
    let long_field = bound_document(
        &format!(r#"{{"name":"{}","type":"uint256"}}"#, name(257)),
        &format!(r#"{{"{}":"1"}}"#, name(257)),
    );
    assert_eq!(
        validate(&long_field, 1),
        Err(TypedDataError::InvalidTypeDefinition)
    );
    let long_type = format!(
        r#"{{"types":{{"EIP712Domain":[],"{0}":[],"Message":[{{"name":"x","type":"{0}"}}]}},"primaryType":"Message","domain":{{}},"message":{{"x":{{}}}}}}"#,
        "T".repeat(257)
    );
    assert_eq!(
        validate(&long_type, 1),
        Err(TypedDataError::InvalidTypeDefinition)
    );
    let long_primary = format!(
        r#"{{"types":{{"EIP712Domain":[],"{0}":[]}},"primaryType":"{0}","domain":{{}},"message":{{}}}}"#,
        "P".repeat(257)
    );
    assert_eq!(
        validate(&long_primary, 1),
        Err(TypedDataError::InvalidEnvelope)
    );
    // ≤ 1,024 fields over all types.
    let wide: Vec<String> = (0..5)
        .map(|index| {
            let fields = (0..205)
                .map(|field| format!(r#"{{"name":"f{field}","type":"uint8"}}"#))
                .collect::<Vec<_>>()
                .join(",");
            format!(r#""U{index}":[{fields}]"#)
        })
        .collect();
    let too_many = format!(
        r#"{{"types":{{"EIP712Domain":[],{},"Message":[]}},"primaryType":"Message","domain":{{}},"message":{{}}}}"#,
        wide.join(",")
    );
    let value = yw_json::parse(too_many.as_bytes(), &Limits::RESPONSE).unwrap();
    assert_eq!(
        validate_typed_data_v4(too_many.as_bytes(), &value, 1),
        Err(TypedDataError::LimitExceeded(LimitKind::Fields))
    );
}

#[test]
fn x7_schema_mismatches_are_rejected() {
    // Permit2 address with a non-Permit2 schema (T02).
    let other = r#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Message":[{"name":"x","type":"uint256"}]},"primaryType":"Message","domain":{"name":"Permit2","chainId":11155111,"verifyingContract":"0x000000000022D473030F116dDEE9F6B43aC78BA3"},"message":{"x":"1"}}"#;
    assert_eq!(
        validate(other, SEPOLIA),
        Err(TypedDataError::SchemaMismatch)
    );
    // Seaport BulkOrder (T02).
    let single = seaport(
        "1.6",
        SEAPORT16,
        ACC1,
        0,
        NOW + 86_400,
        2,
        "OrderComponents",
    );
    let (head, order) = single.split_once("\"message\":").unwrap();
    let order = order.strip_suffix('}').unwrap();
    let bulk = format!("{head}\"message\":{{\"tree\":[{order},{order}]}}}}")
        .replace("\"primaryType\":\"OrderComponents\"", "\"primaryType\":\"BulkOrder\"")
        .replace("\"OrderComponents\":[", "\"BulkOrder\":[{\"name\":\"tree\",\"type\":\"OrderComponents[2]\"}],\"OrderComponents\":[");
    // The document itself is well-formed EIP-712 (accepted on a non-Seaport contract).
    let elsewhere = bulk.replace(SEAPORT16, "0x1111111111111111111111111111111111111111");
    assert_eq!(validate(&elsewhere, SEPOLIA).unwrap().schema, None);
    assert_eq!(
        validate(&bulk, SEPOLIA),
        Err(TypedDataError::SchemaMismatch)
    );
    // Seaport version/contract mismatch (T02).
    let wrong_version = seaport(
        "1.5",
        SEAPORT16,
        ACC1,
        0,
        NOW + 86_400,
        2,
        "OrderComponents",
    );
    assert_eq!(
        validate(&wrong_version, SEPOLIA),
        Err(TypedDataError::SchemaMismatch)
    );
}

// ------------------------------------------------------------ rules (spec/03 §10.3)

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

fn draft_on(chain: &ChainInfo, source: &str, facts: &ChainFacts) -> Fallible<ApprovalDraft> {
    let typed = validate(source, chain.chain_id)?;
    Ok(build_typed_request(
        yw_core::lang::Lang::Ko,
        ApprovalId([1; 16]),
        ApprovalOrigin::Site(BrowserOrigin::parse("https://app.example").ok_or("origin")?),
        EvmKeySource::Derived(AccountIndex::ZERO),
        parse_address(ACC1)?,
        ApprovalKind::EvmTypedData,
        chain,
        &typed,
        facts,
        NOW_MS,
    )?)
}

fn draft(source: &str, facts: &ChainFacts) -> Fallible<ApprovalDraft> {
    draft_on(&sepolia(), source, facts)
}

fn labels(draft: &ApprovalDraft) -> Vec<String> {
    draft
        .display
        .warnings
        .iter()
        .map(|w| w.rule.label())
        .collect()
}

fn eoa(address: &str) -> Fallible<ChainFacts> {
    Ok(ChainFacts {
        code: vec![(parse_address(address)?, CodeKind::Eoa)],
        ..ChainFacts::default()
    })
}

#[test]
#[expect(clippy::too_many_lines, reason = "table-driven test")]
fn typed_rules_t03_to_t17() {
    let none = ChainFacts::default();
    // T03 + T10 + T04 for an unbound, unrecognized message.
    let unbound = r#"{"types":{"EIP712Domain":[],"Message":[{"name":"contents","type":"string"}]},"primaryType":"Message","domain":{},"message":{"contents":"hello"}}"#;
    let d = draft(unbound, &none).unwrap();
    assert_eq!(labels(&d), ["T03", "T04", "T10"]);
    assert_eq!(d.display.risk, RiskLevel::High);
    // T05 (+ T12 for an already expired deadline), T07, T09.
    let d = draft(
        &erc2612("0x2222222222222222222222222222222222222222", "5", NOW - 1),
        &eoa("0x2222222222222222222222222222222222222222").unwrap(),
    )
    .unwrap();
    assert_eq!(labels(&d), ["T05", "T07", "T09", "T12"]);
    // Unlimited value shows 무제한.
    let d = draft(
        &erc2612(
            ACC1,
            "115792089237316195423570985008687907853269984665640564039457584007913129639935",
            NOW + 600,
        ),
        &none,
    )
    .unwrap();
    assert!(
        d.display
            .fields
            .iter()
            .any(|f| f.key == FieldKey::TD_FIELD && f.sub_label == "금액" && f.value == "무제한")
    );
    // DAI allowed=true → T05; expiry 0 = no expiry → T12; allowed=false → T15 (info).
    let mainnet = ethereum_mainnet();
    assert_eq!(
        labels(&draft_on(&mainnet, &dai(true, 0), &none).unwrap()),
        ["T05", "T12"]
    );
    let revoke = draft_on(&mainnet, &dai(false, NOW + 600), &none).unwrap();
    assert_eq!(labels(&revoke), ["T15"]);
    assert_eq!(revoke.display.risk, RiskLevel::Info);
    // Adversarial: the DAI layout at an unknown contract is not a harmless "revocation".
    let fake = draft(
        &dai_on(
            SEPOLIA,
            "0x3333333333333333333333333333333333333333",
            false,
            NOW + 600,
        ),
        &none,
    )
    .unwrap();
    assert_eq!(labels(&fake), ["T04"]);
    assert_eq!(fake.display.risk, RiskLevel::High);
    // Permit2 single: max expiration → T12, sigDeadline > 1 day → T13, spender EOA → T09.
    let spender = "0x2222222222222222222222222222222222222222";
    let d = draft(
        &permit_single(PERMIT2, (1 << 48) - 1, NOW + 2 * 86_400, spender),
        &eoa(spender).unwrap(),
    )
    .unwrap();
    assert_eq!(labels(&d), ["T05", "T09", "T12", "T13"]);
    assert!(
        d.display
            .fields
            .iter()
            .any(|f| f.sub_label == "허용 만료" && f.value == "만료 없음")
    );
    assert!(
        d.display
            .fields
            .iter()
            .any(|f| f.sub_label == "금액" && f.value == "무제한")
    );
    // Witness: T06 and the witness subtree is listed.
    let d = draft(&permit_transfer(false, true), &none).unwrap();
    assert_eq!(labels(&d), ["T06"]);
    assert!(
        d.display.fields.iter().any(|f| f.key == FieldKey::TD_TREE
            && f.sub_label == "witness.note"
            && f.value == "swap")
    );
    // Seaport: the user is the offerer of a non-empty offer → T19 (high) on every listing;
    // nothing received → T08; CONTRACT order → T14; end > 180 days → T13; criteria item with
    // identifier 0 → T14.
    let other = "0x2222222222222222222222222222222222222222";
    assert_eq!(
        labels(
            &draft(
                &seaport(
                    "1.6",
                    SEAPORT16,
                    other,
                    0,
                    NOW + 86_400,
                    2,
                    "OrderComponents"
                ),
                &none
            )
            .unwrap()
        ),
        ["T08", "T19"]
    );
    assert_eq!(
        labels(
            &draft(
                &seaport(
                    "1.6",
                    SEAPORT16,
                    ACC1,
                    4,
                    NOW + 86_400,
                    2,
                    "OrderComponents"
                ),
                &none
            )
            .unwrap()
        ),
        ["T19", "T14"]
    );
    assert_eq!(
        labels(
            &draft(
                &seaport(
                    "1.6",
                    SEAPORT16,
                    ACC1,
                    0,
                    NOW + 200 * 86_400,
                    2,
                    "OrderComponents"
                ),
                &none
            )
            .unwrap()
        ),
        ["T19", "T13"]
    );
    assert_eq!(
        labels(
            &draft(
                &seaport(
                    "1.6",
                    SEAPORT16,
                    ACC1,
                    0,
                    NOW + 86_400,
                    4,
                    "OrderComponents"
                ),
                &none
            )
            .unwrap()
        ),
        ["T19", "T14"]
    );
    let seaport_ok = draft(
        &seaport(
            "1.6",
            SEAPORT16,
            ACC1,
            0,
            NOW + 86_400,
            2,
            "OrderComponents",
        ),
        &none,
    )
    .unwrap();
    assert!(
        seaport_ok
            .display
            .fields
            .iter()
            .any(|f| f.sub_label == "내가 받는 것")
    );
    assert!(
        seaport_ok
            .display
            .fields
            .iter()
            .any(|f| f.sub_label == "conduitKey" && f.value.ends_with("[OpenSea Conduit]"))
    );
    // T11: verifying contract is an EOA.
    let d = draft(
        ETHER_MAIL
            .replace("\"chainId\": 1", "\"chainId\": 11155111")
            .as_str(),
        &eoa("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC").unwrap(),
    )
    .unwrap();
    assert_eq!(labels(&d), ["T04", "T11"]);
}

/// Seaport consideration of the user replaced by `item_type`/`token` (ERC-20/NFT).
fn seaport_receiving(item_type: u8, token: &str) -> String {
    seaport(
        "1.6",
        SEAPORT16,
        ACC1,
        0,
        NOW + 86_400,
        2,
        "OrderComponents",
    )
    .replace(
        r#""itemType":"0","token":"0x0000000000000000000000000000000000000000""#,
        &format!(r#""itemType":"{item_type}","token":"{token}""#),
    )
}

fn token_facts(token: &str, symbol: &str) -> Fallible<ChainFacts> {
    Ok(ChainFacts {
        tokens: vec![(
            parse_address(token)?,
            TokenMeta {
                symbol: Some(symbol.to_owned()),
                decimals: Some(6),
                registered: false,
            },
        )],
        ..ChainFacts::default()
    })
}

const SEPOLIA_USDC: &str = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
const FAKE: &str = "0x5555555555555555555555555555555555555555";

#[test]
fn c6_seaport_fake_consideration_and_t20() {
    let none = ChainFacts::default();
    // Registered ERC-20 consideration counts as received.
    assert_eq!(
        labels(&draft(&seaport_receiving(1, SEPOLIA_USDC), &none).unwrap()),
        ["T19"]
    );
    // An unregistered ERC-20 or an NFT paid to the user is not "received" (T08 + cause).
    for (item_type, token) in [(1, FAKE), (2, FAKE), (3, FAKE)] {
        let d = draft(&seaport_receiving(item_type, token), &none).unwrap();
        assert_eq!(labels(&d), ["T08", "T19"], "{item_type}");
        let t08 = d.display.warnings.iter().find(|w| w.rule == T08).unwrap();
        assert!(
            t08.text
                .ends_with("받는 것이 등록되지 않은 토큰·NFT뿐입니다")
        );
        assert!(d.display.ack_required);
    }
    // T20: an unregistered consideration token claiming a registry symbol.
    let d = draft(
        &seaport_receiving(1, FAKE),
        &token_facts(FAKE, "usdc").unwrap(),
    )
    .unwrap();
    assert_eq!(labels(&d), ["T08", "T19", "T20"]);
    // T20 for an EIP-2612 permit whose (unregistered) token claims the native symbol.
    let fake_permit = erc2612(ACC1, "5", NOW + 600).replace(SEPOLIA_USDC, FAKE);
    let d = draft(&fake_permit, &token_facts(FAKE, "SepoliaETH").unwrap()).unwrap();
    assert_eq!(labels(&d), ["T05", "T20"]);
    // T20 for a Permit2 detail token.
    let fake_detail =
        permit_single(PERMIT2, NOW + 86_400, NOW + 600, ACC1).replace(SEPOLIA_USDC, FAKE);
    let d = draft(&fake_detail, &token_facts(FAKE, "WETH").unwrap()).unwrap();
    assert!(labels(&d).contains(&"T20".to_owned()), "{:?}", labels(&d));
    // The registry token itself never triggers T20.
    let d = draft(
        &erc2612(ACC1, "5", NOW + 600),
        &token_facts(SEPOLIA_USDC, "USDC").unwrap(),
    )
    .unwrap();
    assert_eq!(labels(&d), ["T05"]);
}

#[test]
fn t18_unknown_spender_classification_is_high() {
    let spender = "0x2222222222222222222222222222222222222222";
    let unknown = ChainFacts {
        code: vec![(parse_address(spender).unwrap(), CodeKind::Unknown)],
        ..ChainFacts::default()
    };
    let d = draft(&erc2612(ACC1, "5", NOW + 600), &unknown).unwrap();
    assert_eq!(labels(&d), ["T05", "T18"]);
    let d = draft(
        &permit_single(PERMIT2, NOW + 86_400, NOW + 600, spender),
        &unknown,
    )
    .unwrap();
    assert!(labels(&d).contains(&"T18".to_owned()));
    assert!(
        d.display
            .fields
            .iter()
            .any(|f| f.sub_label == "사용자" && f.value.ends_with("[계정 종류 확인 불가]"))
    );
}

#[test]
fn c13_line_breaks_in_typed_strings_are_escaped() {
    let text = r#"{"text":"hello\nspender = 0x2222222222222222222222222222222222222222"}"#;
    let source = bound_document(r#"{"name":"text","type":"string"}"#, text)
        .replace("\"chainId\":1", "\"chainId\":11155111");
    let d = draft(&source, &ChainFacts::default()).unwrap();
    let field = d
        .display
        .fields
        .iter()
        .find(|f| f.key == FieldKey::TD_TREE && f.sub_label == "text")
        .unwrap();
    assert_eq!(
        field.value,
        "hello[U+000A]spender = 0x2222222222222222222222222222222222222222"
    );
    assert!(
        d.display
            .fields
            .iter()
            .filter(|f| f.key == FieldKey::TD_TREE)
            .all(|f| !f.value.contains('\n'))
    );
    // Domain strings too.
    let domain_lf = ETHER_MAIL
        .replace("\"chainId\": 1", "\"chainId\": 11155111")
        .replace("\"Ether Mail\"", "\"Ether\\nverifyingContract: 0xC0FFEE\"");
    let d = draft(&domain_lf, &ChainFacts::default()).unwrap();
    let domain = d
        .display
        .fields
        .iter()
        .find(|f| f.key == FieldKey::TD_DOMAIN)
        .unwrap();
    assert!(
        domain
            .value
            .starts_with("name: Ether[U+000A]verifyingContract: 0xC0FFEE\n"),
        "{}",
        domain.value
    );
}

#[test]
fn t16_tree_limits_and_t17_hidden_characters() {
    let none = ChainFacts::default();
    let many = (0..513)
        .map(|i| format!("\"{i}\""))
        .collect::<Vec<_>>()
        .join(",");
    let big = bound_document(
        r#"{"name":"values","type":"uint256[]"}"#,
        &format!(r#"{{"values":[{many}]}}"#),
    )
    .replace("\"chainId\":1", "\"chainId\":11155111");
    let d = draft(&big, &none).unwrap();
    assert!(labels(&d).contains(&"T16".to_owned()));
    assert_eq!(d.display.risk, RiskLevel::Blocked);
    let long = bound_document(
        r#"{"name":"text","type":"string"}"#,
        &format!(r#"{{"text":"{}"}}"#, "a".repeat(1_025)),
    )
    .replace("\"chainId\":1", "\"chainId\":11155111");
    assert!(labels(&draft(&long, &none).unwrap()).contains(&"T16".to_owned()));
    let deep_types = (0..9)
        .map(|i| format!(r#""L{i}":[{{"name":"n","type":"L{}"}}]"#, i + 1))
        .collect::<Vec<_>>()
        .join(",");
    let deep_value = (0..9).fold(r#"{"x":"1"}"#.to_owned(), |inner, _| {
        format!(r#"{{"n":{inner}}}"#)
    });
    let deep = format!(
        r#"{{"types":{{"EIP712Domain":[{{"name":"chainId","type":"uint256"}}],{deep_types},"L9":[{{"name":"x","type":"uint8"}}]}},"primaryType":"L0","domain":{{"chainId":11155111}},"message":{deep_value}}}"#
    );
    assert!(labels(&draft(&deep, &none).unwrap()).contains(&"T16".to_owned()));
    // X-20: hidden characters in a typed-data string are escaped and flagged (T17).
    let text = format!(r#"{{"text":"pay{}me"}}"#, char::from_u32(0x202e).unwrap());
    let hidden = bound_document(r#"{"name":"text","type":"string"}"#, &text)
        .replace("\"chainId\":1", "\"chainId\":11155111");
    let d = draft(&hidden, &none).unwrap();
    assert!(labels(&d).contains(&"T17".to_owned()));
    assert!(d.display.fields.iter().any(|f| f.value == "pay[U+202E]me"));
    let ok = bound_document(
        r#"{"name":"values","type":"uint256[]"}"#,
        r#"{"values":["1","2"]}"#,
    )
    .replace("\"chainId\":1", "\"chainId\":11155111");
    let d = draft(&ok, &none).unwrap();
    assert!(!labels(&d).contains(&"T16".to_owned()));
    assert!(
        d.display
            .fields
            .iter()
            .any(|f| f.sub_label == "values[1]" && f.value == "2")
    );
}

/// Security review M3/S1: a recognized schema is measured against the tree limits too (T16),
/// and one whose structured fields reach the field cap is a blocked request, not an error.
#[test]
fn t16_applies_to_recognized_schemas_and_the_field_cap_blocks() {
    let none = ChainFacts::default();
    // 2 details: under every limit.
    let d = draft(&permit_batch_of(2), &none).unwrap();
    assert!(!labels(&d).contains(&"T16".to_owned()));
    // 200 details = 800 leaves > 512: T16, blocked (was approvable).
    let d = draft(&permit_batch_of(200), &none).unwrap();
    assert!(labels(&d).contains(&"T16".to_owned()));
    assert_eq!(d.display.risk, RiskLevel::Blocked);
    // 300 details ≈ 1,200 structured fields > 1,024: still a draft (was `TooMany`), the list
    // stops at the cap with a note in the last slot, T16, blocked.
    let d = draft(&permit_batch_of(300), &none).unwrap();
    assert!(labels(&d).contains(&"T16".to_owned()));
    assert_eq!(d.display.risk, RiskLevel::Blocked);
    assert_eq!(
        d.display.fields.len(),
        yw_core::approval::MAX_DISPLAY_FIELDS
    );
    let last = d.display.fields.last().unwrap();
    assert!(
        last.value.starts_with("(표시 한도 초과: 항목 ") && last.value.ends_with("개 생략)"),
        "{}",
        last.value
    );
}

#[test]
fn typed_payload_is_the_preimage() {
    let typed = validate(&erc2612(ACC1, "5", NOW + 600), SEPOLIA).unwrap();
    let d = draft(&erc2612(ACC1, "5", NOW + 600), &ChainFacts::default()).unwrap();
    assert_eq!(
        d.payload,
        yw_core::approval::SigningPayload::EvmTypedData(typed.preimage)
    );
    assert_eq!(typed.preimage[..2], [0x19, 0x01]);
    let _: Address = typed.domain.verifying_contract.unwrap();
}

/// spec/14 §3: the same typed-data requests built in English carry no Hangul anywhere in the
/// display (ASCII inputs), and their display differs from the Korean one.
#[test]
fn english_typed_displays_have_no_korean() -> Fallible<()> {
    use yw_core::lang::{Lang, has_hangul};
    let none = ChainFacts::default();
    let sources = [
        erc2612(ACC1, "5", NOW + 600),
        permit_single(PERMIT2, NOW + 86_400, NOW + 600, ACC1),
        permit_batch_of(2),
        permit_transfer(true, true),
        seaport_receiving(1, SEPOLIA_USDC),
    ];
    for source in &sources {
        let chain = sepolia();
        let typed = validate(source, chain.chain_id)?;
        let build = |lang| {
            build_typed_request(
                lang,
                ApprovalId([1; 16]),
                ApprovalOrigin::Site(BrowserOrigin::parse("https://app.example").ok_or("origin")?),
                EvmKeySource::Derived(AccountIndex::ZERO),
                parse_address(ACC1)?,
                ApprovalKind::EvmTypedData,
                &chain,
                &typed,
                &none,
                NOW_MS,
            )
            .map_err(Box::<dyn std::error::Error>::from)
        };
        let english = build(Lang::En)?.display;
        let korean = build(Lang::Ko)?.display;
        assert_eq!(english.lang, Lang::En);
        assert!(!has_hangul(&english.title), "{}", english.title);
        for field in &english.fields {
            assert!(
                !has_hangul(&field.sub_label) && !has_hangul(&field.value),
                "{} = {}",
                field.sub_label,
                field.value
            );
        }
        for warning in &english.warnings {
            assert!(!has_hangul(&warning.text), "{}", warning.text);
        }
        assert_ne!(english.title, korean.title);
    }
    Ok(())
}
