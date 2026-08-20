//! Official and adversarial vectors for strict EIP-712 v4 admission.

use wallet_eip712::{LimitKind, TypedDataError, eip712_signing_digest, validate_typed_data_v4};
use wallet_model::{Hash32, U256};

const OFFICIAL_ETHER_MAIL: &str = r#"{
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

fn chain_id() -> U256 {
    U256::from_u64(1)
}

fn bound_document(message_fields: &str, message: &str) -> String {
    format!(
        r#"{{
          "types": {{
            "EIP712Domain": [
              {{"name":"chainId","type":"uint256"}},
              {{"name":"verifyingContract","type":"address"}}
            ],
            "Message": [{message_fields}]
          }},
          "primaryType": "Message",
          "domain": {{
            "chainId": 1,
            "verifyingContract": "0x1111111111111111111111111111111111111111"
          }},
          "message": {message}
        }}"#
    )
}

#[test]
fn official_eip712_ether_mail_vector_matches() -> Result<(), Box<dyn std::error::Error>> {
    let validated = validate_typed_data_v4(OFFICIAL_ETHER_MAIL.as_bytes(), chain_id())?;
    let protocol_value = validated.as_untrusted();
    assert_eq!(
        protocol_value.domain_separator,
        Hash32::from_fixed_hex(
            "0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
        )?
    );
    assert_eq!(
        protocol_value.message_hash,
        Hash32::from_fixed_hex(
            "0xc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
        )?
    );
    assert_eq!(
        eip712_signing_digest(&validated),
        Hash32::from_fixed_hex(
            "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
        )?
    );
    Ok(())
}

#[test]
fn duplicate_json_type_key_is_rejected_before_value_conversion() {
    let source = br#"{
      "types": {
        "EIP712Domain": [],
        "Message": [],
        "Message": []
      },
      "primaryType":"Message",
      "domain":{},
      "message":{}
    }"#;
    assert_eq!(
        validate_typed_data_v4(source, chain_id()),
        Err(TypedDataError::DuplicateJsonKey)
    );
}

#[test]
fn recursive_type_cycle_is_rejected() {
    let source = br#"{
      "types": {
        "EIP712Domain": [],
        "Node": [{"name":"next","type":"Node"}]
      },
      "primaryType":"Node",
      "domain":{},
      "message":{"next":{}}
    }"#;
    assert_eq!(
        validate_typed_data_v4(source, chain_id()),
        Err(TypedDataError::CyclicType)
    );
}

#[test]
fn undefined_and_duplicate_fields_are_rejected() {
    let undefined = br#"{
      "types": {
        "EIP712Domain": [],
        "Message": [{"name":"person","type":"Person"}]
      },
      "primaryType":"Message",
      "domain":{},
      "message":{"person":{}}
    }"#;
    assert_eq!(
        validate_typed_data_v4(undefined, chain_id()),
        Err(TypedDataError::UndefinedType)
    );

    let duplicate = br#"{
      "types": {
        "EIP712Domain": [],
        "Message": [
          {"name":"value","type":"uint256"},
          {"name":"value","type":"uint256"}
        ]
      },
      "primaryType":"Message",
      "domain":{},
      "message":{"value":"1"}
    }"#;
    assert_eq!(
        validate_typed_data_v4(duplicate, chain_id()),
        Err(TypedDataError::DuplicateField)
    );
}

#[test]
fn excessive_array_dimensions_are_rejected() {
    let source = bound_document(
        r#"{"name":"values","type":"uint256[][][][][][][][][]"}"#,
        r#"{"values":[]}"#,
    );
    assert_eq!(
        validate_typed_data_v4(source.as_bytes(), chain_id()),
        Err(TypedDataError::LimitExceeded(LimitKind::ArrayDimensions))
    );
}

#[test]
fn huge_and_ambiguous_integers_are_rejected() {
    let huge = bound_document(
        r#"{"name":"value","type":"uint256"}"#,
        r#"{"value":"115792089237316195423570985008687907853269984665640564039457584007913129639936"}"#,
    );
    assert_eq!(
        validate_typed_data_v4(huge.as_bytes(), chain_id()),
        Err(TypedDataError::InvalidValue)
    );

    let ambiguous = bound_document(
        r#"{"name":"value","type":"uint256"}"#,
        r#"{"value":9007199254740992}"#,
    );
    assert_eq!(
        validate_typed_data_v4(ambiguous.as_bytes(), chain_id()),
        Err(TypedDataError::InvalidValue)
    );

    let noncanonical = bound_document(r#"{"name":"value","type":"uint256"}"#, r#"{"value":"01"}"#);
    assert_eq!(
        validate_typed_data_v4(noncanonical.as_bytes(), chain_id()),
        Err(TypedDataError::InvalidValue)
    );

    for number in ["-0", "1.0", "1e0"] {
        let source = bound_document(
            r#"{"name":"value","type":"int256"}"#,
            &format!(r#"{{"value":{number}}}"#),
        );
        assert_eq!(
            validate_typed_data_v4(source.as_bytes(), chain_id()),
            Err(TypedDataError::InvalidValue)
        );
    }
}

#[test]
fn missing_domain_bindings_are_unconditionally_rejected() {
    let source = br#"{
      "types": {
        "EIP712Domain": [],
        "Message": [{"name":"contents","type":"string"}]
      },
      "primaryType":"Message",
      "domain":{},
      "message":{"contents":"hello"}
    }"#;
    assert_eq!(
        validate_typed_data_v4(source, chain_id()),
        Err(TypedDataError::SchemaExceptionRequired)
    );
}

#[test]
fn zero_contract_is_unbound_and_chain_mismatch_is_never_excepted() {
    let zero_contract = r#"{
      "types": {
        "EIP712Domain": [
          {"name":"chainId","type":"uint256"},
          {"name":"verifyingContract","type":"address"}
        ],
        "Message": []
      },
      "primaryType":"Message",
      "domain":{
        "chainId":1,
        "verifyingContract":"0x0000000000000000000000000000000000000000"
      },
      "message":{}
    }"#;
    assert_eq!(
        validate_typed_data_v4(zero_contract.as_bytes(), chain_id()),
        Err(TypedDataError::SchemaExceptionRequired)
    );

    let mismatch = bound_document("", "{}").replace("\"chainId\": 1", "\"chainId\": 2");
    assert_eq!(
        validate_typed_data_v4(mismatch.as_bytes(), chain_id()),
        Err(TypedDataError::ChainIdMismatch)
    );
}

#[test]
fn message_object_key_order_does_not_change_struct_hash() -> Result<(), TypedDataError> {
    let fields = r#"{"name":"a","type":"uint256"},{"name":"b","type":"string"}"#;
    let first = bound_document(fields, r#"{"a":"7","b":"hello"}"#);
    let second = bound_document(fields, r#"{"b":"hello","a":"7"}"#);
    let first = validate_typed_data_v4(first.as_bytes(), chain_id())?;
    let second = validate_typed_data_v4(second.as_bytes(), chain_id())?;
    assert_eq!(
        first.as_untrusted().domain_separator,
        second.as_untrusted().domain_separator
    );
    assert_eq!(
        first.as_untrusted().message_hash,
        second.as_untrusted().message_hash
    );
    assert_ne!(
        first.as_untrusted().source_document_hash,
        second.as_untrusted().source_document_hash
    );
    Ok(())
}

#[test]
fn one_message_bit_changes_the_signing_digest() -> Result<(), TypedDataError> {
    let fields = r#"{"name":"data","type":"bytes1"}"#;
    let first = bound_document(fields, r#"{"data":"0x00"}"#);
    let second = bound_document(fields, r#"{"data":"0x01"}"#);
    let first = validate_typed_data_v4(first.as_bytes(), chain_id())?;
    let second = validate_typed_data_v4(second.as_bytes(), chain_id())?;
    assert_ne!(
        eip712_signing_digest(&first),
        eip712_signing_digest(&second)
    );
    Ok(())
}

#[test]
fn primitives_nested_structs_and_arrays_are_supported() -> Result<(), TypedDataError> {
    let source = br#"{
      "types": {
        "EIP712Domain": [
          {"name":"chainId","type":"uint256"},
          {"name":"verifyingContract","type":"address"}
        ],
        "Point": [
          {"name":"x","type":"int16"},
          {"name":"y","type":"int16"}
        ],
        "Message": [
          {"name":"owner","type":"address"},
          {"name":"enabled","type":"bool"},
          {"name":"label","type":"string"},
          {"name":"payload","type":"bytes"},
          {"name":"tag","type":"bytes4"},
          {"name":"small","type":"uint8"},
          {"name":"negative","type":"int8"},
          {"name":"points","type":"Point[2]"},
          {"name":"matrix","type":"uint16[][2]"}
        ]
      },
      "primaryType":"Message",
      "domain":{
        "chainId":"0x1",
        "verifyingContract":"0x1111111111111111111111111111111111111111"
      },
      "message":{
        "owner":"0x2222222222222222222222222222222222222222",
        "enabled":true,
        "label":"bounded",
        "payload":"0x010203",
        "tag":"0xaabbccdd",
        "small":"255",
        "negative":"-128",
        "points":[{"x":"-1","y":"2"},{"x":"3","y":"-4"}],
        "matrix":[[1,2,3],[4]]
      }
    }"#;
    let validated = validate_typed_data_v4(source, chain_id())?;
    assert_ne!(validated.as_untrusted().message_hash, Hash32::ZERO);
    Ok(())
}

#[test]
fn narrow_integer_ranges_are_enforced() {
    for value in [r#""256""#, r#""0x100""#] {
        let source = bound_document(
            r#"{"name":"value","type":"uint8"}"#,
            &format!(r#"{{"value":{value}}}"#),
        );
        assert_eq!(
            validate_typed_data_v4(source.as_bytes(), chain_id()),
            Err(TypedDataError::InvalidValue)
        );
    }
    for value in [r#""128""#, r#""-129""#, r#""-0""#] {
        let source = bound_document(
            r#"{"name":"value","type":"int8"}"#,
            &format!(r#"{{"value":{value}}}"#),
        );
        assert_eq!(
            validate_typed_data_v4(source.as_bytes(), chain_id()),
            Err(TypedDataError::InvalidValue)
        );
    }
}

#[test]
fn fixed_source_limit_fails_closed() {
    let source = vec![b' '; 1_048_577];
    assert_eq!(
        validate_typed_data_v4(&source, chain_id()),
        Err(TypedDataError::LimitExceeded(LimitKind::SourceBytes))
    );
}
