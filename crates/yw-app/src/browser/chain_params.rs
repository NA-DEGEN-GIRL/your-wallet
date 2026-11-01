//! Parameters of the Solana and Bitcoin dApp methods (spec/05 §3.6): connect and message
//! signing only. Every violation is -32602 `Invalid params.`; account membership (4100) is the
//! dispatcher's.

use yw_core::btc::msgsign::{BtcMessageProtocol, MAX_BTC_MESSAGE_BYTES};
use yw_core::policy::{BtcPurpose, ProviderError, btc_purposes_valid};
use yw_core::sol::msgsign::{
    MAX_SIWS_FIELD_BYTES, MAX_SIWS_RESOURCES, MAX_SOL_MESSAGE_BYTES, SiwsMessage,
};
use yw_json::{Object, Value};

use super::params::Validated;

type Checked<T> = Result<T, ProviderError>;

fn invalid<T>() -> Checked<T> {
    Err(ProviderError::InvalidParams)
}

fn exact_keys(object: &Object, required: &[&str], optional: &[&str]) -> bool {
    required.iter().all(|key| object.get(key).is_some())
        && object
            .keys()
            .all(|key| required.contains(&key) || optional.contains(&key))
}

fn single_object(values: &[Value]) -> Checked<&Object> {
    match values {
        [value] => value.as_object().ok_or(ProviderError::InvalidParams),
        _ => invalid(),
    }
}

/// A base58 Solana public key.
fn public_key(value: Option<&Value>) -> Checked<[u8; 32]> {
    let text = value
        .and_then(Value::as_str)
        .ok_or(ProviderError::InvalidParams)?;
    yw_core::codec::base58::base58_decode_32(text).map_err(|_| ProviderError::InvalidParams)
}

/// `sol_connect`: `[]` or `[{ "onlyIfTrusted": bool }]`.
pub(super) fn sol_connect(values: &[Value]) -> Checked<Validated> {
    if values.is_empty() {
        return Ok(Validated::SolConnect {
            only_if_trusted: false,
        });
    }
    let object = single_object(values)?;
    if !exact_keys(object, &[], &["onlyIfTrusted"]) {
        return invalid();
    }
    let only_if_trusted = match object.get("onlyIfTrusted") {
        None => false,
        Some(value) => value.as_bool().ok_or(ProviderError::InvalidParams)?,
    };
    Ok(Validated::SolConnect { only_if_trusted })
}

/// `sol_signMessage`: `[{ "publicKey": base58, "message": hex }]` (≤ 64 KiB).
pub(super) fn sol_sign_message(values: &[Value]) -> Checked<Validated> {
    let object = single_object(values)?;
    if !exact_keys(object, &["publicKey", "message"], &[]) {
        return invalid();
    }
    let public = public_key(object.get("publicKey"))?;
    let hex = object
        .get("message")
        .and_then(Value::as_str)
        .ok_or(ProviderError::InvalidParams)?;
    if hex.len() > MAX_SOL_MESSAGE_BYTES * 2 {
        return invalid();
    }
    let message = yw_core::hex::decode(&hex.to_ascii_lowercase())
        .map_err(|_| ProviderError::InvalidParams)?;
    Ok(Validated::SolSignMessage { public, message })
}

const SIWS_KEYS: [&str; 12] = [
    "domain",
    "address",
    "statement",
    "uri",
    "version",
    "chainId",
    "nonce",
    "issuedAt",
    "expirationTime",
    "notBefore",
    "requestId",
    "resources",
];

/// One SIWS string: ≤ 1 KiB, no control characters (a line feed would forge another line).
fn siws_text(value: &Value) -> Checked<Option<String>> {
    let text = value.as_str().ok_or(ProviderError::InvalidParams)?;
    if text.len() > MAX_SIWS_FIELD_BYTES || text.chars().any(char::is_control) {
        return invalid();
    }
    Ok((!text.is_empty()).then(|| text.to_owned()))
}

/// The `SolanaSignInInput` object: only the twelve known keys (an unknown key such as
/// `useOffchainMessage` is refused), strings without control characters, ≤ 32 resources.
/// `domain`/`address` stay empty when absent (the dispatcher fills them in).
pub(super) fn siws_input(value: &Value) -> Checked<SiwsMessage> {
    let object = value.as_object().ok_or(ProviderError::InvalidParams)?;
    if !exact_keys(object, &[], &SIWS_KEYS) {
        return invalid();
    }
    let field =
        |key: &str| -> Checked<Option<String>> { object.get(key).map_or(Ok(None), siws_text) };
    let resources = match object.get("resources") {
        None => None,
        Some(value) => {
            let items = value.as_array().ok_or(ProviderError::InvalidParams)?;
            if items.len() > MAX_SIWS_RESOURCES {
                return invalid();
            }
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match siws_text(item)? {
                    Some(text) => out.push(text),
                    None => return invalid(),
                }
            }
            Some(out)
        }
    };
    Ok(SiwsMessage {
        domain: field("domain")?.unwrap_or_default(),
        address: field("address")?.unwrap_or_default(),
        statement: field("statement")?,
        uri: field("uri")?,
        version: field("version")?,
        chain_id: field("chainId")?,
        nonce: field("nonce")?,
        issued_at: field("issuedAt")?,
        expiration_time: field("expirationTime")?,
        not_before: field("notBefore")?,
        request_id: field("requestId")?,
        resources,
    })
}

/// `sol_signIn`: `[{ "publicKey": base58, "input": SolanaSignInInput }]`.
pub(super) fn sol_sign_in(values: &[Value]) -> Checked<Validated> {
    let object = single_object(values)?;
    if !exact_keys(object, &["publicKey", "input"], &[]) {
        return invalid();
    }
    let public = public_key(object.get("publicKey"))?;
    let input = siws_input(object.get("input").ok_or(ProviderError::InvalidParams)?)?;
    Ok(Validated::SolSignIn {
        public,
        input: Box::new(input),
    })
}

/// `btc_requestAccounts`: `[{ "purposes": ["payment"|"ordinals"] | ["any"] }]`.
pub(super) fn btc_request_accounts(values: &[Value]) -> Checked<Validated> {
    let object = single_object(values)?;
    if !exact_keys(object, &["purposes"], &[]) {
        return invalid();
    }
    let purposes = object
        .get("purposes")
        .and_then(Value::as_array)
        .ok_or(ProviderError::InvalidParams)?
        .iter()
        .map(|item| item.as_str().and_then(BtcPurpose::parse))
        .collect::<Option<Vec<_>>>()
        .ok_or(ProviderError::InvalidParams)?;
    if !btc_purposes_valid(&purposes) {
        return invalid();
    }
    Ok(Validated::BtcRequestAccounts(purposes))
}

/// `btc_signMessage`: `[{ "address", "message": UTF-8 text ≤ 64 KiB, "protocol"?: "ecdsa" |
/// "bip322" }]`.
pub(super) fn btc_sign_message(values: &[Value]) -> Checked<Validated> {
    let object = single_object(values)?;
    if !exact_keys(object, &["address", "message"], &["protocol"]) {
        return invalid();
    }
    let address = object
        .get("address")
        .and_then(Value::as_str)
        .filter(|text| (1..=100).contains(&text.len()) && text.is_ascii())
        .ok_or(ProviderError::InvalidParams)?;
    let address = normalize_btc_address(address).ok_or(ProviderError::InvalidParams)?;
    let message = object
        .get("message")
        .and_then(Value::as_str)
        .filter(|text| text.len() <= MAX_BTC_MESSAGE_BYTES)
        .ok_or(ProviderError::InvalidParams)?
        .as_bytes()
        .to_vec();
    let protocol = match object.get("protocol") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .and_then(BtcMessageProtocol::parse)
                .ok_or(ProviderError::InvalidParams)?,
        ),
    };
    Ok(Validated::BtcSignMessage {
        address,
        message,
        protocol,
    })
}

/// The wallet's spelling of a requested Bitcoin address (security review L13): a bech32/bech32m
/// address (`bc1`/`tb1`/`bcrt1`, BIP173 allows all-uppercase) is matched in lowercase, as the
/// wallet stores it; a mixed-case one is invalid (BIP173), `None`. Base58 addresses are
/// case-sensitive and kept as given.
fn normalize_btc_address(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    if !["bc1", "tb1", "bcrt1"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
    {
        return Some(text.to_owned());
    }
    let upper = text.bytes().any(|byte| byte.is_ascii_uppercase());
    let lowercase = text.bytes().any(|byte| byte.is_ascii_lowercase());
    (!(upper && lowercase)).then_some(lower)
}

#[cfg(test)]
mod tests {
    use yw_core::policy::{BtcPurpose, Method, ProviderError};
    use yw_json::{Limits, parse};

    use crate::browser::params::{Validated, validate};

    fn check(method: Method, json: &str) -> Result<Validated, ProviderError> {
        validate(method, &parse(json.as_bytes(), &Limits::REQUEST).unwrap())
    }

    const KEY: &str = "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T";

    #[test]
    fn solana_params() {
        assert!(matches!(
            check(Method::SolConnect, "[]"),
            Ok(Validated::SolConnect {
                only_if_trusted: false
            })
        ));
        assert!(matches!(
            check(Method::SolConnect, r#"[{"onlyIfTrusted":true}]"#),
            Ok(Validated::SolConnect {
                only_if_trusted: true
            })
        ));
        assert!(check(Method::SolConnect, r#"[{"other":1}]"#).is_err());
        assert!(matches!(
            check(
                Method::SolSignMessage,
                &format!(r#"[{{"publicKey":"{KEY}","message":"48656C6c6f"}}]"#)
            ),
            Ok(Validated::SolSignMessage { message, .. }) if message == b"Hello"
        ));
        for bad in [
            format!(r#"[{{"publicKey":"{KEY}","message":"abc"}}]"#),
            r#"[{"publicKey":"0x00","message":"00"}]"#.to_owned(),
            format!(r#"[{{"publicKey":"{KEY}","message":"00","display":"utf8"}}]"#),
        ] {
            assert_eq!(
                check(Method::SolSignMessage, &bad).err(),
                Some(ProviderError::InvalidParams)
            );
        }
        let sign_in = check(
            Method::SolSignIn,
            &format!(
                r#"[{{"publicKey":"{KEY}","input":{{"domain":"app.example","statement":"Hi","resources":["a"],"nonce":""}}}}]"#
            ),
        );
        let Ok(Validated::SolSignIn { input, .. }) = sign_in else {
            unreachable!("sign-in params");
        };
        assert_eq!(input.domain, "app.example");
        assert_eq!(input.address, "");
        assert_eq!(input.nonce, None);
        assert_eq!(input.resources, Some(vec!["a".to_owned()]));
        for bad in [
            r#"{"useOffchainMessage":true}"#,
            r#"{"statement":"a\nURI: x"}"#,
            r#"{"resources":[""]}"#,
            r#"{"domain":1}"#,
        ] {
            assert_eq!(
                check(
                    Method::SolSignIn,
                    &format!(r#"[{{"publicKey":"{KEY}","input":{bad}}}]"#)
                )
                .err(),
                Some(ProviderError::InvalidParams),
                "{bad}"
            );
        }
    }

    #[test]
    fn bitcoin_params() {
        assert!(matches!(
            check(Method::BtcRequestAccounts, r#"[{"purposes":["payment","ordinals"]}]"#),
            Ok(Validated::BtcRequestAccounts(purposes))
                if purposes == [BtcPurpose::Payment, BtcPurpose::Ordinals]
        ));
        for bad in [
            r#"[{"purposes":[]}]"#,
            r#"[{"purposes":["any","payment"]}]"#,
            r#"[{"purposes":["stacks"]}]"#,
            r"[]",
        ] {
            assert!(check(Method::BtcRequestAccounts, bad).is_err(), "{bad}");
        }
        assert!(matches!(
            check(
                Method::BtcSignMessage,
                r#"[{"address":"bc1qx","message":"hi","protocol":"bip322"}]"#
            ),
            Ok(Validated::BtcSignMessage {
                protocol: Some(_),
                ..
            })
        ));
        assert!(
            check(
                Method::BtcSignMessage,
                r#"[{"address":"bc1qx","message":"hi","protocol":"BIP322"}]"#
            )
            .is_err()
        );
        assert!(
            check(
                Method::BtcSignMessage,
                r#"[{"address":"bc1qx","message":1}]"#
            )
            .is_err()
        );
        assert!(check(Method::BtcGetAccounts, "[]").is_ok());
        assert!(check(Method::BtcGetNetwork, "[1]").is_err());
    }

    /// Security review L13: an all-uppercase bech32/bech32m address (valid per BIP173) is
    /// matched in the wallet's lowercase spelling; mixed case is invalid; base58 is kept.
    #[test]
    fn btc_sign_message_addresses_are_normalized() {
        let address_of = |address: &str| match check(
            Method::BtcSignMessage,
            &format!(r#"[{{"address":"{address}","message":"hi"}}]"#),
        ) {
            Ok(Validated::BtcSignMessage { address, .. }) => Ok(address),
            Err(error) => Err(error),
            Ok(_) => Err(ProviderError::Internal),
        };
        let taproot = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297";
        assert_eq!(
            address_of(&taproot.to_ascii_uppercase()).as_deref(),
            Ok(taproot)
        );
        assert_eq!(address_of(taproot).as_deref(), Ok(taproot));
        let testnet = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        assert_eq!(
            address_of(&testnet.to_ascii_uppercase()).as_deref(),
            Ok(testnet)
        );
        assert_eq!(
            address_of("BCRT1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KYGT080").as_deref(),
            Ok("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")
        );
        assert_eq!(
            address_of("bc1P5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297"),
            Err(ProviderError::InvalidParams)
        );
        let legacy = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
        assert_eq!(address_of(legacy).as_deref(), Ok(legacy));
    }
}
