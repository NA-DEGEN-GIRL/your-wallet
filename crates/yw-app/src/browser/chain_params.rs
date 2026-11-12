//! Parameters of the Solana and Bitcoin dApp methods (spec/05 §3.6): connect, message signing
//! and Solana dApp transactions (spec/07 §20). Every violation is -32602 `Invalid params.`;
//! account membership (4100) and the cluster are the dispatcher's.

use yw_core::btc::msgsign::{BtcMessageProtocol, MAX_BTC_MESSAGE_BYTES};
use yw_core::policy::{BtcPurpose, ProviderError, btc_purposes_valid};
use yw_core::sol::SolCluster;
use yw_core::sol::dapp::{
    SOL_TX_MAX_BATCH, SolCommitment, SolSendOptions, SolTxMode, parse_wire_tx,
};
use yw_core::sol::msgsign::{
    MAX_SIWS_FIELD_BYTES, MAX_SIWS_RESOURCES, MAX_SOL_MESSAGE_BYTES, SiwsMessage,
};
use yw_core::sol::template::SOL_MAX_TX_BYTES;
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

/// JavaScript's `Number.MAX_SAFE_INTEGER` (2^53 − 1): the largest `minContextSlot` a page can
/// send exactly.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// The optional `chain` of a transaction request: `solana:mainnet` or `solana:devnet`.
fn sol_chain(value: Option<&Value>) -> Checked<Option<SolCluster>> {
    match value.map(Value::as_str) {
        None => Ok(None),
        Some(Some("solana:mainnet")) => Ok(Some(SolCluster::Mainnet)),
        Some(Some("solana:devnet")) => Ok(Some(SolCluster::Devnet)),
        Some(_) => invalid(),
    }
}

/// One `transaction`: hex folded to lowercase, ≤ 2,464 characters (1,232 bytes), a dApp
/// transaction the strict parser accepts (spec/07 §20.2) with `public` in one signer slot. A
/// send also needs every other required signature present (non-zero; whether they verify is
/// the window's X01) and no durable nonce (spec/07 §20.8).
fn sol_tx(value: &Value, public: &[u8; 32], mode: SolTxMode) -> Checked<Vec<u8>> {
    let hex = value.as_str().ok_or(ProviderError::InvalidParams)?;
    if hex.len() > SOL_MAX_TX_BYTES * 2 {
        return invalid();
    }
    let bytes = yw_core::hex::decode(&hex.to_ascii_lowercase())
        .map_err(|_| ProviderError::InvalidParams)?;
    let wire = parse_wire_tx(&bytes).map_err(|_| ProviderError::InvalidParams)?;
    let ours = wire
        .message
        .signer_slot(public)
        .map_err(|_| ProviderError::InvalidParams)?;
    if mode == SolTxMode::SignAndSend {
        let signed = (0..usize::from(wire.message.header.required))
            .filter(|slot| *slot != usize::from(ours))
            .all(|slot| {
                wire.slot(slot)
                    .is_some_and(|signature| signature.iter().any(|byte| *byte != 0))
            });
        if !signed || wire.message.durable_nonce().is_some() {
            return invalid();
        }
    }
    Ok(bytes)
}

/// `sol_signAndSendTransaction` `options`: exact keys ⊆ {`skipPreflight`, `preflightCommitment`,
/// `minContextSlot`} (the provider already folded the aliases and dropped every other key).
fn sol_send_options(value: Option<&Value>) -> Checked<SolSendOptions> {
    let Some(value) = value else {
        return Ok(SolSendOptions::default());
    };
    let object = value.as_object().ok_or(ProviderError::InvalidParams)?;
    if !exact_keys(
        object,
        &[],
        &["skipPreflight", "preflightCommitment", "minContextSlot"],
    ) {
        return invalid();
    }
    let skip_preflight = match object.get("skipPreflight") {
        None => false,
        Some(value) => value.as_bool().ok_or(ProviderError::InvalidParams)?,
    };
    let preflight_commitment = match object.get("preflightCommitment") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .and_then(SolCommitment::parse)
                .ok_or(ProviderError::InvalidParams)?,
        ),
    };
    let min_context_slot = match object.get("minContextSlot") {
        None => None,
        Some(value) => Some(
            value
                .as_number()
                .and_then(yw_json::Number::as_u64)
                .filter(|slot| *slot <= MAX_SAFE_INTEGER)
                .ok_or(ProviderError::InvalidParams)?,
        ),
    };
    Ok(SolSendOptions {
        skip_preflight,
        preflight_commitment,
        min_context_slot,
    })
}

/// `sol_signTransaction`: `[{ "publicKey": base58, "transaction": hex, "chain"? }]`.
pub(super) fn sol_sign_transaction(values: &[Value]) -> Checked<Validated> {
    let object = single_object(values)?;
    if !exact_keys(object, &["publicKey", "transaction"], &["chain"]) {
        return invalid();
    }
    let public = public_key(object.get("publicKey"))?;
    let chain = sol_chain(object.get("chain"))?;
    let transaction = object
        .get("transaction")
        .ok_or(ProviderError::InvalidParams)?;
    Ok(Validated::SolTx {
        public,
        chain,
        txs: vec![sol_tx(transaction, &public, SolTxMode::SignOnly)?],
        mode: SolTxMode::SignOnly,
        batch: false,
        options: SolSendOptions::default(),
    })
}

/// `sol_signAllTransactions`: `[{ "publicKey", "transactions": [hex] (1..=32), "chain"? }]`.
pub(super) fn sol_sign_all_transactions(values: &[Value]) -> Checked<Validated> {
    let object = single_object(values)?;
    if !exact_keys(object, &["publicKey", "transactions"], &["chain"]) {
        return invalid();
    }
    let public = public_key(object.get("publicKey"))?;
    let chain = sol_chain(object.get("chain"))?;
    let txs = object
        .get("transactions")
        .and_then(Value::as_array)
        .filter(|items| (1..=SOL_TX_MAX_BATCH).contains(&items.len()))
        .ok_or(ProviderError::InvalidParams)?
        .iter()
        .map(|item| sol_tx(item, &public, SolTxMode::SignOnly))
        .collect::<Checked<Vec<_>>>()?;
    Ok(Validated::SolTx {
        public,
        chain,
        txs,
        mode: SolTxMode::SignOnly,
        batch: true,
        options: SolSendOptions::default(),
    })
}

/// `sol_signAndSendTransaction`: `[{ "publicKey", "transaction": hex, "chain"?, "options"? }]`.
pub(super) fn sol_sign_and_send(values: &[Value]) -> Checked<Validated> {
    let object = single_object(values)?;
    if !exact_keys(object, &["publicKey", "transaction"], &["chain", "options"]) {
        return invalid();
    }
    let public = public_key(object.get("publicKey"))?;
    let chain = sol_chain(object.get("chain"))?;
    let options = sol_send_options(object.get("options"))?;
    let transaction = object
        .get("transaction")
        .ok_or(ProviderError::InvalidParams)?;
    Ok(Validated::SolTx {
        public,
        chain,
        txs: vec![sol_tx(transaction, &public, SolTxMode::SignAndSend)?],
        mode: SolTxMode::SignAndSend,
        batch: false,
        options,
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

    /// A legacy wire transaction (hex) over `keys` (`required` signers, the last key read-only
    /// unsigned) with `signatures` in the slots and the fixed blockhash `[7; 32]`.
    fn wire_hex(
        keys: &[[u8; 32]],
        required: u8,
        ixs: &[(u8, &[u8], &[u8])],
        signatures: &[[u8; 64]],
    ) -> String {
        let len = |n: usize| u8::try_from(n).unwrap();
        let mut out = vec![len(signatures.len())];
        for signature in signatures {
            out.extend_from_slice(signature);
        }
        out.extend_from_slice(&[required, 0, 1, len(keys.len())]);
        for key in keys {
            out.extend_from_slice(key);
        }
        out.extend_from_slice(&[7; 32]);
        out.push(len(ixs.len()));
        for (program, accounts, data) in ixs {
            out.extend_from_slice(&[*program, len(accounts.len())]);
            out.extend_from_slice(accounts);
            out.push(len(data.len()));
            out.extend_from_slice(data);
        }
        yw_core::hex::encode(&out)
    }

    /// spec/05 §3.6: the three transaction methods — shapes, the hex and size bounds, the
    /// strict parser, our signer slot, the cluster names, the send-only rules (other required
    /// signatures present, no durable nonce) and the exact send options.
    #[test]
    #[allow(clippy::too_many_lines, reason = "one table of params cases")]
    fn solana_transaction_params() {
        use yw_core::sol::SolCluster;
        use yw_core::sol::dapp::{SolCommitment, SolSendOptions, SolTxMode};

        let key = yw_core::codec::base58::base58_decode_32(KEY).unwrap();
        let program = [5; 32];
        let one = wire_hex(&[key, program], 1, &[(1, &[0], &[9])], &[[0; 64]]);
        let tx = |method: Method, extra: &str, transaction: &str| {
            check(
                method,
                &format!(r#"[{{"publicKey":"{KEY}","transaction":"{transaction}"{extra}}}]"#),
            )
        };
        // Upper-case hex is folded; the bytes are kept exactly.
        let Ok(Validated::SolTx {
            public,
            chain,
            txs,
            mode,
            batch,
            options,
        }) = tx(Method::SolSignTransaction, "", &one.to_ascii_uppercase())
        else {
            unreachable!("sign params");
        };
        assert_eq!(public, key);
        assert_eq!((chain, mode, batch), (None, SolTxMode::SignOnly, false));
        assert_eq!(txs, vec![yw_core::hex::decode(&one).unwrap()]);
        assert_eq!(options, SolSendOptions::default());
        assert!(matches!(
            tx(
                Method::SolSignTransaction,
                r#","chain":"solana:devnet""#,
                &one
            ),
            Ok(Validated::SolTx {
                chain: Some(SolCluster::Devnet),
                ..
            })
        ));
        let all = |items: &[&str]| {
            let list: Vec<String> = items.iter().map(|hex| format!("\"{hex}\"")).collect();
            check(
                Method::SolSignAllTransactions,
                &format!(
                    r#"[{{"publicKey":"{KEY}","transactions":[{}],"chain":"solana:mainnet"}}]"#,
                    list.join(",")
                ),
            )
        };
        assert!(matches!(
            all(&[&one, &one]),
            Ok(Validated::SolTx { batch: true, chain: Some(SolCluster::Mainnet), ref txs, .. })
                if txs.len() == 2
        ));
        assert!(all(&[one.as_str(); 32]).is_ok());
        // Not a signer; the fee payer as program; 65 instructions; over 1,232 bytes.
        let stranger = wire_hex(&[[6; 32], key], 1, &[(1, &[0], &[])], &[[0; 64]]);
        let payer_program = wire_hex(&[key, program], 1, &[(0, &[0], &[])], &[[0; 64]]);
        let many: Vec<(u8, &[u8], &[u8])> = vec![(1, &[0], &[]); 65];
        let too_many = wire_hex(&[key, program], 1, &many, &[[0; 64]]);
        let oversize = format!("{one}{}", "00".repeat(1_233 - one.len() / 2));
        for (bad, why) in [
            (stranger.as_str(), "not a signer"),
            (payer_program.as_str(), "program index 0"),
            (too_many.as_str(), "65 instructions"),
            (oversize.as_str(), "1,233 bytes"),
            ("abc", "odd hex"),
            ("", "empty"),
        ] {
            assert_eq!(
                tx(Method::SolSignTransaction, "", bad).err(),
                Some(ProviderError::InvalidParams),
                "{why}"
            );
        }
        for extra in [
            r#","chain":"solana:testnet""#,
            r#","chain":1"#,
            r#","options":{}"#,
            r#","display":"x""#,
        ] {
            assert_eq!(
                tx(Method::SolSignTransaction, extra, &one).err(),
                Some(ProviderError::InvalidParams),
                "{extra}"
            );
        }
        assert_eq!(all(&[]).err(), Some(ProviderError::InvalidParams));
        assert_eq!(
            all(&[one.as_str(); 33]).err(),
            Some(ProviderError::InvalidParams)
        );
        // Send: every other required signature present, no durable nonce, exact options.
        let payer = [8; 32];
        let ixs: &[(u8, &[u8], &[u8])] = &[(2, &[0, 1], &[])];
        let unsigned = wire_hex(&[payer, key, program], 2, ixs, &[[0; 64], [0; 64]]);
        let cosigned = wire_hex(&[payer, key, program], 2, ixs, &[[0x33; 64], [0; 64]]);
        let nonce = wire_hex(
            &[key, [9; 32], [0; 32]],
            1,
            &[(2, &[1, 0], &[4, 0, 0, 0])],
            &[[0; 64]],
        );
        assert!(tx(Method::SolSignTransaction, "", &unsigned).is_ok());
        assert!(tx(Method::SolSignTransaction, "", &nonce).is_ok());
        let send = |transaction: &str, extra: &str| {
            tx(Method::SolSignAndSendTransaction, extra, transaction)
        };
        assert_eq!(
            send(&unsigned, "").err(),
            Some(ProviderError::InvalidParams)
        );
        assert_eq!(send(&nonce, "").err(), Some(ProviderError::InvalidParams));
        assert!(matches!(
            send(&cosigned, ""),
            Ok(Validated::SolTx {
                mode: SolTxMode::SignAndSend,
                batch: false,
                ..
            })
        ));
        let Ok(Validated::SolTx { options, .. }) = send(
            &one,
            r#","options":{"skipPreflight":true,"preflightCommitment":"processed","minContextSlot":9007199254740991}"#,
        ) else {
            unreachable!("send options");
        };
        assert!(options.skip_preflight);
        assert_eq!(options.preflight_commitment, Some(SolCommitment::Processed));
        assert_eq!(options.min_context_slot, Some(9_007_199_254_740_991));
        for bad in [
            r#","options":{"maxRetries":1}"#,
            r#","options":{"skipPreflight":"yes"}"#,
            r#","options":{"preflightCommitment":"recent"}"#,
            r#","options":{"minContextSlot":-1}"#,
            r#","options":{"minContextSlot":1.5}"#,
            r#","options":{"minContextSlot":9007199254740992}"#,
            r#","options":[]"#,
        ] {
            assert_eq!(
                send(&one, bad).err(),
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
