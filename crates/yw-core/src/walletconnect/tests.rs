#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use super::*;

const SPEC_URI: &str = "wc:7f6e504bfad60b485450578e05678ed3e8e8c4751d3c6160be17160d63ec90f9@2?symKey=587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303&methods=[wc_sessionPropose],[wc_authRequest,wc_authBatchRequest]&relay-protocol=irn&expiryTimestamp=1705667684";

fn hex32(text: &str) -> [u8; 32] {
    crate::hex::decode_array::<32>(text).unwrap()
}

/// The example of `clients/core/pairing/pairing-uri.md`.
#[test]
fn spec_pairing_uri_parses() {
    let uri = parse_pairing_uri(SPEC_URI).unwrap();
    assert_eq!(
        uri.topic_hex(),
        "7f6e504bfad60b485450578e05678ed3e8e8c4751d3c6160be17160d63ec90f9"
    );
    assert_eq!(
        *uri.sym_key,
        hex32("587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303")
    );
    assert_eq!(uri.relay_protocol, "irn");
    assert_eq!(uri.expiry, Some(1_705_667_684));
    assert!(uri.expired(1_705_667_684) && !uri.expired(1_705_667_683));
    assert_eq!(
        uri.methods.as_deref(),
        Some("[wc_sessionPropose],[wc_authRequest,wc_authBatchRequest]")
    );
    // Whitespace, percent-encoding of the whole URI and of values are accepted.
    let encoded = SPEC_URI
        .replace(':', "%3A")
        .replace('@', "%40")
        .replace('?', "%3F");
    assert_eq!(parse_pairing_uri(&format!("  {encoded}\n")).unwrap(), uri);
    let escaped = SPEC_URI.replace("[wc_sessionPropose]", "%5Bwc_sessionPropose%5D");
    assert_eq!(parse_pairing_uri(&escaped).unwrap().topic, uri.topic);
    assert_eq!(format!("{uri:?}"), "PairingUri([REDACTED])");
}

#[test]
fn bad_pairing_uris_are_refused() {
    let v1 = "wc:8a5e5bdc-a0e4-4702-ba63-8f1a5655744f@1?bridge=https%3A%2F%2Fbridge.walletconnect.org&key=41791102999c339c844880b23950704cc43aa840f3739e365323cda4dfa89e7a";
    assert_eq!(parse_pairing_uri(v1), Err(UriError::Version1));
    assert_eq!(
        parse_pairing_uri("https://example.com"),
        Err(UriError::NotWalletConnect)
    );
    assert_eq!(
        parse_pairing_uri(&SPEC_URI.replace("relay-protocol=irn", "relay-protocol=waku")),
        Err(UriError::BadRelay)
    );
    assert_eq!(
        parse_pairing_uri(&SPEC_URI.replace("symKey=587d", "symKey=587")),
        Err(UriError::BadSymKey)
    );
    assert_eq!(
        parse_pairing_uri(&SPEC_URI.replace("@2", "")),
        Err(UriError::UnsupportedVersion)
    );
    assert_eq!(
        parse_pairing_uri(&format!("{SPEC_URI}&symKey=00")),
        Err(UriError::Malformed)
    );
    assert_eq!(
        parse_pairing_uri(&SPEC_URI.replace("7f6e504b", "7f6e50")),
        Err(UriError::BadTopic)
    );
}

/// spec/14: every paste-field message exists in both languages; the Korean one is the `Display`.
#[test]
fn uri_messages_in_both_languages() {
    use crate::lang::{Lang, has_hangul};
    for error in [
        UriError::NotWalletConnect,
        UriError::Version1,
        UriError::UnsupportedVersion,
        UriError::BadTopic,
        UriError::BadSymKey,
        UriError::BadRelay,
        UriError::Malformed,
    ] {
        assert_eq!(error.to_string(), error.message(Lang::Ko));
        assert!(has_hangul(error.message(Lang::Ko)));
        assert!(!has_hangul(error.message(Lang::En)), "{error:?}");
    }
    for entry in uri::text::ALL {
        assert!(!has_hangul(entry.en), "{}", entry.name);
    }
}

/// The test case of `clients/core/crypto/crypto-authentication.md` (seed, sub, aud, iat, ttl
/// 86400 → the published JWT).
#[test]
fn relay_auth_jwt_matches_the_spec_vector() {
    let seed = hex32("58e0254c211b858ef7896b00e3f36beeb13d568d47c6031c4218b87718061295");
    assert_eq!(
        crate::hex::encode(&jwt::client_public(&seed)),
        "884ab67f787b69e534bfdba8d5beb4e719700e90ac06317ed177d49e5a33be5a"
    );
    let jwt = relay_auth_jwt(
        &seed,
        "c479fe5dc464e771e78b193d239a65b58d278cad1c34bfb0b5716e5bb514928e",
        "wss://relay.walletconnect.com",
        1_656_910_097,
        86_400,
    );
    assert_eq!(
        jwt,
        "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtvZEhad25lVlJTaHRhTGY4SktZa3hwREdwMXZHWm5wR21kQnBYOE0yZXh4SCIsInN1YiI6ImM0NzlmZTVkYzQ2NGU3NzFlNzhiMTkzZDIzOWE2NWI1OGQyNzhjYWQxYzM0YmZiMGI1NzE2ZTViYjUxNDkyOGUiLCJhdWQiOiJ3c3M6Ly9yZWxheS53YWxsZXRjb25uZWN0LmNvbSIsImlhdCI6MTY1NjkxMDA5NywiZXhwIjoxNjU2OTk2NDk3fQ.bAKl1swvwqqV_FgwvD4Bx3Yp987B9gTpZctyBviA-EkAuWc8iI8SyokOjkv9GJESgid4U8Tf2foCgrQp2qrxBA"
    );
    assert_eq!(
        did_key(&jwt::client_public(&seed)),
        "did:key:z6MkodHZwneVRShtaLf8JKYkxpDGp1vGZnpGmdBpX8M2exxH"
    );
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(base64url_decode(parts[2]).unwrap().len(), 64);
    assert_eq!(base64url_decode("YQ").unwrap(), b"a");
    assert_eq!(base64url_decode("YQ==").unwrap(), b"a");
    assert!(base64url_decode("Y+").is_none());
}

/// RFC 7748 §6.1 X25519 vector, then the session key and topic of `deriveSymKey`/`hashKey`:
/// HKDF-SHA256 with no salt (= 32 zero bytes) and empty info, computed here with HMAC directly.
#[test]
fn x25519_hkdf_and_topic() {
    use hmac::{Hmac, Mac};
    let alice = X25519Secret::from_bytes(hex32(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ));
    let bob = X25519Secret::from_bytes(hex32(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    ));
    assert_eq!(
        alice.public(),
        hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    );
    assert_eq!(
        bob.public(),
        hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    );
    let shared = alice.shared(&bob.public()).unwrap();
    assert_eq!(
        *shared,
        hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    );
    let mut extract = Hmac::<sha2::Sha256>::new_from_slice(&[0_u8; 32]).unwrap();
    extract.update(shared.as_ref());
    let prk = extract.finalize().into_bytes();
    let mut expand = Hmac::<sha2::Sha256>::new_from_slice(&prk).unwrap();
    expand.update(&[1]);
    let expected: [u8; 32] = expand.finalize().into_bytes().into();
    let key_a = derive_sym_key(&alice, &bob.public()).unwrap();
    let key_b = derive_sym_key(&bob, &alice.public()).unwrap();
    assert_eq!(*key_a, expected);
    assert_eq!(*key_a, *key_b);
    assert_eq!(topic_of(&key_a), crate::codec::sha256(key_a.as_ref()));
    // A low-order peer point (all zero) gives no key.
    assert!(derive_sym_key(&alice, &[0_u8; 32]).is_none());
}

#[test]
fn envelopes_round_trip_and_authenticate() {
    let key = [7_u8; 32];
    let iv = [9_u8; 12];
    let text = br#"{"id":1,"jsonrpc":"2.0","method":"wc_sessionPing","params":{}}"#;
    let wire = seal_envelope(&key, &iv, text, None).unwrap();
    let envelope = Envelope::decode(&wire).unwrap();
    assert_eq!(envelope.kind(), 0);
    assert_eq!(open_envelope(&key, &envelope).unwrap(), text);
    assert!(open_envelope(&[8_u8; 32], &envelope).is_none());
    // Layout: 1 + 12 + len + 16.
    let raw = crate::codec::base64::decode(&wire).unwrap();
    assert_eq!(raw.len(), 1 + 12 + text.len() + 16);
    assert_eq!(&raw[1..13], &iv);
    let mut tampered = raw.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let tampered = Envelope::decode(&crate::codec::base64::encode(&tampered)).unwrap();
    assert!(open_envelope(&key, &tampered).is_none());
    let sender = [3_u8; 32];
    let wire1 = seal_envelope(&key, &iv, text, Some(&sender)).unwrap();
    match Envelope::decode(&wire1).unwrap() {
        envelope @ Envelope::Type1 { sender_public, .. } => {
            assert_eq!(sender_public, sender);
            assert_eq!(open_envelope(&key, &envelope).unwrap(), text);
        }
        Envelope::Type0 { .. } => panic!("type 1 expected"),
    }
    // Type 2 (plaintext link mode) and truncated envelopes are refused.
    assert!(Envelope::decode(&crate::codec::base64::encode(&[2, 1, 2, 3])).is_none());
    assert!(Envelope::decode(&crate::codec::base64::encode(&[0; 20])).is_none());
}
