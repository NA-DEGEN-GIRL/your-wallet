//! The relay client-auth did-JWT (`clients/core/relay/relay-client-auth.md`,
//! `clients/core/crypto/crypto-authentication.md`): header `{"alg":"EdDSA","typ":"JWT"}`, payload
//! `{"iss","sub","aud","iat","exp"}` in that order (the reference `signJWT` of
//! `@walletconnect/relay-auth` and the spec's test vector), each part base64url without padding,
//! signature = Ed25519 over `base64url(header) "." base64url(payload)`.
//!
//! `iss` = `did:key:z` + base58btc(`0xed 0x01` ‖ public key) (multicodec `ed25519-pub`).

use core::fmt::Write as _;

use ed25519_dalek::{Signer as _, SigningKey};

const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url without padding (RFC 4648 §5).
#[must_use]
pub fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let symbol = |index: u32| {
        char::from(
            URL_ALPHABET
                .get(usize::try_from(index & 0x3f).unwrap_or(0))
                .copied()
                .unwrap_or(b'A'),
        )
    };
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(symbol(triple >> 18));
        out.push(symbol(triple >> 12));
        if chunk.len() > 1 {
            out.push(symbol(triple >> 6));
        }
        if chunk.len() > 2 {
            out.push(symbol(triple));
        }
    }
    out
}

/// base64url decoding (padding optional; standard `+`/`/` refused). `None` for anything else.
#[must_use]
pub fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let trimmed = text.trim_end_matches('=');
    let value = |byte: u8| -> Option<u32> {
        let index = URL_ALPHABET.iter().position(|symbol| *symbol == byte)?;
        u32::try_from(index).ok()
    };
    let bytes = trimmed.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut triple = 0_u32;
        for (position, byte) in chunk.iter().enumerate() {
            triple |= value(*byte)? << (18 - 6 * u32::try_from(position).ok()?);
        }
        let [_, first, second, third] = triple.to_be_bytes();
        out.push(first);
        if chunk.len() > 2 {
            out.push(second);
        }
        if chunk.len() > 3 {
            out.push(third);
        }
    }
    Some(out)
}

/// `did:key:z…` of an Ed25519 public key.
#[must_use]
pub fn did_key(public: &[u8; 32]) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&[0xed, 0x01]);
    bytes.extend_from_slice(public);
    format!("did:key:z{}", crate::codec::base58::encode(&bytes))
}

/// A JSON string literal of `text` (quotes, backslash and controls escaped).
fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The relay auth JWT signed with the client key `seed` (Ed25519 secret seed): `iss` = did:key of
/// its public key, `sub` = a random per-connection nonce (hex), `aud` = the relay URL,
/// `iat` = now (Unix seconds), `exp` = `iat + ttl_s`.
#[must_use]
pub fn relay_auth_jwt(seed: &[u8; 32], sub: &str, aud: &str, iat: u64, ttl_s: u64) -> String {
    let key = SigningKey::from_bytes(seed);
    let iss = did_key(&key.verifying_key().to_bytes());
    let header = base64url_encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let payload = format!(
        "{{\"iss\":{},\"sub\":{},\"aud\":{},\"iat\":{iat},\"exp\":{}}}",
        json_string(&iss),
        json_string(sub),
        json_string(aud),
        iat.saturating_add(ttl_s)
    );
    let signing_input = format!("{header}.{}", base64url_encode(payload.as_bytes()));
    let signature = key.sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        base64url_encode(&signature.to_bytes())
    )
}

/// The Ed25519 public key of a client seed.
#[must_use]
pub fn client_public(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}
