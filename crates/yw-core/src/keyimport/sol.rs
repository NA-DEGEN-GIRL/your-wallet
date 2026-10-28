//! Solana private-key text (spec/02 §8.4, spec/07 §3.4): the base58 64-byte keypair exported by
//! Phantom/Solflare (`seed[32] ‖ public[32]`) and the `solana-keygen` JSON file (an array of 64
//! numbers, same layout). The public half must equal the Ed25519 public key of the seed. A 32-byte
//! value is most likely an address and is reported as such.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use zeroize::Zeroizing;

use crate::codec::base58::{decode_secret, encode_into, max_encoded_len};
use crate::error::KeyError;
use crate::secret::SecretString;

/// Longest accepted text: a JSON array of 64 numbers, compact (`[1,2,…]`, at most 257 bytes) or
/// pretty-printed with a line break and up to 4 spaces after each comma (`64 × 3 + 63 × 6 + 2 =
/// 572`), plus slack around the brackets.
pub const SOL_KEY_TEXT_MAX: usize = 640;
/// Longest base58 text of 64 bytes.
const BASE58_64_MAX: usize = 88;

/// A parsed Solana key: the RFC 8032 secret seed and its public key.
pub(crate) struct SolSecret {
    pub(crate) seed: Zeroizing<[u8; 32]>,
    pub(crate) public: [u8; 32],
}

impl fmt::Debug for SolSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SolSecret([REDACTED])")
    }
}

fn is_blank(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

/// `[n, n, …]` with exactly 64 decimal numbers 0–255 (no sign, no leading zeros), optional ASCII
/// whitespace between tokens.
fn parse_json_bytes(text: &[u8]) -> Result<Zeroizing<[u8; 64]>, KeyError> {
    let mut out = Zeroizing::new([0_u8; 64]);
    let inner = text
        .strip_prefix(b"[")
        .and_then(|rest| rest.strip_suffix(b"]"))
        .ok_or(KeyError::SolKeyFormat)?;
    let mut count = 0_usize;
    for token in inner.split(|byte| *byte == b',') {
        let start = token
            .iter()
            .position(|byte| !is_blank(*byte))
            .ok_or(KeyError::SolKeyFormat)?;
        let end = token
            .iter()
            .rposition(|byte| !is_blank(*byte))
            .map_or(start, |index| index.saturating_add(1));
        let digits = token.get(start..end).ok_or(KeyError::SolKeyFormat)?;
        let leading_zero = digits.len() > 1 && digits.first() == Some(&b'0');
        if digits.is_empty()
            || digits.len() > 3
            || leading_zero
            || !digits.iter().all(u8::is_ascii_digit)
        {
            return Err(KeyError::SolKeyFormat);
        }
        let value = digits.iter().fold(0_u16, |acc, digit| {
            acc.saturating_mul(10)
                .saturating_add(u16::from(digit.saturating_sub(b'0')))
        });
        let byte = u8::try_from(value).map_err(|_| KeyError::SolKeyFormat)?;
        *out.get_mut(count).ok_or(KeyError::SolKeyFormat)? = byte;
        count = count.saturating_add(1);
    }
    if count != 64 {
        return Err(KeyError::SolKeyFormat);
    }
    Ok(out)
}

fn parse_base58(text: &str) -> Result<Zeroizing<[u8; 64]>, KeyError> {
    if text.len() > BASE58_64_MAX {
        return Err(KeyError::SolKeyFormat);
    }
    let decoded = decode_secret(text).map_err(|_| KeyError::SolKeyFormat)?;
    match decoded.len() {
        64 => {
            let mut out = Zeroizing::new([0_u8; 64]);
            out.copy_from_slice(&decoded);
            Ok(out)
        }
        32 => Err(KeyError::SolKeyIsAddress),
        _ => Err(KeyError::SolKeyFormat),
    }
}

/// Parses Solana key text (surrounding ASCII whitespace ignored, ASCII only).
///
/// # Errors
///
/// [`KeyError::SolKeyFormat`], [`KeyError::SolKeyIsAddress`] (32 bytes) or
/// [`KeyError::SolKeyMismatch`] (the public half differs from the seed's public key).
pub(crate) fn parse_sol_secret(text: &str) -> Result<SolSecret, KeyError> {
    let bytes = text.as_bytes();
    let start = bytes
        .iter()
        .position(|byte| !is_blank(*byte))
        .ok_or(KeyError::SolKeyFormat)?;
    let end = bytes
        .iter()
        .rposition(|byte| !is_blank(*byte))
        .map_or(start, |index| index.saturating_add(1));
    let trimmed = text.get(start..end).ok_or(KeyError::SolKeyFormat)?;
    if !trimmed.is_ascii() || trimmed.len() > SOL_KEY_TEXT_MAX {
        return Err(KeyError::SolKeyFormat);
    }
    let pair = if trimmed.starts_with('[') {
        parse_json_bytes(trimmed.as_bytes())?
    } else {
        parse_base58(trimmed)?
    };
    let (seed_part, public_part) = pair.split_at(32);
    let mut seed = Zeroizing::new([0_u8; 32]);
    seed.copy_from_slice(seed_part);
    let mut public = [0_u8; 32];
    public.copy_from_slice(public_part);
    if crate::sol::keys::public_key(&seed) != public {
        return Err(KeyError::SolKeyMismatch);
    }
    Ok(SolSecret { seed, public })
}

/// The base58 64-byte keypair text (Phantom/Solflare import format) for a reveal.
pub(crate) fn encode_keypair(seed: &[u8; 32], public: &[u8; 32]) -> SecretString {
    let mut pair: Zeroizing<[u8; 64]> = Zeroizing::new([0_u8; 64]);
    let (head, tail) = pair.split_at_mut(32);
    head.copy_from_slice(seed);
    tail.copy_from_slice(public);
    let mut out = Zeroizing::new(String::with_capacity(max_encoded_len(64)));
    encode_into(pair.as_slice(), &mut out);
    SecretString::from_zeroizing(out)
}
