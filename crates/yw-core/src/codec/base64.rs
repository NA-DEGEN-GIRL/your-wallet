//! Standard base64 (RFC 4648 §4, padded): Bitcoin message signatures (BIP137, BIP322 simple and
//! full) are base64 text, and Solana RPC payloads use it too. Decoding is strict: length a
//! multiple of 4, padding only at the end (at most two `=`), unused bits zero (canonical).

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Strict standard base64 decoding; `None` for anything non-canonical.
#[must_use]
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let value = |byte: u8| -> Option<u32> {
        let index = ALPHABET.iter().position(|symbol| *symbol == byte)?;
        u32::try_from(index).ok()
    };
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let chunks = bytes.chunks_exact(4);
    let last = chunks.len().saturating_sub(1);
    for (index, chunk) in chunks.enumerate() {
        let [s0, s1, s2, s3] = <[u8; 4]>::try_from(chunk).ok()?;
        let padding = match (s2, s3) {
            (b'=', b'=') => 2,
            (_, b'=') => 1,
            _ => 0,
        };
        if padding > 0 && index != last {
            return None;
        }
        let triple = (value(s0)? << 18)
            | (value(s1)? << 12)
            | if padding == 2 { 0 } else { value(s2)? << 6 }
            | if padding == 0 { value(s3)? } else { 0 };
        let [_, first, second, third] = triple.to_be_bytes();
        out.push(first);
        match padding {
            0 => {
                out.push(second);
                out.push(third);
            }
            1 if third == 0 => out.push(second),
            2 if second == 0 && third == 0 => {}
            _ => return None,
        }
    }
    Some(out)
}

/// Standard base64 with padding.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    let symbol = |index: u32| {
        char::from(
            ALPHABET
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
        out.push(if chunk.len() > 1 {
            symbol(triple >> 6)
        } else {
            '='
        });
        out.push(if chunk.len() > 2 { symbol(triple) } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn rfc4648_vectors_round_trip() {
        for (plain, text) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), text);
            assert_eq!(decode(text).unwrap(), plain.as_bytes());
        }
        for bad in ["Zg=", "Zh==", "Zm9=", "Z===", "Zg==Zg==", "Zm9v!", "Zm 9v"] {
            assert_eq!(decode(bad), None, "{bad}");
        }
    }
}
