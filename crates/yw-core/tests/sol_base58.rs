//! Strict fixed-length base58 (spec/07 §5, §17.2): boundaries, the program/address constants and
//! the rejections. The Bitcoin Core vectors run in `codec_base58.rs` through the same encoder.

use yw_core::codec::base58::{Base58Error, base58_decode_32, base58_decode_64, base58_encode};
use yw_core::sol::address::SOL_BLOCKED_RECIPIENTS;

#[test]
fn boundaries() {
    assert_eq!(base58_encode(&[0; 32]), "11111111111111111111111111111111");
    assert_eq!(
        base58_decode_32("11111111111111111111111111111111"),
        Ok([0; 32])
    );
    assert_eq!(
        base58_encode(&[0xff; 32]),
        "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG"
    );
    let mut lead = [0xff_u8; 32];
    lead[0] = 0;
    assert_eq!(
        base58_encode(&lead),
        "14uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofL"
    );
    let mut one = [0_u8; 32];
    one[0] = 1;
    let text = base58_encode(&one);
    assert_eq!(text, "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM");
    assert_eq!(text.len(), 43);
    for value in [[0_u8; 32], [0xff; 32], lead, one] {
        assert_eq!(base58_decode_32(&base58_encode(&value)), Ok(value));
    }
    let signature = [0x5a_u8; 64];
    assert_eq!(base58_decode_64(&base58_encode(&signature)), Ok(signature));
    for text in SOL_BLOCKED_RECIPIENTS {
        let bytes = base58_decode_32(text).unwrap();
        assert_eq!(base58_encode(&bytes), text);
    }
    for text in [
        "ComputeBudget111111111111111111111111111111",
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
        "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
        "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
        "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
    ] {
        assert_eq!(base58_encode(&base58_decode_32(text).unwrap()), text);
    }
}

#[test]
fn rejections() {
    let valid = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
    assert_eq!(base58_decode_32(""), Err(Base58Error::Empty));
    assert_eq!(
        base58_decode_32(&"1".repeat(31)),
        Err(Base58Error::BadLength)
    );
    assert_eq!(
        base58_decode_32(&"2".repeat(45)),
        Err(Base58Error::BadLength)
    );
    for bad in ['0', 'O', 'I', 'l', '+', ' '] {
        let mut text: String = valid.chars().take(20).collect();
        text.push(bad);
        text.extend(valid.chars().skip(21));
        assert_eq!(
            base58_decode_32(&text),
            Err(Base58Error::InvalidChar { pos: 20 }),
            "{bad:?}"
        );
    }
    // Non-ASCII at byte 20 (two UTF-8 bytes; one character dropped to keep 44 bytes).
    let mut text: String = valid.chars().take(20).collect();
    text.push('é');
    text.extend(valid.chars().skip(22));
    assert_eq!(text.len(), 44);
    assert_eq!(
        base58_decode_32(&text),
        Err(Base58Error::InvalidChar { pos: 20 })
    );
    // Leading '1' missing (→ 31 bytes) or added (→ 33 bytes).
    assert_eq!(
        base58_decode_32("1111111111111111111111111111111"),
        Err(Base58Error::BadLength)
    );
    assert_eq!(
        base58_decode_32("14uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM"),
        Err(Base58Error::WrongDecodedLength)
    );
    // 44 characters that decode to 33 bytes.
    assert_eq!(
        base58_decode_32(&"z".repeat(44)),
        Err(Base58Error::WrongDecodedLength)
    );
    assert_eq!(
        base58_decode_32("4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziof"),
        Err(Base58Error::WrongDecodedLength)
    );
    assert_eq!(base58_decode_64(valid), Err(Base58Error::BadLength));
    assert_eq!(
        base58_decode_64(&"2".repeat(89)),
        Err(Base58Error::BadLength)
    );
    assert_eq!(
        base58_decode_32(&format!(" {valid}")),
        Err(Base58Error::BadLength)
    );
}
