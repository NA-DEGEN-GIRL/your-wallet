//! Base58 against bitcoin/bitcoin `src/test/data/base58_encode_decode.json` (spec/09 §3.1).

use yw_core::codec::base58;
use yw_json::{Limits, Value};

const VECTORS: &str = include_str!("vectors/base58_encode_decode.json");

#[test]
fn bitcoin_core_vectors_round_trip() {
    let root = yw_json::parse(VECTORS.as_bytes(), &Limits::RESPONSE).unwrap();
    let vectors = root.as_array().unwrap();
    assert_eq!(vectors.len(), 21);
    for vector in vectors {
        let pair: Vec<&str> = vector
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(pair.len(), 2);
        let (hex_text, text) = (
            pair.first().copied().unwrap(),
            pair.last().copied().unwrap(),
        );
        // The file uses uppercase hex in a few rows; the core hex decoder is lowercase-only.
        let bytes = yw_core::hex::decode(&hex_text.to_ascii_lowercase()).unwrap();
        assert_eq!(base58::encode(&bytes), text, "{hex_text}");
        assert_eq!(base58::decode(text).unwrap(), bytes, "{text}");
    }
}

#[test]
fn base58check_wraps_the_payload() {
    let text = base58::encode_check(&[0x00; 21]);
    assert_eq!(text, "1111111111111111111114oLvT2");
    assert_eq!(base58::decode_check(&text).unwrap(), vec![0x00; 21]);
}
