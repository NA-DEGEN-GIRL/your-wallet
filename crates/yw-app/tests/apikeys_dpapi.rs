//! V-DPAPI at the application level (spec/09 §4.1): the `apikeys.dpapi` plaintext (spec/04 §6.3)
//! sealed with the app's entropy round-trips through yw-win's DPAPI, and the wrong entropy or a
//! flipped byte is refused. Names, tokens and keys are fake.
//! (2026-11-17, spec/15 §11.4 S2 T1: split from `apikeys.rs`, whose plaintext tests moved to
//! yw-engine; this one stays because DPAPI is the Windows platform's seal.)

use yw_app::app::APIKEYS_ENTROPY;

const NAME: &str = "fake-node";
const TOKEN: &str = "FakeToken_0123456789abcdef";
const KEY: &str = "FakeAlchemyKey_0123456789";

fn entry(name: &str, value: &str) -> Vec<u8> {
    let mut out = vec![u8::try_from(name.len()).unwrap_or(u8::MAX)];
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    out
}

fn plaintext(entries: &[(String, String)]) -> Vec<u8> {
    let mut out = b"YWAPIK01".to_vec();
    out.push(u8::try_from(entries.len()).unwrap_or(u8::MAX));
    for (name, value) in entries {
        out.extend(entry(name, value));
    }
    out
}

fn long_url(tag: usize) -> String {
    let head = format!("https://h{tag}.example/");
    format!("{head}{}", "a".repeat(2_048 - head.len()))
}

fn full_set() -> Vec<(String, String)> {
    let mut entries = vec![
        ("tpl:quicknode".to_owned(), format!("{NAME}:{TOKEN}")),
        ("tpl:alchemy".to_owned(), KEY.to_owned()),
        ("llm".to_owned(), "local-model-key".to_owned()),
    ];
    let mut networks = vec![
        "eip155:1".to_owned(),
        "eip155:11155111".to_owned(),
        "eip155:999".to_owned(),
    ];
    networks.extend((0..32).map(|i| format!("eip155:{}", 10_000 + i)));
    networks.extend(
        [
            "solana:mainnet",
            "solana:devnet",
            "bitcoin:mainnet",
            "bitcoin:testnet4",
        ]
        .map(str::to_owned),
    );
    for (index, network) in networks.into_iter().enumerate() {
        entries.push((format!("rpc:{network}"), long_url(index)));
    }
    entries
}

#[test]
fn dpapi_round_trip_of_the_plaintext() {
    let bytes = plaintext(&full_set());
    let blob = yw_win::dpapi::protect(&bytes, APIKEYS_ENTROPY).unwrap();
    let plain = yw_win::dpapi::unprotect(&blob, APIKEYS_ENTROPY).unwrap();
    assert_eq!(plain.as_slice(), bytes.as_slice());
    assert!(yw_win::dpapi::unprotect(&blob, b"other").is_err());
    let mut tampered = blob;
    let last = tampered.len() - 1;
    tampered[last] ^= 0x80;
    assert!(yw_win::dpapi::unprotect(&tampered, APIKEYS_ENTROPY).is_err());
}
