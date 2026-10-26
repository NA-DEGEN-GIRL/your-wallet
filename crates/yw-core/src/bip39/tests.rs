//! BIP39 KAT and negative tests (spec/09 §3.2 B39-1–4, §4.1 V-6/V-7; spec/02 §11.2).
//! Zero-entropy cases port `archive/spec-v2.4:demo/sepolia-wallet/src/wallet_secret.rs:917-962`.

use sha2::{Digest, Sha256};
use yw_json::Limits;

use super::{Mnemonic, WordCount, wordlist};
use crate::bip32::Bip32Path;
use crate::bip32::xkey::{XKeyVersion, derive_xkey, encode_xkey};
use crate::error::KeyError;
use crate::hex;
use crate::password::Bip39Passphrase;

const TREZOR_EN: &str = include_str!("../../tests/vectors/bip39_trezor_en.json");
const WORDLIST_SHA256: &str = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";
const ABOUT: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn repeat_then(word: &str, count: usize, last: &str) -> String {
    let mut words = vec![word; count];
    words.push(last);
    words.join(" ")
}

#[test]
fn b39_1_trezor_vectors_round_trip_seed_and_master_xprv() {
    let root = yw_json::parse(TREZOR_EN.as_bytes(), &Limits::RESPONSE).unwrap();
    let english = root
        .as_object()
        .unwrap()
        .get("english")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(english.len(), 24);
    let passphrase = Bip39Passphrase::new("TREZOR").unwrap();
    let mut sizes = Vec::new();
    for vector in english {
        let mut fields = vector
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap());
        let (entropy_hex, phrase, seed_hex, xprv) = (
            fields.next().unwrap(),
            fields.next().unwrap(),
            fields.next().unwrap(),
            fields.next().unwrap(),
        );
        assert!(fields.next().is_none());
        let entropy = hex::decode(entropy_hex).unwrap();
        sizes.push(entropy.len());
        let from_entropy = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(from_entropy.phrase().as_str(), phrase);
        let parsed = Mnemonic::parse(phrase).unwrap();
        assert_eq!(parsed.entropy(), entropy.as_slice());
        let seed = parsed.to_seed(&passphrase);
        assert_eq!(hex::encode(seed.as_slice()), seed_hex);
        let master = derive_xkey(seed.as_slice(), &Bip32Path::master(), XKeyVersion::Xprv).unwrap();
        assert_eq!(encode_xkey(&master).as_str(), xprv);
    }
    sizes.sort_unstable();
    sizes.dedup();
    assert_eq!(sizes, [16, 24, 32]);
}

#[test]
fn b39_1_representative_values() {
    let trezor = Bip39Passphrase::new("TREZOR").unwrap();
    let about = Mnemonic::from_entropy(&[0; 16]).unwrap();
    assert_eq!(about.phrase().as_str(), ABOUT);
    assert_eq!(
        hex::encode(about.to_seed(&trezor).as_slice()),
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    );
    let zoo = Mnemonic::from_entropy(&[0xff; 16]).unwrap();
    assert_eq!(zoo.phrase().as_str(), repeat_then("zoo", 11, "wrong"));
    assert!(
        hex::encode(zoo.to_seed(&trezor).as_slice())
            .starts_with("ac27495480225222079d7be181583751")
    );
    let art = Mnemonic::from_entropy(&[0; 32]).unwrap();
    assert_eq!(art.phrase().as_str(), repeat_then("abandon", 23, "art"));
    assert!(
        hex::encode(art.to_seed(&trezor).as_slice())
            .starts_with("bda85446c68413707090a52022edd26a")
    );
    let ozone =
        Mnemonic::from_entropy(&hex::decode("9e885d952ad362caeb4efe34a8e91bd2").unwrap()).unwrap();
    assert_eq!(
        ozone.phrase().as_str(),
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"
    );
    let legal = Mnemonic::from_entropy(&[0x7f; 16]).unwrap();
    assert!(
        hex::encode(legal.to_seed(&trezor).as_slice())
            .starts_with("2e8905819b8723fe2c1d161860e5ee18")
    );
}

#[test]
fn b39_2_zero_entropy_covers_every_word_count() {
    for (len, words, last, count) in [
        (16, 11, "about", WordCount::W12),
        (20, 14, "address", WordCount::W15),
        (24, 17, "agent", WordCount::W18),
        (28, 20, "admit", WordCount::W21),
        (32, 23, "art", WordCount::W24),
    ] {
        let mnemonic = Mnemonic::from_entropy(&vec![0; len]).unwrap();
        let expected = repeat_then("abandon", words, last);
        assert_eq!(mnemonic.phrase().as_str(), expected);
        assert_eq!(mnemonic.word_count(), count);
        assert_eq!(count.words(), words + 1);
        assert_eq!(count.entropy_len(), len);
        let parsed = Mnemonic::parse(&expected).unwrap();
        assert_eq!(parsed.entropy(), vec![0; len].as_slice());
        assert_eq!(parsed.word_at(1).unwrap(), "abandon");
        assert_eq!(
            parsed.word_at(u8::try_from(words + 1).unwrap()).unwrap(),
            last
        );
        assert_eq!(parsed.word_at(0), Err(KeyError::Internal));
        assert_eq!(
            parsed.word_at(u8::try_from(words + 2).unwrap()),
            Err(KeyError::Internal)
        );
    }
    assert_eq!(
        Mnemonic::from_entropy(&[7; 17]).err(),
        Some(KeyError::InvalidEntropyLength)
    );
    assert_eq!(
        Mnemonic::from_entropy(&[]).err(),
        Some(KeyError::InvalidEntropyLength)
    );
}

#[test]
fn b39_3_empty_passphrase_seeds() {
    let empty = Bip39Passphrase::empty();
    assert_eq!(
        hex::encode(Mnemonic::parse(ABOUT).unwrap().to_seed(&empty).as_slice()),
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
    );
    assert_eq!(
        hex::encode(
            Mnemonic::from_entropy(&[0; 32])
                .unwrap()
                .to_seed(&empty)
                .as_slice()
        ),
        "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840"
    );
}

#[test]
fn b39_4_wordlist_integrity_and_structure() {
    let text = include_bytes!("english.txt");
    assert_eq!(text.len(), 13_116);
    assert_eq!(hex::encode(&Sha256::digest(text)), WORDLIST_SHA256);
    let list = wordlist().unwrap();
    assert_eq!(list.first(), Some(&"abandon"));
    assert_eq!(list.last(), Some(&"zoo"));
    assert!(
        list.windows(2)
            .all(|pair| pair.first().unwrap().as_bytes() < pair.last().unwrap().as_bytes())
    );
    assert!(
        list.iter()
            .all(|w| (3..=8).contains(&w.len()) && w.bytes().all(|b| b.is_ascii_lowercase()))
    );
    let mut prefixes: Vec<&str> = list.iter().map(|w| w.get(..4).unwrap_or(w)).collect();
    prefixes.sort_unstable();
    prefixes.dedup();
    assert_eq!(prefixes.len(), 2_048);
}

#[test]
fn v7_strict_parser_rejections() {
    let abandon12 = ["abandon"; 12].join(" ");
    let cases: Vec<(String, KeyError)> = vec![
        (format!(" {ABOUT}"), KeyError::MnemonicFormat),
        (format!("{ABOUT} "), KeyError::MnemonicFormat),
        (ABOUT.replacen(' ', "  ", 1), KeyError::MnemonicFormat),
        (ABOUT.replacen(' ', "\t", 1), KeyError::MnemonicFormat),
        (ABOUT.replacen(' ', "\n", 1), KeyError::MnemonicFormat),
        (ABOUT.replacen(' ', "\u{a0}", 1), KeyError::MnemonicFormat),
        (
            ABOUT.replacen("abandon", "Abandon", 1),
            KeyError::MnemonicFormat,
        ),
        (
            ABOUT.replacen("abandon", "\u{ff41}bandon", 1),
            KeyError::MnemonicFormat,
        ),
        ("a".repeat(257), KeyError::MnemonicFormat),
        (String::new(), KeyError::MnemonicWordCount),
        (["abandon"; 11].join(" "), KeyError::MnemonicWordCount),
        (["abandon"; 13].join(" "), KeyError::MnemonicWordCount),
        (["abandon"; 25].join(" "), KeyError::MnemonicWordCount),
        (
            ABOUT.replacen("abandon", "abandonn", 1),
            KeyError::MnemonicUnknownWord { position: 1 },
        ),
        (
            repeat_then("abandon", 10, "zzzz about"),
            KeyError::MnemonicUnknownWord { position: 11 },
        ),
        (abandon12, KeyError::MnemonicChecksum),
    ];
    for (phrase, expected) in cases {
        assert_eq!(
            Mnemonic::parse(&phrase).err(),
            Some(expected),
            "{expected:?}"
        );
    }
}

#[test]
fn v6_passphrase_changes_seed() {
    let mnemonic = Mnemonic::parse(ABOUT).unwrap();
    let plain = mnemonic.to_seed(&Bip39Passphrase::new("TREZOR").unwrap());
    let spaced = mnemonic.to_seed(&Bip39Passphrase::new(" TREZOR").unwrap());
    assert_ne!(plain.as_slice(), spaced.as_slice());
    let long = mnemonic.to_seed(&Bip39Passphrase::new(&"~".repeat(256)).unwrap());
    assert_ne!(long.as_slice(), plain.as_slice());
}

#[test]
fn generation_uses_32_bytes_and_debug_is_redacted() {
    let mut rng = crate::entropy::ScriptedRandom::new(&(0_u8..32).collect::<Vec<_>>());
    let mnemonic = Mnemonic::generate_with_rng(&mut rng).unwrap();
    assert_eq!(rng.consumed, 32);
    assert_eq!(mnemonic.word_count(), WordCount::W24);
    assert_eq!(
        mnemonic.entropy(),
        (0_u8..32).collect::<Vec<_>>().as_slice()
    );
    let rendered = format!("{mnemonic:?}");
    assert_eq!(rendered, "Mnemonic([REDACTED])");
    assert!(!rendered.contains("abandon"));
}
