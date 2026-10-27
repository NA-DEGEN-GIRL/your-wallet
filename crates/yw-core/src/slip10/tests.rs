//! SLIP-0010 Ed25519 vectors 1–2 (spec/09 §3.9, `tests/vectors/slip10_ed25519.json`), path
//! parsing, RFC 8032 §7.1 (`tests/vectors/rfc8032.json`) and the ed25519-dalek API properties
//! the wallet relies on (spec/07 §17.1, SOL-N4).

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use yw_json::{Limits, Value};

use super::{Slip10Path, SolKeySource, derive_node, sol_path};
use crate::bip32::HARDENED;
use crate::bip32::path::AccountIndex;
use crate::error::KeyError;
use crate::hex;

const SLIP10: &str = include_str!("../../tests/vectors/slip10_ed25519.json");
const RFC8032: &str = include_str!("../../tests/vectors/rfc8032.json");

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .as_object()
        .unwrap()
        .get(key)
        .unwrap()
        .as_str()
        .unwrap()
}

/// `m`, `m/0'`, … → hardened components (the vector notation).
fn components(path: &str) -> Vec<u32> {
    path.split('/')
        .skip(1)
        .map(|part| part.strip_suffix('\'').unwrap().parse::<u32>().unwrap() | HARDENED)
        .collect()
}

#[test]
fn slip10_ed25519_vectors_1_and_2() {
    let root = yw_json::parse(SLIP10.as_bytes(), &Limits::RESPONSE).unwrap();
    let mut checked = 0;
    for vector in root.as_array().unwrap() {
        let seed = hex::decode(text(vector, "seed")).unwrap();
        let chains = vector.as_object().unwrap().get("chains").unwrap();
        for chain in chains.as_array().unwrap() {
            let path = text(chain, "path");
            let node = derive_node(&seed, &components(path)).unwrap();
            assert_eq!(
                hex::encode(node.chain_code.as_slice()),
                text(chain, "chain_code"),
                "{path}"
            );
            assert_eq!(
                hex::encode(node.key.as_slice()),
                text(chain, "private"),
                "{path}"
            );
            let public = SigningKey::from_bytes(&node.key).verifying_key().to_bytes();
            assert_eq!(
                format!("00{}", hex::encode(&public)),
                text(chain, "public"),
                "{path}"
            );
            if path != "m" {
                let parsed: Slip10Path = path.parse().unwrap();
                assert_eq!(parsed.to_string(), path);
                assert_eq!(parsed.components(), components(path));
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 12);
}

#[test]
fn slip10_path_grammar() {
    for good in [
        "m/0'",
        "m/44'/501'/0'/0'",
        "m/2147483647'",
        "m/1'/2'/3'/4'/5'/6'/7'/8'/9'/10'",
    ] {
        assert_eq!(good.parse::<Slip10Path>().unwrap().to_string(), good);
    }
    for bad in [
        "m",
        "m/",
        "m/0",
        "m/44'/501'/0'/0",
        "m/0h",
        "m/0H",
        "M/0'",
        "m//0'",
        "m/00'",
        "m/01'",
        "m/2147483648'",
        "m/-1'",
        "m/ 0'",
        "m/1'/2'/3'/4'/5'/6'/7'/8'/9'/10'/11'",
    ] {
        assert_eq!(
            bad.parse::<Slip10Path>(),
            Err(KeyError::InvalidPath),
            "{bad}"
        );
    }
    assert_eq!(
        Slip10Path::from_components(vec![0]),
        Err(KeyError::InvalidPath)
    );
    assert_eq!(
        Slip10Path::from_components(Vec::new()),
        Err(KeyError::InvalidPath)
    );
    assert_eq!(
        derive_node(&[0; 16], &[0]).map(|_| ()),
        Err(KeyError::InvalidPath)
    );
    assert_eq!(
        sol_path(AccountIndex::new(7).unwrap()).to_string(),
        "m/44'/501'/7'/0'"
    );
}

#[test]
fn abandon_standard_seed_and_address() {
    let seed: [u8; 64] = hex::decode(
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
    )
    .unwrap()
    .try_into()
    .unwrap();
    let secret = SolKeySource::Standard(AccountIndex::ZERO)
        .ed25519_seed(&seed)
        .unwrap();
    assert_eq!(
        hex::encode(secret.as_slice()),
        "37df573b3ac4ad5b522e064e25b63ea16bcbe79d449e81a0268d1047948bb445"
    );
    let public = crate::sol::keys::public_key(&secret);
    assert_eq!(
        crate::codec::base58::encode(&public),
        "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
    );
    assert_eq!(
        SolKeySource::SolletLegacy {
            wallet: 0,
            account: 0
        }
        .ed25519_seed(&seed)
        .map(|_| ()),
        Err(KeyError::InvalidPath)
    );
}

#[test]
fn key_source_tags_and_parts_round_trip() {
    let i = AccountIndex::new(5).unwrap();
    for source in [
        SolKeySource::Standard(i),
        SolKeySource::Bip44Account(i),
        SolKeySource::Bip44Root,
        SolKeySource::RawSeed,
        SolKeySource::SolletLegacy {
            wallet: 1,
            account: 2,
        },
    ] {
        let (a, b) = source.params();
        assert_eq!(SolKeySource::from_parts(source.tag(), a, b), Ok(source));
    }
    assert!(SolKeySource::from_parts(0, 0, 0).is_err());
    assert!(SolKeySource::from_parts(6, 0, 0).is_err());
    assert!(SolKeySource::from_parts(1, 1_000, 0).is_err());
    assert!(SolKeySource::from_parts(1, 0, 1).is_err());
    assert!(SolKeySource::from_parts(3, 1, 0).is_err());
    assert!(SolKeySource::from_parts(4, 0, 9).is_err());
    assert!(SolKeySource::from_parts(5, HARDENED, 0).is_err());
}

#[test]
fn rfc8032_section_7_1_vectors() {
    let root = yw_json::parse(RFC8032.as_bytes(), &Limits::RESPONSE).unwrap();
    let tests = root
        .as_object()
        .unwrap()
        .get("tests")
        .unwrap()
        .as_array()
        .unwrap();
    let names: Vec<&str> = tests.iter().map(|test| text(test, "test")).collect();
    assert_eq!(names, ["1", "2", "3", "1024", "SHA(abc)"]);
    for test in tests {
        let secret: [u8; 32] = hex::decode(text(test, "secret_key"))
            .unwrap()
            .try_into()
            .unwrap();
        let message = hex::decode(text(test, "message")).unwrap();
        let key = SigningKey::from_bytes(&secret);
        let public = key.verifying_key();
        assert_eq!(hex::encode(&public.to_bytes()), text(test, "public_key"));
        let signature = key.sign(&message).to_bytes();
        assert_eq!(
            hex::encode(&signature),
            text(test, "signature"),
            "{}",
            text(test, "test")
        );
        assert!(crate::sol::keys::verify_strict(
            &public.to_bytes(),
            &message,
            &signature
        ));
        let mut tampered = signature;
        tampered[63] ^= 0x01;
        assert!(!crate::sol::keys::verify_strict(
            &public.to_bytes(),
            &message,
            &tampered
        ));
    }
}

/// SOL-N4: a 64-byte keypair whose public half does not match is refused by the library (the
/// wallet never uses this API; it never takes a public key next to a secret).
#[test]
fn keypair_bytes_with_wrong_public_half_are_rejected() {
    let secret = [7_u8; 32];
    let other = SigningKey::from_bytes(&[8_u8; 32])
        .verifying_key()
        .to_bytes();
    let mut keypair = [0_u8; 64];
    keypair[..32].copy_from_slice(&secret);
    keypair[32..].copy_from_slice(&other);
    assert!(SigningKey::from_keypair_bytes(&keypair).is_err());
    keypair[32..].copy_from_slice(&SigningKey::from_bytes(&secret).verifying_key().to_bytes());
    assert!(SigningKey::from_keypair_bytes(&keypair).is_ok());
    // verify_strict rejects a small-order public key that plain `verify` would accept.
    let identity = {
        let mut bytes = [0_u8; 32];
        bytes[0] = 1;
        bytes
    };
    let key = VerifyingKey::from_bytes(&identity).unwrap();
    let signature = Signature::from_bytes(&[0; 64]);
    assert!(key.verify_strict(b"", &signature).is_err());
}
