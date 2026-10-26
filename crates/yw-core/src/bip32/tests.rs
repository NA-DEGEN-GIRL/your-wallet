//! BIP32 vectors 1–5 as full strings, path rules, CKD tweak rejections (spec/09 §3.3,
//! spec/02 §11.3). Ports the vector-1 public key checks of
//! `archive/spec-v2.4:crates/secret-core/src/bip32.rs:517-544`.

use core::str::FromStr;

use yw_json::Limits;

use super::path::{AccountIndex, BtcChain, BtcCoin, btc_path, evm_path};
use super::xkey::{XKeyVersion, decode_xkey, derive_xkey, encode_xkey, fingerprint};
use super::{Bip32Path, HARDENED, XPriv, ckd_from_il};
use crate::bip39::Mnemonic;
use crate::entropy::{OsRandom, secp_context};
use crate::error::KeyError;
use crate::hex;
use crate::password::Bip39Passphrase;

const BIP32_JSON: &str = include_str!("../../tests/vectors/bip32.json");
const ORDER_N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

fn field<'a>(object: &'a yw_json::Object, key: &str) -> &'a str {
    object.get(key).unwrap().as_str().unwrap()
}

#[test]
fn vectors_1_to_4_full_strings_and_round_trip() {
    let root = yw_json::parse(BIP32_JSON.as_bytes(), &Limits::RESPONSE).unwrap();
    let valid = root
        .as_object()
        .unwrap()
        .get("valid")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(valid.len(), 4);
    let mut paths = 0;
    for vector in valid {
        let vector = vector.as_object().unwrap();
        let seed = hex::decode(field(vector, "seed")).unwrap();
        for chain in vector.get("chains").unwrap().as_array().unwrap() {
            let chain = chain.as_object().unwrap();
            let path = Bip32Path::from_str(field(chain, "path")).unwrap();
            for (version, key) in [(XKeyVersion::Xprv, "xprv"), (XKeyVersion::Xpub, "xpub")] {
                let official = field(chain, key);
                let derived = derive_xkey(&seed, &path, version).unwrap();
                assert_eq!(encode_xkey(&derived).as_str(), official, "{path} {key}");
                let decoded = decode_xkey(official).unwrap();
                assert_eq!(decoded.version, version);
                assert_eq!(usize::from(decoded.depth), path.depth());
                assert_eq!(encode_xkey(&decoded).as_str(), official);
            }
            paths += 1;
        }
    }
    assert_eq!(paths, 17);
}

#[test]
fn vector_5_invalid_keys_rejected() {
    let root = yw_json::parse(BIP32_JSON.as_bytes(), &Limits::RESPONSE).unwrap();
    let invalid = root
        .as_object()
        .unwrap()
        .get("invalid")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(invalid.len(), 16);
    for entry in invalid {
        let mut fields = entry
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap());
        let (key, reason) = (fields.next().unwrap(), fields.next().unwrap());
        assert_eq!(
            decode_xkey(key).err(),
            Some(KeyError::InvalidExtendedKey),
            "{reason}"
        );
    }
}

#[test]
fn independent_chain_codes_private_keys_and_fingerprint() {
    let ctx = secp_context(&mut OsRandom).unwrap();
    let cases = [
        (
            "000102030405060708090a0b0c0d0e0f",
            "m",
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        ),
        (
            "000102030405060708090a0b0c0d0e0f",
            "m/0'",
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
        ),
        (
            "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
            "m",
            "01d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f",
            "00ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32",
        ),
        (
            "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
            "m/0'",
            "cdc0f06456a14876c898790e0b3b1a41c531170aec69da44ff7b7265bfe7743b",
            "00d948e9261e41362a688b916f297121ba6bfb2274a3575ac0e456551dfd7f7e",
        ),
        (
            "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
            "m/0'/1'",
            "a48ee6674c5264a237703fd383bccd9fad4d9378ac98ab05e6e7029b06360c0d",
            "3a2086edd7d9df86c3487a5905a1712a9aa664bce8cc268141e07549eaa8661d",
        ),
    ];
    for (seed, path, chain_code, private) in cases {
        let node = XPriv::from_seed(&hex::decode(seed).unwrap())
            .unwrap()
            .derive_path(&ctx, &path.parse().unwrap())
            .unwrap();
        assert_eq!(hex::encode(node.chain_code()), chain_code, "{path}");
        assert_eq!(hex::encode(node.key_bytes()), private, "{path}");
    }
    let master =
        XPriv::from_seed(&hex::decode("000102030405060708090a0b0c0d0e0f").unwrap()).unwrap();
    let public = master.public_key(&ctx).unwrap().serialize();
    assert_eq!(
        hex::encode(&public),
        "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
    );
    let child = master.derive_child(&ctx, HARDENED).unwrap();
    assert_eq!(
        hex::encode(&child.public_key(&ctx).unwrap().serialize()),
        "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"
    );
    assert_eq!(hex::encode(&fingerprint(&public)), "3442193e");
}

fn sub_be(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    let mut borrow = 0_i16;
    for ((slot, l), r) in out.iter_mut().zip(left).zip(right).rev() {
        let mut value = i16::from(*l) - i16::from(*r) - borrow;
        borrow = i16::from(value < 0);
        if value < 0 {
            value += 256;
        }
        *slot = u8::try_from(value).unwrap();
    }
    out
}

#[test]
fn derive_child_tweak_rejections() {
    let order: [u8; 32] = hex::decode_array(ORDER_N).unwrap();
    let parent = XPriv::from_seed(&[0x11; 32]).unwrap();
    let parent_key = *parent.key_bytes();
    assert_eq!(
        ckd_from_il(&parent_key, &order).err(),
        Some(KeyError::DerivationFailed)
    );
    let negated = sub_be(&order, &parent_key);
    assert_eq!(
        ckd_from_il(&parent_key, &negated).err(),
        Some(KeyError::DerivationFailed)
    );
    let mut one = [0_u8; 32];
    one[31] = 1;
    let mut almost = sub_be(&order, &parent_key);
    almost = sub_be(&almost, &one);
    // k_par + (n - k_par - 1) = n - 1: valid, no skipping or wrap-around to the next index.
    assert_eq!(
        ckd_from_il(&parent_key, &almost).unwrap().as_slice(),
        sub_be(&order, &one).as_slice()
    );
    assert_eq!(
        XPriv::from_seed(&[0; 15]).err(),
        Some(KeyError::InvalidEntropyLength)
    );
    assert_eq!(
        XPriv::from_seed(&[0; 65]).err(),
        Some(KeyError::InvalidEntropyLength)
    );
}

#[test]
fn path_parser_table() {
    for valid in [
        "m",
        "m/0",
        "m/44'/60'/0'/0/0",
        "m/2147483647'",
        "m/0/1/2/3/4/5/6/7/8/9",
    ] {
        let path = Bip32Path::from_str(valid).unwrap();
        assert_eq!(path.to_string(), valid);
    }
    for invalid in [
        "",
        "M/0",
        "m/",
        "m//0",
        "m/0/",
        "m/00",
        "m/01",
        "m/0h",
        "m/0H",
        "m/ 0",
        "m/2147483648",
        "m/-1",
        "m/+1",
        " m/0",
        "m/0 ",
        "m/0''",
        "m/'",
        "m/0/1/2/3/4/5/6/7/8/9/10",
        "m/99999999999",
    ] {
        assert_eq!(
            Bip32Path::from_str(invalid).err(),
            Some(KeyError::InvalidPath),
            "{invalid:?}"
        );
    }
    assert_eq!(
        evm_path(AccountIndex::new(7).unwrap()).to_string(),
        "m/44'/60'/0'/0/7"
    );
    assert_eq!(AccountIndex::new(999).unwrap().get(), 999);
    assert_eq!(AccountIndex::new(1000), Err(KeyError::InvalidAccountIndex));
    assert_eq!(
        btc_path(BtcCoin::Mainnet, BtcChain::Change, 5)
            .unwrap()
            .to_string(),
        "m/84'/0'/0'/1/5"
    );
    assert_eq!(
        btc_path(BtcCoin::Test, BtcChain::Receive, 0)
            .unwrap()
            .to_string(),
        "m/84'/1'/0'/0/0"
    );
    assert_eq!(
        btc_path(BtcCoin::Mainnet, BtcChain::Receive, HARDENED),
        Err(KeyError::InvalidPath)
    );
}

#[test]
fn bip84_private_derivation_public_keys() {
    let about = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = Mnemonic::parse(about)
        .unwrap()
        .to_seed(&Bip39Passphrase::empty());
    for (chain, index, expected) in [
        (
            BtcChain::Receive,
            0,
            "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
        ),
        (
            BtcChain::Receive,
            1,
            "03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77",
        ),
        (
            BtcChain::Change,
            0,
            "03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6",
        ),
    ] {
        let path = btc_path(BtcCoin::Mainnet, chain, index).unwrap();
        let node = derive_xkey(seed.as_slice(), &path, XKeyVersion::Xpub).unwrap();
        assert_eq!(hex::encode(node.key.as_slice()), expected, "{path}");
    }
}

#[test]
fn xkey_debug_is_redacted() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let parts = derive_xkey(&seed, &Bip32Path::master(), XKeyVersion::Tprv).unwrap();
    let rendered = format!("{parts:?}");
    assert_eq!(rendered, "XKeyParts([REDACTED])");
    assert!(encode_xkey(&parts).starts_with("tprv"));
    let node = XPriv::from_seed(&seed).unwrap();
    assert_eq!(format!("{node:?}"), "XPriv([REDACTED])");
}
