//! Imported-key parsers (spec/02 §11.9): WIF vectors from the Bitcoin wiki and BIP49/BIP84
//! (abandon mnemonic), BIP173 and BIP86 addresses, Solana keypairs built from the RFC 8032 test 1
//! seed and the spec/07 §17.1 abandon seed, and the rejection tables. Public test vectors only.

use secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey};

use super::sol::{encode_keypair, parse_sol_secret};
use super::{ImportChain, ImportKey, ImportPreview, ImportSpec};
use crate::btc::account::{BtcAccountId, BtcPubKey, ScriptType, kind_for_key};
use crate::btc::address::{ScriptKind, encode_address};
use crate::btc::network::BtcNetwork;
use crate::btc::taproot::output_key;
use crate::codec::base58;
use crate::codec::wif::{encode_wif_for_tests, parse_wif};
use crate::error::KeyError;
use crate::hex;

/// Bitcoin wiki "Wallet import format" example secret.
const WIKI_SECRET: &str = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
const WIKI_WIF_UNCOMPRESSED: &str = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
const WIKI_WIF_COMPRESSED: &str = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617";
/// Secret 1 (public key = G) in the four WIF forms.
const ONE_WIF_MAIN_COMPRESSED: &str = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
const ONE_WIF_MAIN_UNCOMPRESSED: &str = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf";
const ONE_WIF_TEST_COMPRESSED: &str = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";
const ONE_WIF_TEST_UNCOMPRESSED: &str = "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgwmaKkrx";
/// BIP49 test vector: abandon mnemonic, testnet `m/49'/1'/0'/0/0`.
const BIP49_WIF: &str = "cULrpoZGXiuC19Uhvykx7NugygA3k86b3hmdCeyvHYQZSxojGyXJ";
const BIP49_ADDRESS: &str = "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2";
/// BIP84 test vector: abandon mnemonic, `m/84'/0'/0'/0/0`.
const BIP84_WIF: &str = "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d";
const BIP84_ADDRESS: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
/// RFC 8032 test 1.
const RFC8032_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const RFC8032_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
/// spec/07 §17.1: abandon mnemonic `m/44'/501'/0'/0'`.
const ABANDON_SOL_SEED: &str = "37df573b3ac4ad5b522e064e25b63ea16bcbe79d449e81a0268d1047948bb445";
const ABANDON_SOL_ADDRESS: &str = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";

fn bytes32(text: &str) -> [u8; 32] {
    hex::decode_array::<32>(text).unwrap()
}

fn btc_of(preview: ImportPreview) -> Option<super::BtcKeyInfo> {
    match preview {
        ImportPreview::Btc(info) => Some(info),
        ImportPreview::Evm(_) | ImportPreview::Sol(_) => None,
    }
}

fn sol_of(preview: &ImportPreview) -> Option<String> {
    match preview {
        ImportPreview::Sol(address) => Some(address.to_base58()),
        ImportPreview::Evm(_) | ImportPreview::Btc(_) => None,
    }
}

fn evm_of(preview: &ImportPreview) -> Option<String> {
    match preview {
        ImportPreview::Evm(address) => Some(address.to_checksum()),
        ImportPreview::Sol(_) | ImportPreview::Btc(_) => None,
    }
}

fn btc_preview(text: &str, script: ScriptType) -> super::BtcKeyInfo {
    btc_of(
        ImportKey::parse(ImportSpec::Btc(script), text)
            .unwrap()
            .preview()
            .unwrap(),
    )
    .unwrap()
}

fn secret_one() -> [u8; 32] {
    let mut one = [0_u8; 32];
    *one.last_mut().unwrap() = 1;
    one
}

fn prefix(text: &str, len: usize) -> &str {
    text.get(..len).unwrap()
}

fn keypair_base58(seed: &[u8; 32], public: &[u8; 32]) -> String {
    let mut pair = seed.to_vec();
    pair.extend_from_slice(public);
    base58::encode(&pair)
}

fn keypair_json(seed: &[u8; 32], public: &[u8; 32], separator: &str) -> String {
    let numbers: Vec<String> = seed
        .iter()
        .chain(public.iter())
        .map(u8::to_string)
        .collect();
    format!("[{}]", numbers.join(separator))
}

// ---------------------------------------------------------------- WIF

#[test]
fn wif_wiki_vectors_round_trip() {
    let secret = bytes32(WIKI_SECRET);
    for (text, compressed) in [(WIKI_WIF_UNCOMPRESSED, false), (WIKI_WIF_COMPRESSED, true)] {
        let key = parse_wif(text).unwrap();
        assert_eq!(**key.secret(), secret);
        assert_eq!(key.compressed(), compressed);
        assert_eq!(key.network(), BtcNetwork::Mainnet);
        assert_eq!(
            encode_wif_for_tests(&secret, compressed, BtcNetwork::Mainnet),
            text
        );
    }
    let one = secret_one();
    for (text, compressed, network) in [
        (ONE_WIF_MAIN_COMPRESSED, true, BtcNetwork::Mainnet),
        (ONE_WIF_MAIN_UNCOMPRESSED, false, BtcNetwork::Mainnet),
        (ONE_WIF_TEST_COMPRESSED, true, BtcNetwork::Testnet4),
        (ONE_WIF_TEST_UNCOMPRESSED, false, BtcNetwork::Testnet4),
    ] {
        let key = parse_wif(text).unwrap();
        assert_eq!(**key.secret(), one, "{text}");
        assert_eq!(key.compressed(), compressed, "{text}");
        assert_eq!(key.network(), network, "{text}");
        assert_eq!(encode_wif_for_tests(&one, compressed, network), text);
    }
    // Surrounding whitespace is ignored; the debug output is redacted.
    let padded = format!(" \t{WIKI_WIF_COMPRESSED}\r\n");
    let key = parse_wif(&padded).unwrap();
    assert_eq!(format!("{key:?}"), "WifKey([REDACTED])");
}

#[test]
fn wif_rejections() {
    let order = bytes32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    let check = |payload: &[u8]| base58::encode_check(payload);
    let mut with_suffix = vec![0x80];
    with_suffix.extend_from_slice(&bytes32(WIKI_SECRET));
    with_suffix.push(0x02);
    let mut wrong_version = vec![0x00];
    wrong_version.extend_from_slice(&bytes32(WIKI_SECRET));
    wrong_version.push(0x01);
    let mut zero = vec![0x80];
    zero.extend_from_slice(&[0; 32]);
    zero.push(0x01);
    let mut too_big = vec![0x80];
    too_big.extend_from_slice(&order);
    too_big.push(0x01);
    let mut flipped = WIKI_WIF_COMPRESSED.to_owned();
    flipped.pop();
    flipped.push('8');
    let cases: Vec<(&str, String)> = vec![
        ("checksum", flipped),
        ("short", prefix(WIKI_WIF_COMPRESSED, 50).to_owned()),
        ("long", format!("{WIKI_WIF_COMPRESSED}1")),
        ("bad char", WIKI_WIF_COMPRESSED.replacen('K', "0", 1)),
        ("non-ascii", format!("{}é", prefix(WIKI_WIF_COMPRESSED, 50))),
        ("suffix 02", check(&with_suffix)),
        ("version 00", check(&wrong_version)),
        ("zero", check(&zero)),
        ("order", check(&too_big)),
        ("empty", String::new()),
        ("hex", WIKI_SECRET.to_owned()),
    ];
    for (label, text) in cases {
        assert_eq!(parse_wif(&text).err(), Some(KeyError::WifFormat), "{label}");
    }
}

#[test]
fn btc_imported_addresses_match_bip_vectors() {
    // BIP84: native segwit, mainnet.
    let info = btc_preview(BIP84_WIF, ScriptType::P2wpkh);
    assert_eq!(info.address, BIP84_ADDRESS);
    assert_eq!(info.network, BtcNetwork::Mainnet);
    assert_eq!(
        hex::encode(info.public_key.as_bytes()),
        "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
    );
    // Its Bitcoin account: one imported single key with the same address (spec/08 §3.5).
    let account = info.account_key([0x42; 16]).unwrap();
    assert_eq!(account.id(), BtcAccountId::Imported { id: [0x42; 16] });
    assert_eq!(
        account
            .address(
                BtcNetwork::Mainnet,
                crate::bip32::path::BtcChain::Receive,
                0
            )
            .unwrap()
            .as_str(),
        BIP84_ADDRESS
    );
    // BIP49: nested segwit, testnet WIF → testnet4 address prefix `2`.
    let info = btc_preview(BIP49_WIF, ScriptType::P2shP2wpkh);
    assert_eq!(info.address, BIP49_ADDRESS);
    assert_eq!(info.network, BtcNetwork::Testnet4);
    // Secret 1 (= G): P2PKH compressed/uncompressed, BIP173 P2WPKH on both networks.
    for (wif, script, expected) in [
        (
            ONE_WIF_MAIN_COMPRESSED,
            ScriptType::P2pkh,
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
        ),
        (
            ONE_WIF_MAIN_UNCOMPRESSED,
            ScriptType::P2pkh,
            "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
        ),
        (
            ONE_WIF_TEST_COMPRESSED,
            ScriptType::P2pkh,
            "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r",
        ),
        (
            ONE_WIF_MAIN_COMPRESSED,
            ScriptType::P2wpkh,
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        ),
        (
            ONE_WIF_TEST_COMPRESSED,
            ScriptType::P2wpkh,
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
        ),
    ] {
        assert_eq!(btc_preview(wif, script).address, expected, "{wif}");
    }
    let uncompressed = btc_preview(ONE_WIF_MAIN_UNCOMPRESSED, ScriptType::P2pkh);
    assert_eq!(uncompressed.public_key.as_bytes().len(), 65);
    assert!(!uncompressed.compressed);
    assert!(matches!(
        uncompressed.public_key,
        BtcPubKey::Uncompressed(_)
    ));
    // An uncompressed key is P2PKH only.
    for script in [ScriptType::P2shP2wpkh, ScriptType::P2wpkh, ScriptType::P2tr] {
        assert_eq!(
            ImportKey::parse(ImportSpec::Btc(script), ONE_WIF_MAIN_UNCOMPRESSED).err(),
            Some(KeyError::WifUncompressedScript),
            "{script:?}"
        );
    }
}

#[test]
fn bip86_taproot_output_key_and_address() {
    // BIP86 test vector (abandon mnemonic, m/86'/0'/0'/0/0): internal key → output key → address,
    // through the shared Taproot code (`btc::taproot::output_key`, `btc::account::kind_for_key`).
    let ctx = Secp256k1::verification_only();
    let x = bytes32("cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115");
    let internal = XOnlyPublicKey::from_byte_array(x).unwrap();
    let output = output_key(&ctx, &internal, None).unwrap().serialize();
    assert_eq!(
        hex::encode(&output),
        "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
    );
    assert_eq!(
        encode_address(&ScriptKind::P2tr(output), BtcNetwork::Mainnet),
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
    );
    // The even- and odd-y lifts of the same x give the same output key (x-only internal key).
    for prefix in [0x02_u8, 0x03] {
        let mut compressed = vec![prefix];
        compressed.extend_from_slice(&x);
        assert!(PublicKey::from_slice(&compressed).is_ok());
        assert_eq!(
            kind_for_key(
                &ctx,
                ScriptType::P2tr,
                &BtcPubKey::parse(&compressed).unwrap()
            )
            .unwrap(),
            ScriptKind::P2tr(output)
        );
    }
    // And an imported key used as P2TR (bc1p…, 62 characters) gets the same address its account
    // derives.
    let info = btc_preview(BIP84_WIF, ScriptType::P2tr);
    assert!(info.address.starts_with("bc1p") && info.address.len() == 62);
    assert_eq!(
        encode_address(
            &kind_for_key(&ctx, ScriptType::P2tr, &info.public_key).unwrap(),
            BtcNetwork::Mainnet
        ),
        info.address
    );
}

#[test]
fn script_type_codes_and_names() {
    // The vault record byte is the account type's stable code (spec/02 §4.6 tag 4).
    for kind in ScriptType::CHOICES {
        assert_eq!(ScriptType::from_code(kind.code()), Some(kind));
        assert_eq!(ScriptType::parse_json_name(kind.json_name()), Some(kind));
    }
    assert_eq!(ScriptType::P2pkh.code(), 1);
    assert_eq!(ScriptType::P2tr.code(), 4);
    assert_eq!(ScriptType::from_code(0), None);
    assert_eq!(ScriptType::from_code(5), None);
    assert_eq!(ScriptType::parse_json_name("P2WPKH"), None);
}

// ---------------------------------------------------------------- Solana

#[test]
fn solana_keypair_formats_parse_to_the_same_key() {
    let seed = bytes32(RFC8032_SEED);
    let public = bytes32(RFC8032_PUBLIC);
    let base58_text = keypair_base58(&seed, &public);
    for text in [
        base58_text.clone(),
        format!("  {base58_text}\n"),
        keypair_json(&seed, &public, ","),
        keypair_json(&seed, &public, ", "),
        format!("\n{}\n", keypair_json(&seed, &public, ",\n  ")),
    ] {
        let parsed = parse_sol_secret(&text).unwrap();
        assert_eq!(*parsed.seed, seed);
        assert_eq!(parsed.public, public);
    }
    // Reveal gives the base58 keypair back (Phantom import format).
    assert_eq!(encode_keypair(&seed, &public).expose(), base58_text);
    // The spec/07 §17.1 seed imports as its known address.
    let abandon_seed = bytes32(ABANDON_SOL_SEED);
    let abandon_public = base58::base58_decode_32(ABANDON_SOL_ADDRESS).unwrap();
    let key = ImportKey::parse(
        ImportSpec::Sol,
        &keypair_base58(&abandon_seed, &abandon_public),
    )
    .unwrap();
    assert_eq!(key.chain(), ImportChain::Sol);
    assert_eq!(
        sol_of(&key.preview().unwrap()).as_deref(),
        Some(ABANDON_SOL_ADDRESS)
    );
    assert_eq!(format!("{key:?}"), "ImportKey(Sol, [REDACTED])");
}

#[test]
fn solana_rejections() {
    let seed = bytes32(RFC8032_SEED);
    let public = bytes32(RFC8032_PUBLIC);
    let abandon_public = base58::base58_decode_32(ABANDON_SOL_ADDRESS).unwrap();
    let mut json63: Vec<String> = seed
        .iter()
        .chain(public.iter())
        .map(u8::to_string)
        .collect();
    json63.pop();
    let mut json_leading_zero = keypair_json(&seed, &public, ",");
    json_leading_zero = json_leading_zero.replacen('[', "[0", 1);
    let cases: Vec<(&str, String, KeyError)> = vec![
        (
            "address",
            ABANDON_SOL_ADDRESS.to_owned(),
            KeyError::SolKeyIsAddress,
        ),
        (
            "mismatch",
            keypair_base58(&seed, &abandon_public),
            KeyError::SolKeyMismatch,
        ),
        (
            "json mismatch",
            keypair_json(&seed, &abandon_public, ","),
            KeyError::SolKeyMismatch,
        ),
        (
            "seed only",
            base58::encode(&[7_u8; 33]),
            KeyError::SolKeyFormat,
        ),
        (
            "65 bytes",
            base58::encode(&[7_u8; 65]),
            KeyError::SolKeyFormat,
        ),
        (
            "json 63",
            format!("[{}]", json63.join(",")),
            KeyError::SolKeyFormat,
        ),
        (
            "json 256",
            "[256".to_owned() + &",1".repeat(63) + "]",
            KeyError::SolKeyFormat,
        ),
        (
            "json negative",
            "[-1".to_owned() + &",1".repeat(63) + "]",
            KeyError::SolKeyFormat,
        ),
        (
            "json leading zero",
            json_leading_zero,
            KeyError::SolKeyFormat,
        ),
        (
            "json empty item",
            "[1,,2]".to_owned(),
            KeyError::SolKeyFormat,
        ),
        ("json open", "[1,2".to_owned(), KeyError::SolKeyFormat),
        ("base58 bad char", "0OIl".repeat(22), KeyError::SolKeyFormat),
        ("too long", "1".repeat(641), KeyError::SolKeyFormat),
        ("non-ascii", "é".to_owned(), KeyError::SolKeyFormat),
        ("empty", "   ".to_owned(), KeyError::SolKeyFormat),
        ("hex", RFC8032_SEED.to_owned(), KeyError::SolKeyFormat),
    ];
    for (label, text, expected) in cases {
        assert_eq!(
            ImportKey::parse(ImportSpec::Sol, &text).err(),
            Some(expected),
            "{label}"
        );
    }
}

// ---------------------------------------------------------------- EVM

#[test]
fn evm_import_trims_and_previews_the_known_address() {
    let mut one = "0".repeat(63);
    one.push('1');
    for text in [one.clone(), format!("0x{one}"), format!(" 0x{one}\n")] {
        let key = ImportKey::parse(ImportSpec::Evm, &text).unwrap();
        assert_eq!(
            evm_of(&key.preview().unwrap()).as_deref(),
            Some("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf")
        );
    }
    for text in ["0X".to_owned() + &one, "0".repeat(64), "é".to_owned()] {
        assert_eq!(
            ImportKey::parse(ImportSpec::Evm, &text).err(),
            Some(KeyError::InvalidPrivateKey),
            "{text}"
        );
    }
}
