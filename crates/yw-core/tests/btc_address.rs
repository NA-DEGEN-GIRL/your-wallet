//! Address policy (spec/08 §6.1, §6.3, §13, §14.1; spec/09 §3.10, §4.4 BTC-N4): the full spec/08
//! §14.1 address table, BIP350 address vectors (valid 8, invalid 15) through `parse_address`,
//! Bitcoin Core `key_io_valid.json` / `key_io_invalid.json` (commit
//! `2b5b6fe231ff45a09d9e24411e4420d51ed45cab`), canonical round trips, the rule order of the
//! decision table, script ↔ kind conversion and the fixed error texts.

use yw_core::btc::address::{
    AddressError, BtcAddress, ScriptKind, encode_address, hash160, kind_from_script, parse_address,
    script_pubkey,
};
use yw_core::btc::network::BtcNetwork;
use yw_core::codec::base58;
use yw_core::hex;
use yw_json::{Limits, Value};

const KEY_IO_VALID: &str = include_str!("vectors/btc/key_io_valid.json");
const KEY_IO_INVALID: &str = include_str!("vectors/btc/key_io_invalid.json");

use BtcNetwork::{Mainnet, Testnet4};

fn spk_hex(kind: &ScriptKind) -> String {
    hex::encode(&script_pubkey(kind))
}

fn both() -> [BtcNetwork; 2] {
    [Mainnet, Testnet4]
}

fn trimmed_canonical(text: &str, kind: &ScriptKind) -> String {
    match kind {
        ScriptKind::P2pkh(_) | ScriptKind::P2sh(_) => text.to_owned(),
        _ => text.to_ascii_lowercase(),
    }
}

/// Parses on `net`, then checks that the canonical encoding parses back to the same kind.
fn parse_round_trip(text: &str, net: BtcNetwork) -> Result<ScriptKind, AddressError> {
    let kind = parse_address(text, net)?;
    let encoded = encode_address(&kind, net);
    assert_eq!(encoded, trimmed_canonical(text.trim(), &kind), "{text}");
    assert_eq!(parse_address(&encoded, net), Ok(kind), "{text}");
    Ok(kind)
}

/// The spec/08 §14.1 address table. Results are for the wallet of the string's own network;
/// on the other network `bc`/`tb` and base58 strings are always `WrongNetwork`.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one row per spec/08 §14.1 table entry"
)]
fn spec_address_table() {
    let ok = [
        (
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
            Mainnet,
            "0014751e76e8199196d454941c45d1b3a323f1433bd6",
        ),
        (
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            Testnet4,
            "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
        ),
        (
            "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
            Testnet4,
            "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
        ),
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            Mainnet,
            "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ),
        (
            "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
            Mainnet,
            "76a91465a16059864a2fdbc7c99a4723a8395bc6f188eb88ac",
        ),
        (
            "3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou",
            Mainnet,
            "a91474f209f6ea907e2ea48f74fae05782ae8a66525787",
        ),
        (
            "mo9ncXisMeAoXwqcV5EWuyncbmCcQN4rVs",
            Testnet4,
            "76a91453c0307d6851aa0ce7825ba883c6bd9ad242b48688ac",
        ),
        (
            "2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br",
            Testnet4,
            "a9146349a418fc4578d10a372b54b45c280cc8c4382f87",
        ),
    ];
    for (text, net, spk) in ok {
        let kind = parse_round_trip(text, net).unwrap();
        assert_eq!(spk_hex(&kind), spk, "{text}");
        assert_eq!(kind_from_script(&script_pubkey(&kind)), Some(kind));
        assert_eq!(
            parse_address(text, net.other()),
            Err(AddressError::WrongNetwork),
            "{text}"
        );
    }
    let rejected: [(&str, BtcNetwork, AddressError); 23] = [
        (
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
            Mainnet,
            AddressError::InvalidProgramLength,
        ),
        (
            "BC1SW50QGDZ25J",
            Mainnet,
            AddressError::UnsupportedWitnessVersion,
        ),
        (
            "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
            Mainnet,
            AddressError::UnsupportedWitnessVersion,
        ),
        ("bc1pfeessrawgf", Mainnet, AddressError::PayToAnchor),
        ("tb1pfees9rn5nz", Testnet4, AddressError::PayToAnchor),
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
            Mainnet,
            AddressError::WrongChecksumVariant,
        ),
        (
            "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
            Testnet4,
            AddressError::WrongChecksumVariant,
        ),
        (
            "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
            Mainnet,
            AddressError::WrongChecksumVariant,
        ),
        (
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
            Mainnet,
            AddressError::WrongChecksumVariant,
        ),
        (
            "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
            Testnet4,
            AddressError::WrongChecksumVariant,
        ),
        (
            "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
            Mainnet,
            AddressError::InvalidCharacter,
        ),
        ("bc1pw5dgrnzv", Mainnet, AddressError::InvalidProgramLength),
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
            Mainnet,
            AddressError::InvalidProgramLength,
        ),
        (
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            Mainnet,
            AddressError::InvalidProgramLength,
        ),
        (
            "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
            Testnet4,
            AddressError::MixedCase,
        ),
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
            Mainnet,
            AddressError::InvalidPadding,
        ),
        (
            "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
            Testnet4,
            AddressError::InvalidPadding,
        ),
        (
            "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
            Mainnet,
            AddressError::InvalidWitnessVersion,
        ),
        ("bc1gmk9yu", Mainnet, AddressError::InvalidWitnessVersion),
        (
            "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
            Mainnet,
            AddressError::NotBitcoinAddress,
        ),
        (
            "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
            Testnet4,
            AddressError::NotBitcoinAddress,
        ),
        (
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
            Mainnet,
            AddressError::WrongChecksumVariant,
        ),
        (
            "BC1SW50QA3JX3S",
            Mainnet,
            AddressError::WrongChecksumVariant,
        ),
    ];
    for (text, net, expected) in rejected {
        assert_eq!(parse_address(text, net), Err(expected), "{text}");
        let lower = text.to_ascii_lowercase();
        if lower.starts_with("bc1") || lower.starts_with("tb1") {
            assert_eq!(
                parse_address(text, net.other()),
                Err(AddressError::WrongNetwork),
                "{text}"
            );
        }
    }
}

/// BIP350 "valid segwit addresses" (8) and "invalid" (15) through the policy parser.
#[test]
#[expect(clippy::too_many_lines, reason = "the BIP350 address lists")]
fn bip350_address_vectors() {
    let valid: [(&str, Result<&str, AddressError>); 8] = [
        (
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
            Ok("0014751e76e8199196d454941c45d1b3a323f1433bd6"),
        ),
        (
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            Ok("00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
        ),
        (
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
            Err(AddressError::InvalidProgramLength),
        ),
        (
            "BC1SW50QGDZ25J",
            Err(AddressError::UnsupportedWitnessVersion),
        ),
        (
            "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
            Err(AddressError::UnsupportedWitnessVersion),
        ),
        (
            "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
            Ok("0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
        ),
        (
            "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
            Ok("5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
        ),
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            Ok("512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        ),
    ];
    for (text, expected) in valid {
        let net = if text.to_ascii_lowercase().starts_with("bc") {
            Mainnet
        } else {
            Testnet4
        };
        let result = parse_address(text, net).map(|kind| spk_hex(&kind));
        assert_eq!(result, expected.map(str::to_owned), "{text}");
    }
    let invalid: [(&str, AddressError); 15] = [
        (
            "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
            AddressError::NotBitcoinAddress,
        ),
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
            AddressError::WrongChecksumVariant,
        ),
        (
            "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
            AddressError::WrongChecksumVariant,
        ),
        (
            "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
            AddressError::WrongChecksumVariant,
        ),
        (
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
            AddressError::WrongChecksumVariant,
        ),
        (
            "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
            AddressError::WrongChecksumVariant,
        ),
        (
            "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
            AddressError::InvalidCharacter,
        ),
        (
            "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
            AddressError::InvalidWitnessVersion,
        ),
        ("bc1pw5dgrnzv", AddressError::InvalidProgramLength),
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
            AddressError::InvalidProgramLength,
        ),
        (
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            AddressError::InvalidProgramLength,
        ),
        (
            "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
            AddressError::MixedCase,
        ),
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
            AddressError::InvalidPadding,
        ),
        (
            "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
            AddressError::InvalidPadding,
        ),
        ("bc1gmk9yu", AddressError::InvalidWitnessVersion),
    ];
    for (text, expected) in invalid {
        let net = if text.to_ascii_lowercase().starts_with("tb") {
            Testnet4
        } else {
            Mainnet
        };
        assert_eq!(parse_address(text, net), Err(expected), "{text}");
    }
}

fn json(text: &str) -> Option<Value> {
    yw_json::parse(text.as_bytes(), &Limits::RESPONSE).ok()
}

/// The wallet network a `key_io` `chain` maps to (spec/08 §14.1): `main` → mainnet, `testnet4`
/// (the spec's `test`) and `signet` → testnet4; `regtest` → `Ok(None)` (checked separately).
fn wallet_for(chain: &str) -> Result<Option<BtcNetwork>, String> {
    match chain {
        "main" => Ok(Some(Mainnet)),
        "testnet4" | "test" | "signet" => Ok(Some(Testnet4)),
        "regtest" => Ok(None),
        other => Err(format!("unknown chain {other}")),
    }
}

/// Expected policy result for a `key_io` destination script (5 kinds or the §6.3 rejection).
fn expected_for_script(spk: &[u8]) -> Result<Vec<u8>, AddressError> {
    match spk {
        [0x51, 0x20, key @ ..] => {
            if <[u8; 32]>::try_from(key)
                .is_ok_and(|key| secp256k1::XOnlyPublicKey::from_byte_array(key).is_ok())
            {
                Ok(spk.to_vec())
            } else {
                Err(AddressError::InvalidTaprootKey)
            }
        }
        [0x51, 0x02, 0x4e, 0x73] => Err(AddressError::PayToAnchor),
        [0x51, ..] => Err(AddressError::InvalidProgramLength),
        [0x52..=0x60, ..] => Err(AddressError::UnsupportedWitnessVersion),
        _ => {
            assert!(kind_from_script(spk).is_some(), "{}", hex::encode(spk));
            Ok(spk.to_vec())
        }
    }
}

/// `key_io_valid` (spec/08 §14.1): non-private entries give the same scriptPubKey or the §6.3
/// rejection on their wallet, `WrongNetwork` on the other one; private keys are always
/// `LooksLikePrivateKey`; `tryCaseFlip` entries behave the same in uppercase.
#[test]
fn key_io_valid() {
    let root = json(KEY_IO_VALID).unwrap();
    let entries = root.as_array().unwrap();
    assert_eq!(entries.len(), 70);
    let (mut addresses, mut keys) = (0, 0);
    for entry in entries {
        let entry = entry.as_array().unwrap();
        let text = entry[0].as_str().unwrap();
        let payload = hex::decode(entry[1].as_str().unwrap()).unwrap();
        let meta = entry[2].as_object().unwrap();
        let chain = meta.get("chain").unwrap().as_str().unwrap();
        let is_private = meta.get("isPrivkey").unwrap().as_bool().unwrap();
        let case_flip = meta
            .get("tryCaseFlip")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if is_private {
            for net in both() {
                assert_eq!(
                    parse_address(text, net),
                    Err(AddressError::LooksLikePrivateKey),
                    "{text}"
                );
            }
            keys += 1;
            continue;
        }
        addresses += 1;
        let bech32 = text.to_ascii_lowercase().starts_with("bcrt1");
        let variants: Vec<String> = if case_flip {
            vec![text.to_owned(), text.to_ascii_uppercase()]
        } else {
            vec![text.to_owned()]
        };
        for variant in &variants {
            match wallet_for(chain).unwrap() {
                Some(net) => {
                    let expected = expected_for_script(&payload);
                    let result = parse_address(variant, net).map(|kind| script_pubkey(&kind));
                    assert_eq!(result, expected, "{variant} on {net:?}");
                    if result.is_ok() {
                        parse_round_trip(variant, net).unwrap();
                    }
                    assert_eq!(
                        parse_address(variant, net.other()),
                        Err(AddressError::WrongNetwork),
                        "{variant}"
                    );
                }
                None if bech32 => {
                    for net in both() {
                        assert_eq!(
                            parse_address(variant, net),
                            Err(AddressError::WrongNetwork),
                            "{variant}"
                        );
                    }
                }
                None => {
                    // regtest base58 shares the test versions: same as testnet4.
                    let result = parse_address(variant, Testnet4).map(|kind| script_pubkey(&kind));
                    assert_eq!(result, Ok(payload.clone()), "{variant}");
                    assert_eq!(
                        parse_address(variant, Mainnet),
                        Err(AddressError::WrongNetwork)
                    );
                }
            }
        }
    }
    assert_eq!((addresses, keys), (54, 16));
}

/// `key_io_invalid`: every entry is rejected on both wallets.
#[test]
fn key_io_invalid() {
    let root = json(KEY_IO_INVALID).unwrap();
    let entries = root.as_array().unwrap();
    assert_eq!(entries.len(), 70);
    for entry in entries {
        let text = entry.as_array().unwrap()[0].as_str().unwrap();
        for net in both() {
            assert!(parse_address(text, net).is_err(), "{text} on {net:?}");
        }
    }
}

/// Decision-table order and the non-address rules (spec/08 §6.3 rules 1–7).
#[test]
fn decision_table_order() {
    let net = Mainnet;
    let cases: [(&str, Result<(), AddressError>); 26] = [
        ("", Err(AddressError::Empty)),
        (" \t\r\n ", Err(AddressError::Empty)),
        ("  bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\n", Ok(())),
        (
            "bc1qw508d6qejxtdg4y5r3zarv ary0c5xw7kv8f3t4",
            Err(AddressError::InvalidCharacter),
        ),
        (
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\u{0}",
            Err(AddressError::InvalidCharacter),
        ),
        (
            "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i\u{a0}x",
            Err(AddressError::InvalidCharacter),
        ),
        (
            "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            Err(AddressError::UriNotSupported),
        ),
        (
            "BITCOIN:BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
            Err(AddressError::UriNotSupported),
        ),
        ("lightning:lnbc1xyz", Err(AddressError::Lightning)),
        ("lnbc2500u1pvjluez", Err(AddressError::Lightning)),
        ("LNTB1abc", Err(AddressError::Lightning)),
        ("lntbs1abc", Err(AddressError::Lightning)),
        ("lnbcrt1abc", Err(AddressError::Lightning)),
        ("lnurl1dp68gurn8ghj7", Err(AddressError::Lightning)),
        (
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3",
            Err(AddressError::LooksLikePrivateKey),
        ),
        ("tprv8ZgxMBicQKsPd", Err(AddressError::LooksLikePrivateKey)),
        ("zprvAWgYBBk7JR8Gj", Err(AddressError::LooksLikePrivateKey)),
        (
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
            Err(AddressError::SilentPayment),
        ),
        (
            "tsp1qqfqnnv8czppwysafq3uwgwvsc638hc8rx3hscuddh0xa2yd746s7xqh6yy9ncjnqhqxazct0fzh98w7lpkm5fvlepqec2x4g8wtsg4ddq2mfdd9",
            Err(AddressError::SilentPayment),
        ),
        ("SP1xyz", Err(AddressError::SilentPayment)),
        (
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            Err(AddressError::WrongNetwork),
        ),
        (
            "BCRT1QDAVT4J2SD7DLHQSAVTNFXVZPPW6K7QY97TMNU9",
            Err(AddressError::WrongNetwork),
        ),
        (
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
            Err(AddressError::Bech32Checksum),
        ),
        (
            "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9",
            Err(AddressError::NotBitcoinAddress),
        ),
        (
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
            Err(AddressError::NotBitcoinAddress),
        ),
        ("안녕하세요", Err(AddressError::NotBitcoinAddress)),
    ];
    for (text, expected) in cases {
        assert_eq!(parse_address(text, net).map(|_| ()), expected, "{text:?}");
    }
    // Rule 4 before rule 6: a WIF key is never treated as a base58 address.
    assert_eq!(
        parse_address("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", net),
        Err(AddressError::LooksLikePrivateKey)
    );
    // bech32 length rules map to the format error.
    assert_eq!(
        parse_address("bc1qqqq", net),
        Err(AddressError::InvalidProgramLength)
    );
    assert_eq!(
        parse_address(&format!("bc1{}", "q".repeat(100)), net),
        Err(AddressError::InvalidProgramLength)
    );
}

/// base58 policy (spec/08 §6.1): payload length, checksum, versions, and the round trip.
#[test]
fn base58_policy() {
    let hash = [0x11_u8; 20];
    let check = |version: u8, body: &[u8]| {
        let mut payload = vec![version];
        payload.extend_from_slice(body);
        base58::encode_check(&payload)
    };
    for (net, p2pkh, p2sh) in [(Mainnet, 0x00, 0x05), (Testnet4, 0x6f, 0xc4)] {
        let text = check(p2pkh, &hash);
        assert_eq!(parse_round_trip(&text, net), Ok(ScriptKind::P2pkh(hash)));
        assert_eq!(encode_address(&ScriptKind::P2pkh(hash), net), text);
        let text = check(p2sh, &hash);
        assert_eq!(parse_round_trip(&text, net), Ok(ScriptKind::P2sh(hash)));
        assert_eq!(
            parse_address(&check(p2pkh, &hash), net.other()),
            Err(AddressError::WrongNetwork)
        );
        assert_eq!(
            parse_address(&check(0x30, &hash), net),
            Err(AddressError::UnknownVersion)
        );
        assert_eq!(
            parse_address(&check(p2pkh, &[0x11; 19]), net),
            Err(AddressError::Base58Length)
        );
        assert_eq!(
            parse_address(&check(p2pkh, &[0x11; 21]), net),
            Err(AddressError::Base58Length)
        );
    }
    let mut tampered = check(0x00, &hash).into_bytes();
    let last = tampered.last_mut().unwrap();
    *last = if *last == b'2' { b'3' } else { b'2' };
    assert_eq!(
        parse_address(core::str::from_utf8(&tampered).unwrap(), Mainnet),
        Err(AddressError::Base58Checksum)
    );
    assert_eq!(parse_address("x", Mainnet), Err(AddressError::Base58Length));
    assert_eq!(
        parse_address(&"2".repeat(65), Mainnet),
        Err(AddressError::Base58Length)
    );
}

#[test]
fn script_kinds_round_trip() {
    let kinds = [
        ScriptKind::P2pkh([1; 20]),
        ScriptKind::P2sh([2; 20]),
        ScriptKind::P2wpkh([3; 20]),
        ScriptKind::P2wsh([4; 32]),
        ScriptKind::P2tr(
            hex::decode_array("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap(),
        ),
    ];
    let lengths = [25, 23, 22, 34, 34];
    let labels = [
        "P2PKH(레거시)",
        "P2SH(스크립트)",
        "P2WPKH",
        "P2WSH(스크립트)",
        "P2TR",
    ];
    for ((kind, length), label) in kinds.iter().zip(lengths).zip(labels) {
        let spk = script_pubkey(kind);
        assert_eq!(spk.len(), length);
        assert_eq!(kind_from_script(&spk), Some(*kind));
        assert_eq!(kind.type_label(), label);
        for net in both() {
            let text = encode_address(kind, net);
            assert_eq!(parse_address(&text, net), Ok(*kind), "{text}");
            if !matches!(kind, ScriptKind::P2pkh(_) | ScriptKind::P2sh(_)) {
                assert_eq!(text, text.to_ascii_lowercase());
                assert!(text.starts_with(net.hrp()));
            }
        }
        let mut longer = spk.clone();
        longer.push(0);
        assert_eq!(kind_from_script(&longer), None);
        assert_eq!(kind_from_script(&spk[..spk.len() - 1]), None);
    }
    assert_eq!(kind_from_script(&[]), None);
    assert_eq!(kind_from_script(&[0x6a, 0x01, 0x00]), None);
    assert_eq!(kind_from_script(&[0x52, 0x20]), None);
}

#[test]
fn btc_address_and_hash160() {
    // HASH160 of the BIP84 0/0 key → its program (spec/09 §3.10).
    let public: [u8; 33] =
        hex::decode_array("0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c")
            .unwrap();
    let program = hash160(&public);
    assert_eq!(
        hex::encode(&program),
        "c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2"
    );
    let ours = BtcAddress::p2wpkh(Mainnet, &program);
    assert_eq!(ours.as_str(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    assert!(
        ours.as_str()
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase())
    );
    assert_eq!(
        format!("{ours:?}"),
        "BtcAddress(bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu)"
    );
    let test = BtcAddress::p2wpkh(Testnet4, &program);
    assert!(test.as_str().starts_with("tb1q"));
    assert_ne!(ours, test);
    assert_eq!(
        hex::encode(&ours.script_pubkey()),
        "0014c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2"
    );
}

/// spec/08 §13 fixed texts.
#[test]
fn error_texts() {
    let table = [
        (AddressError::Empty, "주소를 입력하세요"),
        (
            AddressError::InvalidCharacter,
            "허용되지 않는 문자가 있습니다",
        ),
        (AddressError::NotBitcoinAddress, "Bitcoin 주소가 아닙니다"),
        (
            AddressError::MixedCase,
            "대소문자가 섞인 bech32 주소는 받지 않습니다",
        ),
        (
            AddressError::Bech32Checksum,
            "주소 체크섬이 틀립니다(오타 확인)",
        ),
        (
            AddressError::Base58Checksum,
            "주소 체크섬이 틀립니다(오타 확인)",
        ),
        (
            AddressError::WrongChecksumVariant,
            "주소 형식이 올바르지 않습니다",
        ),
        (
            AddressError::InvalidPadding,
            "주소 형식이 올바르지 않습니다",
        ),
        (
            AddressError::InvalidProgramLength,
            "주소 형식이 올바르지 않습니다",
        ),
        (
            AddressError::InvalidWitnessVersion,
            "주소 형식이 올바르지 않습니다",
        ),
        (AddressError::Base58Length, "주소 형식이 올바르지 않습니다"),
        (
            AddressError::UnknownVersion,
            "지원하지 않는 주소 버전입니다",
        ),
        (
            AddressError::PayToAnchor,
            "P2A 앵커 출력은 누구나 가져갈 수 있어 보낼 수 없습니다",
        ),
        (
            AddressError::InvalidTaprootKey,
            "유효하지 않은 Taproot 키입니다. 보내면 잃습니다",
        ),
        (
            AddressError::UnsupportedWitnessVersion,
            "지원하지 않는 세그윗 버전(v2–v16) 주소입니다",
        ),
        (AddressError::SilentPayment, "사일런트 페이먼트 미지원"),
        (AddressError::Lightning, "라이트닝 미지원"),
        (AddressError::UriNotSupported, "주소만 붙여넣으세요"),
        (
            AddressError::LooksLikePrivateKey,
            "개인키처럼 보입니다. 다른 곳에 붙여넣지 마세요",
        ),
    ];
    for (error, text) in table {
        for net in both() {
            assert_eq!(error.text(net), text);
        }
        assert_eq!(error.to_string(), text);
    }
    assert_eq!(
        AddressError::WrongNetwork.text(Mainnet),
        "다른 네트워크의 주소입니다(지갑: MAINNET)"
    );
    assert_eq!(
        AddressError::WrongNetwork.text(Testnet4),
        "다른 네트워크의 주소입니다(지갑: TESTNET4)"
    );
}

/// A v1/32 program that is not an x-only key (x = 5 is off the curve) → `InvalidTaprootKey`.
#[test]
fn invalid_taproot_key() {
    let mut key = [0_u8; 32];
    key[31] = 5;
    let text = encode_address(&ScriptKind::P2tr(key), Mainnet);
    assert_eq!(
        parse_address(&text, Mainnet),
        Err(AddressError::InvalidTaprootKey)
    );
}
