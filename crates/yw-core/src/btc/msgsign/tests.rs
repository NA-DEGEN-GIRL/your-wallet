//! Bitcoin message signature vectors: BIP322 `basic-test-vectors.json` (message hashes, the
//! `to_spend`/`to_sign` txids, the P2WPKH simple signatures of "" and "Hello World" and the
//! unprefixed P2TR signature) and the bitcoinjs-message fixtures for BIP137 (private key 1,
//! "vires is numeris", magic hashes, verify cases).
#![expect(
    clippy::indexing_slicing,
    reason = "test fixtures index buffers of known length"
)]

use secp256k1::SecretKey;

use super::{
    BtcMessageError, BtcMessageProtocol, MAX_BTC_MESSAGE_BYTES, address_of, bip137_magic_hash,
    bip137_verify, bip322_message_hash, bip322_to_sign, bip322_to_spend, bip322_verify_simple,
    looks_like_transaction, sign_message_with,
};
use crate::approval::{
    AccountRef, ApprovalKind, Approved, BtcMessagePayload, ChainRef, Signer, SigningPayload,
};
use crate::btc::account::{BtcKeySource, BtcPubKey, ScriptType};
use crate::btc::address::{ScriptKind, parse_address};
use crate::btc::network::BtcNetwork;
use crate::btc::sign::SeedKeys;
use crate::btc::tx::{parse_transaction, txid};
use crate::codec::wif::parse_wif;
use crate::entropy::{OsRandom, secp_context};

const VECTOR_WIF: &str = "L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k";
const VECTOR_ADDRESS: &str = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";

fn secret_of_wif(wif: &str) -> (SecretKey, bool) {
    let key = parse_wif(wif).unwrap();
    (
        SecretKey::from_byte_array(**key.secret()).unwrap(),
        key.compressed(),
    )
}

fn one() -> SecretKey {
    let mut bytes = [0_u8; 32];
    bytes[31] = 1;
    SecretKey::from_byte_array(bytes).unwrap()
}

fn keys_with(secret: SecretKey, compressed: bool, script_type: ScriptType) -> SeedKeys {
    let mut keys = SeedKeys {
        seed: [7; 64],
        imported: Vec::new(),
        aux: [9; 32],
    };
    keys.add_imported(
        [1; 16],
        secret,
        compressed,
        BtcNetwork::Mainnet,
        script_type,
    );
    keys
}

fn approved(
    secret: &SecretKey,
    compressed: bool,
    script_type: ScriptType,
    protocol: BtcMessageProtocol,
    message: &[u8],
) -> Approved {
    let ctx = secp_context(&mut OsRandom).unwrap();
    let pubkey = BtcPubKey::of_point(&secret.public_key(&ctx), compressed);
    let (_, address) = address_of(BtcNetwork::Mainnet, script_type, &pubkey).unwrap();
    Approved::for_test(
        ChainRef::Bitcoin {
            network: BtcNetwork::Mainnet.id(),
            genesis: BtcNetwork::Mainnet.genesis(),
        },
        AccountRef::Bitcoin(pubkey.compressed().unwrap()),
        Signer::FromPayload,
        ApprovalKind::BtcMessage,
        SigningPayload::BtcMessage(Box::new(BtcMessagePayload {
            network: BtcNetwork::Mainnet,
            source: BtcKeySource::Imported {
                id: [1; 16],
                script_type,
                compressed,
            },
            pubkey,
            script_type,
            address,
            protocol,
            message: message.to_vec(),
        })),
    )
}

#[test]
fn bip322_hash_and_transaction_vectors() {
    let kind = parse_address(VECTOR_ADDRESS, BtcNetwork::Mainnet).unwrap();
    let script = crate::btc::address::script_pubkey(&kind);
    for (message, hash, to_spend, to_sign) in [
        (
            "",
            "c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1",
            "c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7",
            "1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6",
        ),
        (
            "Hello World",
            "f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a",
            "b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b",
            "88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf",
        ),
        (
            "UTF-8 support: öäüéàè 测试文本 😄",
            "43936b237ea38c7794eb5d755e0d220b6db92ebfc5c8f482759d22b1286376d7",
            "c8f4f525fe8afb1bc09b44175bd2096f079c98425e8a1be676b712add1fb62f0",
            "8f488e06b89eafd019ec528109eafaf7f1d1811fd617aa1eeb9658f1c1be6586",
        ),
    ] {
        assert_eq!(
            crate::hex::encode(&bip322_message_hash(message.as_bytes())),
            hash
        );
        let spend = bip322_to_spend(&script, message.as_bytes());
        assert_eq!(txid(&spend).to_display_hex(), to_spend);
        assert_eq!(
            txid(&bip322_to_sign(txid(&spend))).to_display_hex(),
            to_sign
        );
    }
}

#[test]
fn bip322_simple_p2wpkh_vectors_reproduce() {
    let (secret, compressed) = secret_of_wif(VECTOR_WIF);
    let keys = keys_with(secret, compressed, ScriptType::P2wpkh);
    let kind = parse_address(VECTOR_ADDRESS, BtcNetwork::Mainnet).unwrap();
    for (message, expected) in [
        (
            "",
            [
                "AkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
                "AkgwRQIhAPkJ1Q4oYS0htvyuSFHLxRQpFAY56b70UvE7Dxazen0ZAiAtZfFz1S6T6I23MWI2lK/pcNTWncuyL8UL+oMdydVgzAEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy",
            ],
        ),
        (
            "Hello World",
            [
                "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
                "AkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy",
            ],
        ),
    ] {
        for vector in expected {
            assert!(bip322_verify_simple(&kind, message.as_bytes(), vector));
            assert!(bip322_verify_simple(
                &kind,
                message.as_bytes(),
                &format!("smp{vector}")
            ));
        }
        let signed = sign_message_with(
            &keys,
            &approved(
                &secret,
                compressed,
                ScriptType::P2wpkh,
                BtcMessageProtocol::Bip322,
                message.as_bytes(),
            ),
        )
        .unwrap();
        // RFC 6979 low-R: the first (grinded) vector, byte for byte.
        assert_eq!(signed.signature, expected[0]);
        assert_eq!(signed.message_hash, bip322_message_hash(message.as_bytes()));
    }
    // Wrong message / wrong address fail (the `error` vectors).
    assert!(!bip322_verify_simple(
        &kind,
        b"Wrong message that was not signed",
        "AkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI="
    ));
    assert!(!bip322_verify_simple(&kind, b"", "AA=="));
    assert!(!bip322_verify_simple(&kind, b"", "not-valid-base64!!!"));
}

#[test]
fn bip322_simple_p2tr_vector_and_own_signature() {
    let vector = parse_address(
        "bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler",
        BtcNetwork::Mainnet,
    )
    .unwrap();
    let signature =
        "AUCJYOwOjxYAvatTAGYaVlNXBVyFuc4MwNQkOuK2tl8xhfKDONd0NjfYyNSYcRqeCp8hsAnCEPHAVEkO9h6vbQ/R";
    assert!(bip322_verify_simple(
        &vector,
        b"No prefix fallback",
        signature
    ));
    assert!(!bip322_verify_simple(
        &vector,
        b"No prefix fallbacK",
        signature
    ));
    // The vector's key signs a verifiable signature for its own address.
    let (secret, compressed) =
        secret_of_wif("KyrSGCFPhqZMjCe5fNTYddiLMp4tMj4gLKuJ26TsB2rvr1VJGPbt");
    let keys = keys_with(secret, compressed, ScriptType::P2tr);
    let request = approved(
        &secret,
        compressed,
        ScriptType::P2tr,
        BtcMessageProtocol::Bip322,
        b"No prefix fallback",
    );
    let SigningPayload::BtcMessage(payload) = request.payload() else {
        unreachable!("test payload");
    };
    assert_eq!(
        payload.address,
        "bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler"
    );
    let signed = sign_message_with(&keys, &request).unwrap();
    assert!(bip322_verify_simple(
        &vector,
        b"No prefix fallback",
        &signed.signature
    ));
    // ECDSA has no Taproot header.
    let ecdsa = approved(
        &secret,
        compressed,
        ScriptType::P2tr,
        BtcMessageProtocol::Ecdsa,
        b"x",
    );
    assert_eq!(
        sign_message_with(&keys, &ecdsa),
        Err(BtcMessageError::Unsupported)
    );
}

#[test]
fn bip137_fixtures() {
    for (message, hash) in [
        (
            "",
            "80e795d4a4caadd7047af389d9f7f220562feb6196032e2131e10563352c4bcc",
        ),
        (
            "Vires is Numeris",
            "f8a5affbef4a3241b19067aa694562f64f513310817297089a8929a930f4f933",
        ),
    ] {
        assert_eq!(
            crate::hex::encode(&bip137_magic_hash(message.as_bytes())),
            hash
        );
    }
    let message = b"vires is numeris";
    for (script_type, compressed, expected) in [
        (
            ScriptType::P2pkh,
            false,
            "HF8nHqFr3K2UKYahhX3soVeoW8W1ECNbr0wfck7lzyXjCS5Q16Ek45zyBuy1Fiy9sTPKVgsqqOuPvbycuVSSVl8=",
        ),
        (
            ScriptType::P2pkh,
            true,
            "IF8nHqFr3K2UKYahhX3soVeoW8W1ECNbr0wfck7lzyXjCS5Q16Ek45zyBuy1Fiy9sTPKVgsqqOuPvbycuVSSVl8=",
        ),
        (
            ScriptType::P2shP2wpkh,
            true,
            "JF8nHqFr3K2UKYahhX3soVeoW8W1ECNbr0wfck7lzyXjCS5Q16Ek45zyBuy1Fiy9sTPKVgsqqOuPvbycuVSSVl8=",
        ),
        (
            ScriptType::P2wpkh,
            true,
            "KF8nHqFr3K2UKYahhX3soVeoW8W1ECNbr0wfck7lzyXjCS5Q16Ek45zyBuy1Fiy9sTPKVgsqqOuPvbycuVSSVl8=",
        ),
    ] {
        let keys = keys_with(one(), compressed, script_type);
        let request = approved(
            &one(),
            compressed,
            script_type,
            BtcMessageProtocol::Ecdsa,
            message,
        );
        let signed = sign_message_with(&keys, &request).unwrap();
        assert_eq!(signed.signature, expected, "{script_type:?}");
        let SigningPayload::BtcMessage(payload) = request.payload() else {
            unreachable!("test payload");
        };
        assert!(bip137_verify(
            BtcNetwork::Mainnet,
            &payload.address,
            message,
            expected
        ));
    }
    // bitcoinjs-message `verify` fixtures (another key).
    for (address, signature) in [
        (
            "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM",
            "G8JawPtQOrybrSP1WHQnQPr67B9S3qrxBrl1mlzoTJOSHEpmnF7D3+t+LX0Xei9J20B5AIdPbeL3AaTBZ4N3bY0=",
        ),
        (
            "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs",
            "H8JawPtQOrybrSP1WHQnQPr67B9S3qrxBrl1mlzoTJOSHEpmnF7D3+t+LX0Xei9J20B5AIdPbeL3AaTBZ4N3bY0=",
        ),
        (
            "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN",
            "JF8nHqFr3K2UKYahhX3soVeoW8W1ECNbr0wfck7lzyXjCS5Q16Ek45zyBuy1Fiy9sTPKVgsqqOuPvbycuVSSVl8=",
        ),
        (
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "KF8nHqFr3K2UKYahhX3soVeoW8W1ECNbr0wfck7lzyXjCS5Q16Ek45zyBuy1Fiy9sTPKVgsqqOuPvbycuVSSVl8=",
        ),
    ] {
        assert!(
            bip137_verify(BtcNetwork::Mainnet, address, message, signature),
            "{address}"
        );
        assert!(!bip137_verify(
            BtcNetwork::Mainnet,
            address,
            b"vires is numeris!",
            signature
        ));
    }
}

#[test]
fn bip322_full_p2sh_p2wpkh_signs_the_to_sign_transaction() {
    let keys = keys_with(one(), true, ScriptType::P2shP2wpkh);
    let request = approved(
        &one(),
        true,
        ScriptType::P2shP2wpkh,
        BtcMessageProtocol::Bip322,
        b"Hello World",
    );
    let signed = sign_message_with(&keys, &request).unwrap();
    let bytes = crate::codec::base64::decode(&signed.signature).unwrap();
    let tx = parse_transaction(&bytes).unwrap();
    let input = &tx.inputs[0];
    let SigningPayload::BtcMessage(payload) = request.payload() else {
        unreachable!("test payload");
    };
    let ScriptKind::P2sh(_) = parse_address(&payload.address, BtcNetwork::Mainnet).unwrap() else {
        unreachable!("p2sh address");
    };
    let spend = bip322_to_spend(
        &crate::btc::address::script_pubkey(
            &parse_address(&payload.address, BtcNetwork::Mainnet).unwrap(),
        ),
        b"Hello World",
    );
    assert_eq!(input.prevout.txid, txid(&spend));
    let key_hash = crate::btc::address::hash160(&input.witness[1]);
    let sighash = crate::btc::sighash::bip143_sighash_p2wpkh(
        &bip322_to_sign(txid(&spend)),
        0,
        &key_hash,
        crate::btc::amount::Sats::ZERO,
    )
    .unwrap();
    crate::btc::sign::check_witness_signature(&input.witness[0], &input.witness[1], &sighash)
        .unwrap();
    assert_eq!(tx.outputs[0].script_pubkey, vec![0x6a]);
}

#[test]
fn refusals() {
    // P2PKH has no BIP322 form here; a mismatched approval kind or a transaction is refused.
    let keys = keys_with(one(), true, ScriptType::P2pkh);
    let p2pkh = approved(
        &one(),
        true,
        ScriptType::P2pkh,
        BtcMessageProtocol::Bip322,
        b"x",
    );
    assert_eq!(
        sign_message_with(&keys, &p2pkh),
        Err(BtcMessageError::Unsupported)
    );
    let tx = crate::btc::tx::Transaction {
        version: 2,
        inputs: vec![crate::btc::tx::TxIn {
            prevout: crate::btc::tx::OutPoint {
                txid: crate::btc::tx::Txid::from_bytes([0x11; 32]),
                vout: 1,
            },
            script_sig: Vec::new(),
            sequence: 0xFFFF_FFFD,
            witness: vec![vec![0x30; 71], vec![0x02; 33]],
        }],
        outputs: vec![crate::btc::tx::TxOut {
            value: crate::btc::amount::Sats::new(10_000).unwrap(),
            script_pubkey: crate::btc::address::script_pubkey(&ScriptKind::P2wpkh([0x22; 20])),
        }],
        lock_time: 800_000,
    };
    let tx_bytes = crate::btc::tx::serialize(&tx, true);
    assert!(parse_transaction(&tx_bytes).is_ok());
    assert!(!looks_like_transaction(b"Hello World"));
    assert!(looks_like_transaction(b"psbt\xff\x01\x00"));
    assert!(looks_like_transaction(b"cHNidP8BAHECAAAAAQ=="));
    assert!(looks_like_transaction(&tx_bytes));
    assert!(looks_like_transaction(
        crate::hex::encode(&tx_bytes).as_bytes()
    ));
    assert!(looks_like_transaction(
        crate::codec::base64::encode(&tx_bytes).as_bytes()
    ));
    let keys = keys_with(one(), true, ScriptType::P2wpkh);
    let psbt = approved(
        &one(),
        true,
        ScriptType::P2wpkh,
        BtcMessageProtocol::Ecdsa,
        b"psbt\xff\x00",
    );
    assert_eq!(
        sign_message_with(&keys, &psbt),
        Err(BtcMessageError::Unsupported)
    );
    let big = approved(
        &one(),
        true,
        ScriptType::P2wpkh,
        BtcMessageProtocol::Ecdsa,
        &vec![b'a'; MAX_BTC_MESSAGE_BYTES + 1],
    );
    assert_eq!(
        sign_message_with(&keys, &big),
        Err(BtcMessageError::Unsupported)
    );
    // A key that does not give the approved public key.
    let mut other = [0_u8; 32];
    other[31] = 2;
    let wrong = keys_with(
        SecretKey::from_byte_array(other).unwrap(),
        true,
        ScriptType::P2wpkh,
    );
    let request = approved(
        &one(),
        true,
        ScriptType::P2wpkh,
        BtcMessageProtocol::Ecdsa,
        b"x",
    );
    assert_eq!(
        sign_message_with(&wrong, &request),
        Err(BtcMessageError::KeyMismatch)
    );
    let _ = BtcPubKey::Compressed([2; 33]);
}

/// spec/08 §17 with an account on an EVM account's key (spec/08 §3.5): the vault lends the EVM
/// key `m/44'/60'/0'/0/0` for the account's one address (BIP322 for P2WPKH and P2TR); a payload
/// naming EVM account 1 for account 0's key is refused.
#[test]
fn evm_shared_key_signs_messages() {
    let vault = crate::btc::tests::about_vault();
    let pubkey = vault
        .evm_public_key(crate::bip32::path::AccountIndex::ZERO)
        .unwrap();
    for script_type in [ScriptType::P2wpkh, ScriptType::P2tr] {
        let key = BtcPubKey::Compressed(pubkey);
        let (_, address) = address_of(BtcNetwork::Mainnet, script_type, &key).unwrap();
        let request = |evm_index| {
            Approved::for_test(
                ChainRef::Bitcoin {
                    network: BtcNetwork::Mainnet.id(),
                    genesis: BtcNetwork::Mainnet.genesis(),
                },
                AccountRef::Bitcoin(pubkey),
                Signer::FromPayload,
                ApprovalKind::BtcMessage,
                SigningPayload::BtcMessage(Box::new(BtcMessagePayload {
                    network: BtcNetwork::Mainnet,
                    source: BtcKeySource::EvmShared {
                        evm_index,
                        script_type,
                    },
                    pubkey: key,
                    script_type,
                    address: address.clone(),
                    protocol: BtcMessageProtocol::Bip322,
                    message: b"Hello World".to_vec(),
                })),
            )
        };
        let signed = sign_message_with(&vault, &request(0)).unwrap();
        let parsed = parse_address(&address, BtcNetwork::Mainnet).unwrap();
        assert!(bip322_verify_simple(
            &parsed,
            b"Hello World",
            &signed.signature
        ));
        assert_eq!(
            sign_message_with(&vault, &request(1)),
            Err(BtcMessageError::KeyMismatch)
        );
    }
}

/// spec/10 §13: Bitcoin message signatures of `YubiKey` accounts on the card emulator (high-s
/// and high-R answers): BIP137 for the three card address types (recovery id found against the
/// recorded key, the vault verifier accepts it), BIP322 simple for P2WPKH (the vault verifier
/// accepts the card witness) and BIP322 full for P2SH-P2WPKH (the `to_sign` witness verifies);
/// the vault path and a software source are refused, and card errors come back unchanged.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario per address type and protocol"
)]
fn yubikey_card_signs_bip137_and_bip322() {
    use super::{BtcMessageCardError, sign_message_card};
    use crate::btc::account::HwBtcKey;
    use crate::yubikey::CardError;
    use crate::yubikey::apdu::ApduMode;
    use crate::yubikey::enrol::{EnrolAuth, enrol_card};
    use crate::yubikey::mock::{MockCard, ToyCipher};
    use crate::yubikey::plan::{CardSlot, KeyRole, PgpKey, PlannedSlot, slot_on_card};
    use crate::yubikey::record::HwPublicKey;
    use crate::yubikey::sign::{CardKey, sign_btc};

    let seed = *crate::bip39::Mnemonic::parse(crate::btc::tests::ABOUT)
        .unwrap()
        .to_seed(&crate::password::Bip39Passphrase::empty())
        .unwrap()
        .expose();
    let owned = secp_context(&mut OsRandom).unwrap();
    let ctx = &owned;
    for script_type in [
        ScriptType::P2wpkh,
        ScriptType::P2shP2wpkh,
        ScriptType::P2pkh,
    ] {
        let role = KeyRole::Btc {
            network: BtcNetwork::Mainnet,
            script: script_type,
            index: 0,
        };
        let mut card = MockCard::new(5_550_001);
        let auth = EnrolAuth {
            admin_pin: b"12345678",
            management_key: &crate::yubikey::piv::DEFAULT_MANAGEMENT_KEY,
            cipher: Some(&ToyCipher),
            challenge: [0; 16],
        };
        let record = enrol_card(
            &mut card,
            ApduMode::Short,
            &seed,
            &[PlannedSlot::recommended(
                CardSlot::OpenPgp(PgpKey::Sig),
                role,
            )],
            &[],
            &auth,
        )
        .unwrap()
        .record;
        card.high_s = true;
        card.high_r = true;
        card.log.clear();
        let holder = slot_on_card(core::slice::from_ref(&record), role, record.serial).unwrap();
        let HwPublicKey::Secp256k1(public) = record.slots[0].public else {
            unreachable!("secp256k1 slot");
        };
        let key = CardKey {
            serial: record.serial,
            slot: holder.slot,
            public: HwPublicKey::Secp256k1(public),
        };
        let pubkey = BtcPubKey::Compressed(public);
        let (kind, address) = address_of(BtcNetwork::Mainnet, script_type, &pubkey).unwrap();
        if script_type == ScriptType::P2wpkh {
            // BIP84 receive 0 of the `abandon` mnemonic.
            assert_eq!(address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        }
        let request = |protocol, source| {
            Approved::for_test(
                ChainRef::Bitcoin {
                    network: BtcNetwork::Mainnet.id(),
                    genesis: BtcNetwork::Mainnet.genesis(),
                },
                AccountRef::Bitcoin(public),
                Signer::FromPayload,
                ApprovalKind::BtcMessage,
                SigningPayload::BtcMessage(Box::new(BtcMessagePayload {
                    network: BtcNetwork::Mainnet,
                    source,
                    pubkey,
                    script_type,
                    address: address.clone(),
                    protocol,
                    message: b"Hello YubiKey".to_vec(),
                })),
            )
        };
        let hardware = BtcKeySource::Hardware {
            key: HwBtcKey::Address(0),
            script_type,
        };
        let mut touches = 0;
        let card_fn = |pin: &'static [u8]| {
            move |card: &mut MockCard, touches: &mut usize, sighash: [u8; 32]| {
                *touches += 1;
                sign_btc(ctx, card, ApduMode::Short, &key, pin, sighash)
            }
        };
        let right = card_fn(b"123456");
        let mut sign = |protocol| {
            sign_message_card(request(protocol, hardware), &mut |sighash| {
                right(&mut card, &mut touches, sighash)
            })
        };
        let ecdsa = sign(BtcMessageProtocol::Ecdsa).unwrap();
        assert!(bip137_verify(
            BtcNetwork::Mainnet,
            &address,
            b"Hello YubiKey",
            &ecdsa.signature
        ));
        assert_eq!(ecdsa.message_hash, bip137_magic_hash(b"Hello YubiKey"));
        match script_type {
            ScriptType::P2wpkh => {
                let signed = sign(BtcMessageProtocol::Bip322).unwrap();
                assert!(bip322_verify_simple(
                    &kind,
                    b"Hello YubiKey",
                    &signed.signature
                ));
                assert_eq!(signed.message_hash, bip322_message_hash(b"Hello YubiKey"));
            }
            ScriptType::P2shP2wpkh => {
                let signed = sign(BtcMessageProtocol::Bip322).unwrap();
                let bytes = crate::codec::base64::decode(&signed.signature).unwrap();
                let tx = parse_transaction(&bytes).unwrap();
                let spend =
                    bip322_to_spend(&crate::btc::address::script_pubkey(&kind), b"Hello YubiKey");
                assert_eq!(tx.inputs[0].prevout.txid, txid(&spend));
                let sighash = crate::btc::sighash::bip143_sighash_p2wpkh(
                    &bip322_to_sign(txid(&spend)),
                    0,
                    &crate::btc::address::hash160(&public),
                    crate::btc::amount::Sats::ZERO,
                )
                .unwrap();
                // A high-R card item: the relaxed card check accepts it.
                crate::btc::sign::check_card_signature(
                    &tx.inputs[0].witness[0],
                    &tx.inputs[0].witness[1],
                    &sighash,
                )
                .unwrap();
            }
            _ => {
                // No BIP322 form for P2PKH: refused before the card is asked.
                assert_eq!(
                    sign(BtcMessageProtocol::Bip322),
                    Err(BtcMessageCardError::Sign(BtcMessageError::Unsupported))
                );
            }
        }
        let signed_count = if script_type == ScriptType::P2pkh {
            1
        } else {
            2
        };
        assert_eq!(touches, signed_count, "one card signature per message");
        assert!(!card.saw_write(), "message signing sends no write");
        // A software source is not a card approval; a wrong PIN comes back as a card error.
        let software = BtcKeySource::Imported {
            id: [1; 16],
            script_type,
            compressed: true,
        };
        assert_eq!(
            sign_message_card(request(BtcMessageProtocol::Ecdsa, software), &mut |_| {
                unreachable!("refused before the card")
            }),
            Err(BtcMessageCardError::Sign(BtcMessageError::KindMismatch))
        );
        let wrong = card_fn(b"000000");
        let mut ignored = 0;
        assert_eq!(
            sign_message_card(
                request(BtcMessageProtocol::Ecdsa, hardware),
                &mut |sighash| { wrong(&mut card, &mut ignored, sighash) }
            ),
            Err(BtcMessageCardError::Card(CardError::WrongPin {
                retries: 2
            }))
        );
    }
}
