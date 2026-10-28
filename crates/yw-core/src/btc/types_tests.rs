//! Address types beyond BIP84 (spec/08 §3, §6.6, §11, §14.1): official vectors and full send
//! flows for every account type.
//!
//! Vectors (official sources only, see `tests/vectors/SOURCES.md`):
//! - BIP49 (`abandon`×11 `about`, `m/49'/1'/0'`): account `uprv`/`upub` body, `0/0` key, key hash,
//!   redeem script, address `2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2`.
//! - BIP84 (`m/84'/0'/0'`): `0/0`, `0/1`, `1/0` addresses through `BtcAccountKey`.
//! - BIP86 (`m/86'/0'/0'`): account `xprv`/`xpub`, `0/0`, `0/1`, `1/0` internal key, output key,
//!   scriptPubKey and bech32m address.
//! - BIP143 "P2SH-P2WPKH": hash parts, sighash, signature, redeem push and the signed transaction.
//! - BIP341 `wallet-test-vectors.json`: every `scriptPubKey` case (tweak, output key, address),
//!   every key-path input's tweak and tweaked private key, the `SIGHASH_DEFAULT` input's sigMsg,
//!   sigHash and witness (all-zero BIP340 aux), and the fully signed transaction's P2TR, P2PKH
//!   (legacy sighash) and P2WPKH (BIP143) signatures.
//! - Bitcoin Core `sighash.json`: every legacy `SIGHASH_ALL`-semantics case without
//!   `OP_CODESEPARATOR` that the strict parser accepts.
//!
//! BIP44 publishes no derivation vector; its path and P2PKH encoding are checked against private
//! derivation and Core's `key_io` vectors (`tests/btc_address.rs`).
#![expect(
    clippy::indexing_slicing,
    reason = "test fixtures index buffers of known length"
)]

use secp256k1::ecdsa::Signature;
use secp256k1::{Message, PublicKey, SecretKey, XOnlyPublicKey};
use yw_json::{Limits, Value};

use super::account::{
    BtcAccountId, BtcAccountKey, BtcKeySource, BtcPubKey, ScriptType, kind_for_compressed,
};
use super::address::{ScriptKind, encode_address, hash160, parse_address, script_pubkey};
use super::amount::Sats;
use super::display::{btc_payload, build_btc_request, payload_header};
use super::fee::{FeeChoice, FeeRate, FeeSource, rate_kvb};
use super::meta::{BtcAccounts, BtcMeta, ListedUtxo, VerifiedUtxo};
use super::network::BtcNetwork;
use super::prevtx::verify_prev_output;
use super::script::{p2sh_p2wpkh_script_sig, split_p2pkh_script_sig};
use super::select::{SendAmount, SendPlan, SendRequest, plan_send};
use super::sighash::{
    bip143_sighash_p2wpkh, hash_outputs, hash_prevouts, hash_sequence, legacy_is_all,
    legacy_sighash,
};
use super::sign::{
    BtcKeys, SeedKeys, SignError, check_recorded_amounts, sign_plan, sign_plan_with, sign_sighash,
};
use super::taproot::{
    Prevout, check_key_path_witness, output_key, sig_msg_default, sighash_default, sign_key_path,
    tap_tweak_hash, tweaked_keypair,
};
use super::tests::{ABOUT, about_vault};
use super::tx::{
    OutPoint, Transaction, TxIn, TxOut, Txid, parse_transaction, serialize, txid, vsize, weight,
};
use super::verify::{PostSignError, verify_signed};
use crate::approval::{
    AccountRef, ApprovalId, ApprovalStore, Approved, ChainRef, Signer, SigningPayload,
};
use crate::bip32::path::{BtcChain, BtcCoin, BtcPurpose, btc_account_path, btc_path};
use crate::bip32::xkey::{XKeyVersion, derive_xkey, encode_xkey};
use crate::bip32::{btc_account_xpub_from_seed, secret_key_from_seed};
use crate::bip39::Mnemonic;
use crate::codec::base58;
use crate::entropy::{OsRandom, secp_context};
use crate::hex;
use crate::journal::btc::BtcRecord;
use crate::password::Bip39Passphrase;

const TIP: u32 = 150_000;
const NOW_MS: u64 = 9_000;
const NOW_UNIX_MS: u64 = 1_790_000_000_000;

fn h<const N: usize>(text: &str) -> [u8; N] {
    hex::decode_array::<N>(text).unwrap()
}

fn about_seed() -> [u8; 64] {
    *Mnemonic::parse(ABOUT)
        .unwrap()
        .to_seed(&Bip39Passphrase::empty())
        .expose()
}

fn hd_key(
    seed: &[u8; 64],
    net: BtcNetwork,
    script_type: ScriptType,
    account: u32,
) -> BtcAccountKey {
    let ctx = secp_context(&mut OsRandom).unwrap();
    let coin = net.account_node(script_type.purpose(), account).unwrap();
    let xpub = btc_account_xpub_from_seed(&ctx, seed, coin).unwrap();
    BtcAccountKey::hd(script_type, account, xpub).unwrap()
}

const BIP341_WALLET: &str = include_str!("../../tests/vectors/btc/bip341_wallet_test_vectors.json");
const CORE_SIGHASH: &str = include_str!("../../tests/vectors/btc/sighash.json");

fn vector_file(text: &str) -> Value {
    yw_json::parse(
        text.as_bytes(),
        &Limits {
            max_bytes: 1 << 20,
            max_depth: 16,
            max_nodes: 1 << 20,
            max_items: 1 << 20,
        },
    )
    .unwrap()
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .as_object()
        .unwrap()
        .get(key)
        .unwrap()
        .as_str()
        .unwrap()
}

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.as_object().unwrap().get(key).unwrap()
}

// ---- derivation vectors ----

/// The BIP44/49/84/86 account node paths and the stable `ScriptType` codes.
#[test]
fn purposes_paths_and_codes() {
    for (script_type, code, purpose, name) in [
        (ScriptType::P2pkh, 1, 44, "p2pkh"),
        (ScriptType::P2shP2wpkh, 2, 49, "p2sh-p2wpkh"),
        (ScriptType::P2wpkh, 3, 84, "p2wpkh"),
        (ScriptType::P2tr, 4, 86, "p2tr"),
    ] {
        assert_eq!(script_type.code(), code);
        assert_eq!(ScriptType::from_code(code), Some(script_type));
        assert_eq!(script_type.purpose().number(), purpose);
        assert_eq!(ScriptType::parse_json_name(name), Some(script_type));
        for (net, coin) in [(BtcNetwork::Mainnet, 0), (BtcNetwork::Testnet4, 1)] {
            let node = net.account_node(script_type.purpose(), 7).unwrap();
            assert_eq!(
                btc_account_path(node).to_string(),
                format!("m/{purpose}'/{coin}'/7'")
            );
            assert_eq!(
                btc_path(node, BtcChain::Change, 3).unwrap().to_string(),
                format!("m/{purpose}'/{coin}'/7'/1/3")
            );
        }
    }
    assert_eq!(ScriptType::from_code(0), None);
    assert_eq!(ScriptType::from_code(5), None);
    assert_eq!(
        BtcCoin::Mainnet,
        BtcNetwork::Mainnet
            .account_node(BtcPurpose::Bip84, 0)
            .unwrap()
    );
    assert_eq!(
        BtcCoin::Test,
        BtcNetwork::Testnet4
            .account_node(BtcPurpose::Bip84, 0)
            .unwrap()
    );
    assert!(
        BtcNetwork::Mainnet
            .account_node(BtcPurpose::Bip44, 1 << 31)
            .is_err()
    );
    // Plain labels with the address prefix (spec/04 BTC 계정 추가).
    assert_eq!(
        ScriptType::P2wpkh.label(BtcNetwork::Mainnet),
        "네이티브 세그윗 (bc1q…, 권장)"
    );
    assert_eq!(
        ScriptType::P2tr.label(BtcNetwork::Mainnet),
        "탭루트 (bc1p…)"
    );
    assert_eq!(
        ScriptType::P2shP2wpkh.label(BtcNetwork::Mainnet),
        "호환 세그윗 (3…)"
    );
    assert_eq!(ScriptType::P2pkh.label(BtcNetwork::Mainnet), "레거시 (1…)");
    assert_eq!(
        ScriptType::P2wpkh.label(BtcNetwork::Testnet4),
        "네이티브 세그윗 (tb1q…, 권장)"
    );
    assert_eq!(
        ScriptType::P2tr.label(BtcNetwork::Testnet4),
        "탭루트 (tb1p…)"
    );
    assert_eq!(
        ScriptType::P2shP2wpkh.label(BtcNetwork::Testnet4),
        "호환 세그윗 (2…)"
    );
    assert_eq!(
        ScriptType::P2pkh.label(BtcNetwork::Testnet4),
        "레거시 (m·n…)"
    );
}

/// BIP49 test vector (testnet, `m/49'/1'/0'`); the testnet base58 version 0xc4 is testnet4's.
#[test]
fn bip49_vector() {
    let seed = about_seed();
    // account0Xpriv / account0Xpub use SLIP-132 `uprv`/`upub` versions: compare everything after
    // the 4 version bytes with our `tprv`/`tpub` serialization of the same node.
    let path = btc_account_path(
        BtcNetwork::Testnet4
            .account_node(BtcPurpose::Bip49, 0)
            .unwrap(),
    );
    assert_eq!(path.to_string(), "m/49'/1'/0'");
    for (version, expected) in [
        (
            XKeyVersion::Tprv,
            "uprv91G7gZkzehuMVxDJTYE6tLivdF8e4rvzSu1LFfKw3b2Qx1Aj8vpoFnHdfUZ3hmi9jsvPifmZ24RTN2KhwB8BfMLTVqaBReibyaFFcTP1s9n",
        ),
        (
            XKeyVersion::Tpub,
            "upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY",
        ),
    ] {
        let ours = encode_xkey(&derive_xkey(&seed, &path, version).unwrap());
        let ours = base58::decode_check(ours.expose()).unwrap();
        let theirs = base58::decode_check(expected).unwrap();
        assert_eq!(ours.len(), 78);
        assert_eq!(ours[4..], theirs[4..], "{version:?}");
    }
    let ctx = secp_context(&mut OsRandom).unwrap();
    let coin = BtcNetwork::Testnet4
        .account_node(BtcPurpose::Bip49, 0)
        .unwrap();
    let secret =
        secret_key_from_seed(&ctx, &seed, &btc_path(coin, BtcChain::Receive, 0).unwrap()).unwrap();
    assert_eq!(
        hex::encode(&secret.secret_bytes()),
        "c9bdb49cfbaedca21c4b1f3a7803c34636b1d7dc55a717132443fc3f4c5867e8"
    );
    let public = PublicKey::from_secret_key(&ctx, &secret).serialize();
    assert_eq!(
        hex::encode(&public),
        "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
    );
    let key_hash = hash160(&public);
    assert_eq!(
        hex::encode(&key_hash),
        "38971f73930f6c141d977ac4fd4a727c854935b3"
    );
    let push = p2sh_p2wpkh_script_sig(&key_hash);
    assert_eq!(
        hex::encode(&push[1..]),
        "001438971f73930f6c141d977ac4fd4a727c854935b3"
    );
    let account = hd_key(&seed, BtcNetwork::Testnet4, ScriptType::P2shP2wpkh, 0);
    let kind = account.kind(BtcChain::Receive, 0).unwrap();
    assert_eq!(
        kind,
        ScriptKind::P2sh(h("336caa13e08b96080a32b5d818d59b4ab3b36742"))
    );
    assert_eq!(
        account
            .address(BtcNetwork::Testnet4, BtcChain::Receive, 0)
            .unwrap()
            .as_str(),
        "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2"
    );
    assert_eq!(
        parse_address("2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2", BtcNetwork::Testnet4),
        Ok(kind)
    );
}

/// BIP84 test vector addresses through the account abstraction (`m/84'/0'/0'`).
#[test]
fn bip84_vector_through_accounts() {
    let account = hd_key(&about_seed(), BtcNetwork::Mainnet, ScriptType::P2wpkh, 0);
    assert_eq!(account.id(), BtcAccountId::PRIMARY);
    for (chain, index, address) in [
        (
            BtcChain::Receive,
            0,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        ),
        (
            BtcChain::Receive,
            1,
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
        ),
        (
            BtcChain::Change,
            0,
            "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
        ),
    ] {
        assert_eq!(
            account
                .address(BtcNetwork::Mainnet, chain, index)
                .unwrap()
                .as_str(),
            address
        );
    }
}

/// BIP86 test vector (`m/86'/0'/0'`): account keys, internal and output keys, scriptPubKeys
/// and bech32m addresses of `0/0`, `0/1`, `1/0`.
#[test]
fn bip86_vector() {
    let seed = about_seed();
    let master =
        encode_xkey(&derive_xkey(&seed, &"m".parse().unwrap(), XKeyVersion::Xprv).unwrap());
    assert_eq!(
        master.expose(),
        "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
    );
    let node = BtcNetwork::Mainnet
        .account_node(BtcPurpose::Bip86, 0)
        .unwrap();
    let path = btc_account_path(node);
    assert_eq!(path.to_string(), "m/86'/0'/0'");
    assert_eq!(
        encode_xkey(&derive_xkey(&seed, &path, XKeyVersion::Xprv).unwrap()).expose(),
        "xprv9xgqHN7yz9MwCkxsBPN5qetuNdQSUttZNKw1dcYTV4mkaAFiBVGQziHs3NRSWMkCzvgjEe3n9xV8oYywvM8at9yRqyaZVz6TYYhX98VjsUk"
    );
    assert_eq!(
        encode_xkey(&derive_xkey(&seed, &path, XKeyVersion::Xpub).unwrap()).expose(),
        "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"
    );
    let account = hd_key(&seed, BtcNetwork::Mainnet, ScriptType::P2tr, 0);
    let ctx = secp_context(&mut OsRandom).unwrap();
    for (chain, index, internal, output, address) in [
        (
            BtcChain::Receive,
            0,
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
            "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
        ),
        (
            BtcChain::Receive,
            1,
            "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145",
            "a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb",
            "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
        ),
        (
            BtcChain::Change,
            0,
            "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef",
            "882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc",
            "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
        ),
    ] {
        let deriver = account.deriver().unwrap();
        let BtcPubKey::Compressed(key) = deriver.pubkey(chain, index).unwrap() else {
            unreachable!("compressed");
        };
        assert_eq!(hex::encode(&key[1..]), internal);
        let tweaked = output_key(
            &ctx,
            &XOnlyPublicKey::from_byte_array(h(internal)).unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(hex::encode(&tweaked.serialize()), output);
        let kind = account.kind(chain, index).unwrap();
        assert_eq!(kind, ScriptKind::P2tr(h(output)));
        assert_eq!(hex::encode(&script_pubkey(&kind)), format!("5120{output}"));
        assert_eq!(
            account
                .address(BtcNetwork::Mainnet, chain, index)
                .unwrap()
                .as_str(),
            address
        );
        assert_eq!(parse_address(address, BtcNetwork::Mainnet), Ok(kind));
        // The private side: the key-path signing key's x-only public key is the output key.
        let coin = BtcNetwork::Mainnet
            .account_node(BtcPurpose::Bip86, 0)
            .unwrap();
        let secret =
            secret_key_from_seed(&ctx, &seed, &btc_path(coin, chain, index).unwrap()).unwrap();
        let pair = tweaked_keypair(&ctx, &secret, None).unwrap();
        assert_eq!(hex::encode(&pair.x_only_public_key().0.serialize()), output);
    }
}

/// BIP44 (no published vector): the account node's public derivation equals private derivation
/// and our P2PKH output is `HASH160` of the derived key under `m/44'/c'/a'`.
#[test]
fn bip44_public_equals_private() {
    let seed = about_seed();
    let ctx = secp_context(&mut OsRandom).unwrap();
    for net in BtcNetwork::ALL {
        let account = hd_key(&seed, net, ScriptType::P2pkh, 2);
        let coin = net.account_node(BtcPurpose::Bip44, 2).unwrap();
        for (chain, index) in [(BtcChain::Receive, 0), (BtcChain::Change, 9)] {
            let secret =
                secret_key_from_seed(&ctx, &seed, &btc_path(coin, chain, index).unwrap()).unwrap();
            let public = PublicKey::from_secret_key(&ctx, &secret).serialize();
            assert_eq!(
                account.kind(chain, index).unwrap(),
                ScriptKind::P2pkh(hash160(&public))
            );
            let address = account.address(net, chain, index).unwrap();
            assert!(match net {
                BtcNetwork::Mainnet => address.as_str().starts_with('1'),
                BtcNetwork::Testnet4 => address.as_str().starts_with(['m', 'n']),
            });
        }
    }
}

// ---- BIP143 P2SH-P2WPKH ----

/// BIP143 "P2SH-P2WPKH" example: hash parts, sighash, the signature with the BIP private key, our
/// redeem-script scriptSig and the exact signed transaction.
#[test]
fn bip143_p2sh_p2wpkh_vector() {
    let unsigned = parse_transaction(&hex::decode("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000").unwrap()).unwrap();
    assert_eq!(
        hex::encode(&hash_prevouts(&unsigned)),
        "b0287b4a252ac05af83d2dcef00ba313af78a3e9c329afa216eb3aa2a7b4613a"
    );
    assert_eq!(
        hex::encode(&hash_sequence(&unsigned)),
        "18606b350cd8bf565266bc352f0caddcf01e8fa789dd8a15386327cf8cabe198"
    );
    assert_eq!(
        hex::encode(&hash_outputs(&unsigned)),
        "de984f44532e2173ca0d64314fcefe6d30da6f8cf27bafa706da61df8a226c83"
    );
    let ctx = secp_context(&mut OsRandom).unwrap();
    let secret = SecretKey::from_byte_array(h(
        "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf",
    ))
    .unwrap();
    let public = PublicKey::from_secret_key(&ctx, &secret).serialize();
    assert_eq!(
        hex::encode(&public),
        "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873"
    );
    let key_hash = hash160(&public);
    assert_eq!(
        hex::encode(&key_hash),
        "79091972186c449eb1ded22b78e40d009bdf0089"
    );
    // Our output kind of this key as P2SH-P2WPKH is the example's scriptPubKey.
    assert_eq!(
        hex::encode(&script_pubkey(
            &kind_for_compressed(&ctx, ScriptType::P2shP2wpkh, &public).unwrap()
        )),
        "a9144733f37cf4db86fbc2efed2500b4f4e49f31202387"
    );
    let sighash =
        bip143_sighash_p2wpkh(&unsigned, 0, &key_hash, Sats::new(1_000_000_000).unwrap()).unwrap();
    assert_eq!(
        hex::encode(&sighash),
        "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"
    );
    let signature = sign_sighash(&ctx, &secret, &sighash).unwrap();
    assert_eq!(
        hex::encode(&signature),
        "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01"
    );
    let mut signed = unsigned;
    signed.inputs[0].script_sig = p2sh_p2wpkh_script_sig(&key_hash).to_vec();
    signed.inputs[0].witness = vec![signature, public.to_vec()];
    assert_eq!(
        hex::encode(&serialize(&signed, true)),
        "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000"
    );
}

// ---- BIP341 ----

/// BIP341 `wallet-test-vectors.json` `scriptPubKey`: the `TapTweak` of every case (with its
/// merkle root), the output key, scriptPubKey and BIP350 address.
#[test]
fn bip341_script_pubkey_vectors() {
    let vectors = vector_file(BIP341_WALLET);
    let cases = field(&vectors, "scriptPubKey").as_array().unwrap();
    assert_eq!(cases.len(), 7);
    let ctx = secp_context(&mut OsRandom).unwrap();
    for case in cases {
        let given = field(case, "given");
        let intermediary = field(case, "intermediary");
        let expected = field(case, "expected");
        let internal = XOnlyPublicKey::from_byte_array(h(text(given, "internalPubkey"))).unwrap();
        let root: Option<[u8; 32]> = field(intermediary, "merkleRoot").as_str().map(h);
        assert_eq!(
            hex::encode(&tap_tweak_hash(&internal, root.as_ref())),
            text(intermediary, "tweak")
        );
        let output = output_key(&ctx, &internal, root.as_ref()).unwrap();
        assert_eq!(
            hex::encode(&output.serialize()),
            text(intermediary, "tweakedPubkey")
        );
        let kind = ScriptKind::P2tr(output.serialize());
        assert_eq!(
            hex::encode(&script_pubkey(&kind)),
            text(expected, "scriptPubKey")
        );
        assert_eq!(
            encode_address(&kind, BtcNetwork::Mainnet),
            text(expected, "bip350Address")
        );
        assert_eq!(
            parse_address(text(expected, "bip350Address"), BtcNetwork::Mainnet),
            Ok(kind)
        );
    }
}

/// BIP341 `keyPathSpending`: every input's tweak and tweaked private key; the
/// `SIGHASH_DEFAULT` input's sigMsg, sigHash and signature (all-zero aux); and the fully signed
/// transaction's P2TR, P2PKH (legacy sighash) and P2WPKH (BIP143) signatures.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "every part of the BIP341 key-path vector"
)]
fn bip341_key_path_vectors() {
    let vectors = vector_file(BIP341_WALLET);
    let spending = &field(&vectors, "keyPathSpending").as_array().unwrap()[0];
    let given = field(spending, "given");
    let unsigned = parse_transaction(&hex::decode(text(given, "rawUnsignedTx")).unwrap()).unwrap();
    let prevouts: Vec<Prevout> = field(given, "utxosSpent")
        .as_array()
        .unwrap()
        .iter()
        .map(|utxo| Prevout {
            value: Sats::new(
                field(utxo, "amountSats")
                    .as_number()
                    .unwrap()
                    .as_u64()
                    .unwrap(),
            )
            .unwrap(),
            script_pubkey: hex::decode(text(utxo, "scriptPubKey")).unwrap(),
        })
        .collect();
    assert_eq!(prevouts.len(), unsigned.inputs.len());
    let ctx = secp_context(&mut OsRandom).unwrap();
    let mut default_checked = 0;
    for input in field(spending, "inputSpending").as_array().unwrap() {
        let given = field(input, "given");
        let intermediary = field(input, "intermediary");
        let index = usize::try_from(
            field(given, "txinIndex")
                .as_number()
                .unwrap()
                .as_u64()
                .unwrap(),
        )
        .unwrap();
        let hash_type = field(given, "hashType")
            .as_number()
            .unwrap()
            .as_u64()
            .unwrap();
        let root: Option<[u8; 32]> = field(given, "merkleRoot").as_str().map(h);
        let secret = SecretKey::from_byte_array(h(text(given, "internalPrivkey"))).unwrap();
        let internal = secret.x_only_public_key(&ctx).0;
        assert_eq!(
            hex::encode(&internal.serialize()),
            text(intermediary, "internalPubkey")
        );
        assert_eq!(
            hex::encode(&tap_tweak_hash(&internal, root.as_ref())),
            text(intermediary, "tweak")
        );
        let pair = tweaked_keypair(&ctx, &secret, root.as_ref()).unwrap();
        assert_eq!(
            hex::encode(&pair.secret_key().secret_bytes()),
            text(intermediary, "tweakedPrivkey")
        );
        // Our output key is the spent scriptPubKey's.
        let output = pair.x_only_public_key().0.serialize();
        assert_eq!(
            prevouts[index].script_pubkey,
            script_pubkey(&ScriptKind::P2tr(output))
        );
        if hash_type != 0 {
            continue;
        }
        let message = sig_msg_default(&unsigned, index, &prevouts).unwrap();
        assert_eq!(hex::encode(&message), text(intermediary, "sigMsg"));
        let sighash = sighash_default(&unsigned, index, &prevouts).unwrap();
        assert_eq!(hex::encode(&sighash), text(intermediary, "sigHash"));
        let (signature, tweaked) =
            sign_key_path(&ctx, &secret, root.as_ref(), &sighash, &[0; 32]).unwrap();
        assert_eq!(tweaked, output);
        let witness = field(field(input, "expected"), "witness")
            .as_array()
            .unwrap();
        assert_eq!(hex::encode(&signature), witness[0].as_str().unwrap());
        default_checked += 1;
    }
    assert_eq!(default_checked, 1);

    let signed = parse_transaction(
        &hex::decode(text(field(spending, "auxiliary"), "fullySignedTx")).unwrap(),
    )
    .unwrap();
    // Input 4 (SIGHASH_DEFAULT key path): our strict key-path check.
    let ScriptKind::P2tr(output) =
        super::address::kind_from_script(&prevouts[4].script_pubkey).unwrap()
    else {
        unreachable!("p2tr");
    };
    let sighash = sighash_default(&signed, 4, &prevouts).unwrap();
    assert_eq!(
        check_key_path_witness(&ctx, &signed.inputs[4].witness, &output, &sighash),
        Ok(())
    );
    // A different amount of another input changes the sighash (BIP341 commits to all of them).
    let mut lied = prevouts.clone();
    lied[0].value = Sats::new(lied[0].value.get() + 1).unwrap();
    let wrong = sighash_default(&signed, 4, &lied).unwrap();
    assert!(check_key_path_witness(&ctx, &signed.inputs[4].witness, &output, &wrong).is_err());
    // Input 2 (P2PKH, legacy sighash, SIGHASH_ALL): verify the vector's signature.
    let (sig_item, key) = split_p2pkh_script_sig(&signed.inputs[2].script_sig).unwrap();
    assert_eq!(
        prevouts[2].script_pubkey,
        script_pubkey(&ScriptKind::P2pkh(hash160(key)))
    );
    let (sighash_type, der) = sig_item.split_last().unwrap();
    assert_eq!(*sighash_type, 0x01);
    let legacy = legacy_sighash(&signed, 2, &prevouts[2].script_pubkey, 1).unwrap();
    ctx.verify_ecdsa(
        Message::from_digest(legacy),
        &Signature::from_der(der).unwrap(),
        &PublicKey::from_slice(key).unwrap(),
    )
    .unwrap();
    // Input 5 (P2WPKH, BIP143): verify the vector's signature.
    let [sig_item, key] = signed.inputs[5].witness.as_slice() else {
        unreachable!("p2wpkh witness");
    };
    let segwit = bip143_sighash_p2wpkh(&signed, 5, &hash160(key), prevouts[5].value).unwrap();
    let (_, der) = sig_item.split_last().unwrap();
    ctx.verify_ecdsa(
        Message::from_digest(segwit),
        &Signature::from_der(der).unwrap(),
        &PublicKey::from_slice(key).unwrap(),
    )
    .unwrap();
}

/// Bitcoin Core `sighash.json`: the legacy signature hash of every case with `SIGHASH_ALL`
/// semantics, no `OP_CODESEPARATOR` byte in the script, and a transaction the strict parser
/// accepts (the expected hash is in `uint256` display order).
#[test]
fn legacy_sighash_core_vectors() {
    let vectors = vector_file(CORE_SIGHASH);
    let mut checked = 0;
    for case in vectors.as_array().unwrap().iter().skip(1) {
        let row = case.as_array().unwrap();
        let script = hex::decode(row[1].as_str().unwrap()).unwrap();
        let index = usize::try_from(row[2].as_number().unwrap().as_i64().unwrap()).unwrap();
        let hash_type = u32::from_le_bytes(
            i32::try_from(row[3].as_number().unwrap().as_i64().unwrap())
                .unwrap()
                .to_le_bytes(),
        );
        if !legacy_is_all(hash_type) || script.contains(&0xab) {
            continue;
        }
        let Ok(tx) = parse_transaction(&hex::decode(row[0].as_str().unwrap()).unwrap()) else {
            continue;
        };
        let mut expected = h::<32>(row[4].as_str().unwrap());
        expected.reverse();
        assert_eq!(
            legacy_sighash(&tx, index, &script, hash_type),
            Some(expected),
            "{}",
            row[0].as_str().unwrap()
        );
        checked += 1;
    }
    // Every one of the 139 qualifying cases of the file parses and matches.
    assert_eq!(checked, 139);
    // Other hash types are refused (never produced by this wallet).
    let tx = parse_transaction(&hex::decode("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000").unwrap()).unwrap();
    for refused in [2, 3, 0x81, 0x82, 0x83] {
        assert_eq!(legacy_sighash(&tx, 0, &[], refused), None);
    }
    assert_eq!(legacy_sighash(&tx, 1, &[], 1), None);
}

// ---- full send flows ----

/// A previous transaction paying `value` to `script` (output 1, after a dummy output).
fn fake_prev(script: &[u8], value: u64, salt: u8) -> (Vec<u8>, Txid) {
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: Txid::from_bytes([salt; 32]),
                vout: 7,
            },
            script_sig: vec![0x51],
            sequence: 0xFFFF_FFFF,
            witness: Vec::new(),
        }],
        outputs: vec![
            TxOut {
                value: Sats::new(1_000).unwrap(),
                script_pubkey: vec![0x51],
            },
            TxOut {
                value: Sats::new(value).unwrap(),
                script_pubkey: script.to_vec(),
            },
        ],
        lock_time: 0,
    };
    (serialize(&tx, false), txid(&tx))
}

/// `meta` with three verified UTXOs (receive 0, receive 1 and change 0 for HD accounts; the one
/// address for a single key) found by the spec/08 §5 check.
fn funded_meta(net: BtcNetwork, account: BtcAccountKey) -> BtcMeta {
    let mut meta = BtcMeta::with_key(net, account);
    let paths: Vec<(BtcChain, u32)> = if account.is_single() {
        vec![(BtcChain::Receive, 0); 3]
    } else {
        let mut discovery = super::meta::Discovery::full();
        while let Some((chain, index)) = discovery.next_request() {
            discovery.observe(u64::from(
                (chain == BtcChain::Receive && index < 2)
                    || (chain == BtcChain::Change && index == 0),
            ));
        }
        discovery.apply(&mut meta).unwrap();
        vec![
            (BtcChain::Receive, 0),
            (BtcChain::Receive, 1),
            (BtcChain::Change, 0),
        ]
    };
    let mut listed = Vec::new();
    let mut newly = Vec::new();
    for ((chain, index), (value, salt)) in
        paths
            .into_iter()
            .zip([(60_000_u64, 0xc1_u8), (45_000, 0xc2), (90_000, 0xc3)])
    {
        let script = meta.expected_script(chain, index).unwrap();
        let (raw, prev_txid) = fake_prev(&script, value, salt);
        let prev = verify_prev_output(&raw, &prev_txid, 1, &script).unwrap();
        // Another script (e.g. another account type of the same key) is refused.
        let other_type = match meta.account().script_type() {
            ScriptType::P2tr => ScriptType::P2wpkh,
            _ => ScriptType::P2tr,
        };
        if let BtcPubKey::Compressed(key) = meta
            .account()
            .deriver()
            .unwrap()
            .pubkey(chain, index)
            .unwrap()
        {
            let ctx = secp_context(&mut OsRandom).unwrap();
            let wrong = script_pubkey(&kind_for_compressed(&ctx, other_type, &key).unwrap());
            assert!(verify_prev_output(&raw, &prev_txid, 1, &wrong).is_err());
        }
        let item = ListedUtxo {
            outpoint: OutPoint {
                txid: prev_txid,
                vout: 1,
            },
            chain,
            index,
            height: TIP - 12,
        };
        listed.push(item);
        newly.push(VerifiedUtxo::from_prev(&prev, &item));
    }
    let report = meta.apply_refresh(&listed, &newly, &[], &[]);
    assert_eq!(report.inserted, 3);
    meta
}

/// Recipients of every sendable kind (the second P2TR is a valid x-only key).
fn recipients() -> [ScriptKind; 5] {
    [
        ScriptKind::P2pkh([0x11; 20]),
        ScriptKind::P2sh([0x22; 20]),
        ScriptKind::P2wpkh([0x33; 20]),
        ScriptKind::P2wsh([0x44; 32]),
        ScriptKind::P2tr(h(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )),
    ]
}

fn plan_for(meta: &BtcMeta, recipient: ScriptKind, amount: SendAmount, seed: u8) -> SendPlan {
    let candidates = meta.spendable(TIP, &[]);
    plan_send(&SendRequest {
        network: meta.network(),
        account: meta.account(),
        recipient,
        amount,
        fee: FeeChoice {
            rate: FeeRate::from_sat_per_kvb(3_000),
            source: FeeSource::Manual,
        },
        candidates: &candidates,
        tip_height: TIP,
        change_next: meta.change_next(),
        layout_seed: [seed; 32],
        typed_fee_override: None,
        conflicts: &[],
    })
    .unwrap()
}

/// Draft → store issue → consume (the real approval path).
fn approve(meta: &BtcMeta, plan: &SendPlan) -> Approved {
    let facts = meta.send_facts(plan, TIP, &[]).unwrap();
    let draft = build_btc_request(ApprovalId([0x5c; 16]), plan, meta.account(), &facts).unwrap();
    let mut store = ApprovalStore::new();
    let request = store.issue(draft, NOW_MS, NOW_UNIX_MS).unwrap();
    store
        .consume(request.id, request.digest, NOW_MS + 1)
        .unwrap()
}

/// sign → verify → parse → journal record round trip, with the fee and size checks.
fn sign_and_check<K: BtcKeys>(keys: &K, meta: &BtcMeta, plan: &SendPlan) -> Vec<u8> {
    check_recorded_amounts(plan, &meta.recorded_amounts()).unwrap();
    let signed = sign_plan_with(keys, approve(meta, plan), plan, meta.account()).unwrap();
    let verified = verify_signed(&signed.raw, plan, meta.account()).unwrap();
    let parsed = parse_transaction(&signed.raw).unwrap();
    assert_eq!(serialize(&parsed, true), signed.raw);
    assert_eq!(
        parsed.has_witness(),
        meta.account().script_type().is_segwit()
    );
    if plan.txid_is_final() {
        assert_eq!(verified.txid(), plan.txid());
    }
    // Fee within bounds: exactly the plan's, at least the chosen rate over the real size, and the
    // estimate is an upper bound within 2 vB per input.
    assert_eq!(verified.fee(), plan.fee());
    assert!(verified.vsize() <= u64::from(plan.planned_vsize()));
    let inputs = u64::try_from(plan.inputs().len()).unwrap();
    assert!(
        u64::from(plan.planned_vsize()) - verified.vsize() <= 2 * inputs + 1,
        "{} vs {}",
        plan.planned_vsize(),
        verified.vsize()
    );
    assert!(rate_kvb(verified.fee(), verified.vsize()).unwrap() >= 3_000);
    assert_eq!(weight(&parsed), verified.weight());
    assert_eq!(vsize(&parsed), verified.vsize());
    // Every input spends one of our verified outputs with the account's script.
    for (input, planned) in parsed.inputs.iter().zip(plan.inputs()) {
        assert_eq!(input.prevout, planned.outpoint);
    }
    // Journal record (version 2 except BIP84 account 0) round trip.
    let record = BtcRecord::new_signed(plan, &signed, &verified, 1_790_000_000).unwrap();
    let body = record.encode().unwrap();
    assert_eq!(
        body[0],
        if meta.id() == BtcAccountId::PRIMARY {
            1
        } else {
            2
        }
    );
    assert_eq!(BtcRecord::decode(&body).unwrap(), record);
    assert_eq!(record.account, meta.id());
    assert_eq!(record.script_type, meta.account().script_type());
    if plan.replaces().is_none() {
        assert!(record.bump_source(meta.account()).is_none()); // Signed is not bumpable
    }
    signed.raw
}

/// Every account kind: HD accounts of the four types and imported single keys (compressed of
/// each type, uncompressed P2PKH), each sending to every destination type, send-max and to an
/// own address.
#[test]
fn full_send_flow_every_type() {
    let seed = about_seed();
    let ctx = secp_context(&mut OsRandom).unwrap();
    let mut keys = SeedKeys {
        seed,
        imported: Vec::new(),
        aux: [0x2a; 32],
    };
    let mut accounts = Vec::new();
    for net in BtcNetwork::ALL {
        for script_type in ScriptType::CHOICES {
            accounts.push((
                net,
                hd_key(
                    &seed,
                    net,
                    script_type,
                    u32::from(script_type == ScriptType::P2wpkh),
                ),
            ));
        }
        accounts.push((net, hd_key(&seed, net, ScriptType::P2wpkh, 0)));
    }
    for (tag, script_type, compressed) in [
        (1_u8, ScriptType::P2pkh, true),
        (2, ScriptType::P2shP2wpkh, true),
        (3, ScriptType::P2wpkh, true),
        (4, ScriptType::P2tr, true),
        (5, ScriptType::P2pkh, false),
    ] {
        let secret =
            SecretKey::from_byte_array([tag.wrapping_mul(17).wrapping_add(3); 32]).unwrap();
        let public = PublicKey::from_secret_key(&ctx, &secret);
        let pubkey = BtcPubKey::of_point(&public, compressed);
        let id = [tag; 16];
        keys.add_imported(id, secret, compressed, BtcNetwork::Testnet4, script_type);
        accounts.push((
            BtcNetwork::Testnet4,
            BtcAccountKey::single(id, script_type, pubkey).unwrap(),
        ));
    }
    assert!(
        BtcAccountKey::single(
            [9; 16],
            ScriptType::P2wpkh,
            BtcPubKey::of_point(
                &PublicKey::from_secret_key(&ctx, &SecretKey::from_byte_array([9; 32]).unwrap()),
                false
            )
        )
        .is_err()
    );
    for (net, account) in accounts {
        let meta = funded_meta(net, account);
        for (seed_byte, recipient) in recipients().into_iter().enumerate() {
            let plan = plan_for(
                &meta,
                recipient,
                SendAmount::Exact(Sats::new(70_000).unwrap()),
                u8::try_from(seed_byte).unwrap(),
            );
            assert_eq!(plan.account(), &account);
            assert!(plan.change().is_some());
            let raw = sign_and_check(&keys, &meta, &plan);
            // The change output is ours (HD: change chain; single key: the same address).
            let parsed = parse_transaction(&raw).unwrap();
            let change = plan.change().unwrap();
            let (chain, index) = account.change_path(change.index);
            assert_eq!(
                parsed.outputs[usize::try_from(change.vout).unwrap()].script_pubkey,
                account.script(chain, index).unwrap()
            );
            if account.is_single() {
                assert_eq!((chain, index), (BtcChain::Receive, 0));
            }
        }
        // Send-max to a P2TR destination and a send to our own receive address.
        let max = plan_for(&meta, recipients()[4], SendAmount::Max, 9);
        assert!(max.change().is_none() && max.inputs().len() == 3);
        sign_and_check(&keys, &meta, &max);
        let own = account.kind(BtcChain::Receive, 0).unwrap();
        let to_self = plan_for(&meta, own, SendAmount::Exact(Sats::new(20_000).unwrap()), 3);
        assert_eq!(
            meta.send_facts(&to_self, TIP, &[]).unwrap().own_recipient,
            Some((BtcChain::Receive, 0))
        );
        sign_and_check(&keys, &meta, &to_self);
    }
}

/// The vault lends derived keys of every purpose and account (`KeyRef::Btc` with the account
/// node) and imported keys (vault tag 4, `BtcImportedKeys`) of every address type: secret 1 in
/// its public testnet WIF forms, compressed for all four types and uncompressed for P2PKH. A
/// missing record is `RecordNotFound`, a record used as another type `KeyMismatch`, a locked
/// vault `InvalidState`; nothing is signed then.
#[test]
#[expect(clippy::too_many_lines, reason = "HD types, imported types, refusals")]
fn vault_signs_every_hd_and_imported_type() {
    use crate::keyimport::{ImportKey, ImportPreview, ImportSpec};
    const ONE_TEST_COMPRESSED: &str = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";
    const ONE_TEST_UNCOMPRESSED: &str = "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgwmaKkrx";
    let mut vault = about_vault();
    let seed = about_seed();
    for script_type in ScriptType::CHOICES {
        let account_number = 3;
        let coin = BtcNetwork::Testnet4
            .account_node(script_type.purpose(), account_number)
            .unwrap();
        let xpub = vault.btc_account_xpub(coin).unwrap();
        let account = BtcAccountKey::hd(script_type, account_number, xpub).unwrap();
        assert_eq!(
            account,
            hd_key(&seed, BtcNetwork::Testnet4, script_type, account_number)
        );
        let meta = funded_meta(BtcNetwork::Testnet4, account);
        let plan = plan_for(
            &meta,
            recipients()[2],
            SendAmount::Exact(Sats::new(80_000).unwrap()),
            4,
        );
        sign_and_check(&vault, &meta, &plan);
    }
    // Imported keys: one tag-4 record per (WIF, type), each signs as its own single-key account.
    let mut imported = Vec::new();
    for (wif, script_type) in [
        (ONE_TEST_COMPRESSED, ScriptType::P2wpkh),
        (ONE_TEST_COMPRESSED, ScriptType::P2tr),
        (ONE_TEST_COMPRESSED, ScriptType::P2shP2wpkh),
        (ONE_TEST_COMPRESSED, ScriptType::P2pkh),
        (ONE_TEST_UNCOMPRESSED, ScriptType::P2pkh),
    ] {
        let key = ImportKey::parse(ImportSpec::Btc(script_type), wif).unwrap();
        let ImportPreview::Btc(info) = key.preview().unwrap() else {
            unreachable!("a Bitcoin preview")
        };
        assert_eq!(info.network, BtcNetwork::Testnet4);
        let id = vault.import_key(key, 1_800_000_000).unwrap();
        let account = info.account_key(*id.as_bytes()).unwrap();
        assert_eq!(
            account.input_weight(),
            script_type.input_weight(info.compressed)
        );
        let meta = funded_meta(BtcNetwork::Testnet4, account);
        let plan = plan_for(
            &meta,
            recipients()[2],
            SendAmount::Exact(Sats::new(80_000).unwrap()),
            5,
        );
        // The public entry point (the vault is the only key lender outside the unit tests).
        let signed = sign_plan(&vault, approve(&meta, &plan), &plan, meta.account()).unwrap();
        verify_signed(&signed.raw, &plan, meta.account()).unwrap();
        sign_and_check(&vault, &meta, &plan);
        imported.push((*id.as_bytes(), info));
    }
    // No such record.
    let (p2wpkh_id, p2wpkh) = imported.first().cloned().unwrap();
    let missing = funded_meta(
        BtcNetwork::Testnet4,
        BtcAccountKey::single([7; 16], ScriptType::P2wpkh, p2wpkh.public_key).unwrap(),
    );
    let plan = plan_for(
        &missing,
        recipients()[0],
        SendAmount::Exact(Sats::new(30_000).unwrap()),
        2,
    );
    assert_eq!(
        sign_plan(&vault, approve(&missing, &plan), &plan, missing.account()),
        Err(SignError::Vault(crate::error::VaultError::RecordNotFound))
    );
    // The P2WPKH record presented as a P2SH-P2WPKH account: the record's type differs.
    let wrong_type = funded_meta(
        BtcNetwork::Testnet4,
        BtcAccountKey::single(p2wpkh_id, ScriptType::P2shP2wpkh, p2wpkh.public_key).unwrap(),
    );
    let plan = plan_for(
        &wrong_type,
        recipients()[0],
        SendAmount::Exact(Sats::new(30_000).unwrap()),
        2,
    );
    assert_eq!(
        sign_plan(
            &vault,
            approve(&wrong_type, &plan),
            &plan,
            wrong_type.account()
        ),
        Err(SignError::KeyMismatch { input: 0 })
    );
    // Locked: nothing is lent.
    let meta = funded_meta(BtcNetwork::Testnet4, p2wpkh.account_key(p2wpkh_id).unwrap());
    let plan = plan_for(
        &meta,
        recipients()[0],
        SendAmount::Exact(Sats::new(30_000).unwrap()),
        2,
    );
    vault.lock();
    assert_eq!(
        sign_plan(&vault, approve(&meta, &plan), &plan, meta.account()),
        Err(SignError::Vault(crate::error::VaultError::InvalidState))
    );
}

/// An imported secret of another network, type or compression is refused before signing.
#[test]
fn imported_key_must_match_account() {
    let ctx = secp_context(&mut OsRandom).unwrap();
    let secret = SecretKey::from_byte_array([0x31; 32]).unwrap();
    let public = PublicKey::from_secret_key(&ctx, &secret);
    let id = [0x31; 16];
    let account = BtcAccountKey::single(
        id,
        ScriptType::P2tr,
        BtcPubKey::Compressed(public.serialize()),
    )
    .unwrap();
    let meta = funded_meta(BtcNetwork::Testnet4, account);
    let plan = plan_for(
        &meta,
        recipients()[3],
        SendAmount::Exact(Sats::new(50_000).unwrap()),
        8,
    );
    for (net, script_type, compressed) in [
        (BtcNetwork::Mainnet, ScriptType::P2tr, true),
        (BtcNetwork::Testnet4, ScriptType::P2wpkh, true),
        (BtcNetwork::Testnet4, ScriptType::P2tr, false),
    ] {
        let mut keys = SeedKeys {
            seed: [0; 64],
            imported: Vec::new(),
            aux: [0; 32],
        };
        keys.add_imported(id, secret, compressed, net, script_type);
        assert!(matches!(
            sign_plan_with(&keys, approve(&meta, &plan), &plan, meta.account()),
            Err(SignError::KeyMismatch { .. })
        ));
    }
    // Another secret under the right record: its key is not the account's.
    let mut keys = SeedKeys {
        seed: [0; 64],
        imported: Vec::new(),
        aux: [0; 32],
    };
    keys.add_imported(
        id,
        SecretKey::from_byte_array([0x32; 32]).unwrap(),
        true,
        BtcNetwork::Testnet4,
        ScriptType::P2tr,
    );
    assert_eq!(
        sign_plan_with(&keys, approve(&meta, &plan), &plan, meta.account()),
        Err(SignError::KeyMismatch { input: 0 })
    );
}

/// Amount lies after signing: Taproot signatures commit to every input's amount, BIP143 to the
/// input's own, the legacy hash to none (only the fee check catches it).
#[test]
fn amount_commitments_by_type() {
    let seed = about_seed();
    let keys = SeedKeys {
        seed,
        imported: Vec::new(),
        aux: [1; 32],
    };
    for (script_type, expected) in [
        (ScriptType::P2tr, "taproot0"),
        (ScriptType::P2wpkh, "segwit1"),
        (ScriptType::P2shP2wpkh, "segwit1"),
        (ScriptType::P2pkh, "fee"),
    ] {
        let account = hd_key(&seed, BtcNetwork::Testnet4, script_type, 5);
        let meta = funded_meta(BtcNetwork::Testnet4, account);
        let plan = plan_for(
            &meta,
            recipients()[1],
            SendAmount::Exact(Sats::new(120_000).unwrap()),
            6,
        );
        assert!(plan.inputs().len() >= 2);
        let raw = sign_and_check(&keys, &meta, &plan);
        let mut lied = plan.clone();
        lied.inputs[1].value = Sats::new(lied.inputs[1].value.get() + 1).unwrap();
        let result = verify_signed(&raw, &lied, meta.account());
        match expected {
            "taproot0" => assert!(matches!(
                result,
                Err(PostSignError::Taproot { input: 0, .. })
            )),
            "segwit1" => assert!(matches!(
                result,
                Err(PostSignError::Signature { input: 1, .. })
            )),
            _ => assert_eq!(result, Err(PostSignError::FeeMismatch)),
        }
    }
}

/// Post-sign checks specific to the new types: a P2PKH scriptSig with another key, a P2SH
/// scriptSig changed, a Taproot witness with a sighash byte, a witness on a P2PKH input.
#[test]
fn post_sign_shapes_by_type() {
    let seed = about_seed();
    let keys = SeedKeys {
        seed,
        imported: Vec::new(),
        aux: [3; 32],
    };
    let legacy = funded_meta(
        BtcNetwork::Testnet4,
        hd_key(&seed, BtcNetwork::Testnet4, ScriptType::P2pkh, 0),
    );
    let plan = plan_for(
        &legacy,
        recipients()[2],
        SendAmount::Exact(Sats::new(30_000).unwrap()),
        1,
    );
    let raw = sign_and_check(&keys, &legacy, &plan);
    let mut tx = parse_transaction(&raw).unwrap();
    let (sig, key) = split_p2pkh_script_sig(&tx.inputs[0].script_sig).unwrap();
    let (sig, mut key) = (sig.to_vec(), key.to_vec());
    key[5] ^= 1;
    tx.inputs[0].script_sig = super::script::p2pkh_script_sig(&sig, &key).unwrap();
    assert!(verify_signed(&serialize(&tx, true), &plan, legacy.account()).is_err());
    let mut tx = parse_transaction(&raw).unwrap();
    tx.inputs[0].witness = vec![vec![1]];
    assert!(verify_signed(&serialize(&tx, true), &plan, legacy.account()).is_err());

    let nested = funded_meta(
        BtcNetwork::Testnet4,
        hd_key(&seed, BtcNetwork::Testnet4, ScriptType::P2shP2wpkh, 0),
    );
    let plan = plan_for(
        &nested,
        recipients()[0],
        SendAmount::Exact(Sats::new(30_000).unwrap()),
        2,
    );
    assert_eq!(plan.tx().inputs[0].script_sig.len(), 23);
    let raw = sign_and_check(&keys, &nested, &plan);
    let mut tx = parse_transaction(&raw).unwrap();
    tx.inputs[0].script_sig[5] ^= 1;
    assert_eq!(
        verify_signed(&serialize(&tx, true), &plan, nested.account()),
        Err(PostSignError::UnsignedMismatch)
    );

    let taproot = funded_meta(
        BtcNetwork::Testnet4,
        hd_key(&seed, BtcNetwork::Testnet4, ScriptType::P2tr, 0),
    );
    let plan = plan_for(
        &taproot,
        recipients()[3],
        SendAmount::Exact(Sats::new(30_000).unwrap()),
        3,
    );
    let raw = sign_and_check(&keys, &taproot, &plan);
    let mut tx = parse_transaction(&raw).unwrap();
    tx.inputs[0].witness[0].push(0x01);
    assert_eq!(
        verify_signed(&serialize(&tx, true), &plan, taproot.account()),
        Err(PostSignError::WitnessShape { input: 0 })
    );
    let mut tx = parse_transaction(&raw).unwrap();
    tx.inputs[0].witness[0][10] ^= 1;
    assert!(matches!(
        verify_signed(&serialize(&tx, true), &plan, taproot.account()),
        Err(PostSignError::Taproot { input: 0, .. })
    ));
}

/// The payload binds the account: BIP84 account 0 keeps the original layout; every other
/// account appends its block; two accounts of one key never share a payload.
#[test]
fn payload_binds_account() {
    let seed = about_seed();
    let primary = funded_meta(
        BtcNetwork::Testnet4,
        hd_key(&seed, BtcNetwork::Testnet4, ScriptType::P2wpkh, 0),
    );
    let plan = plan_for(
        &primary,
        recipients()[2],
        SendAmount::Exact(Sats::new(10_000).unwrap()),
        1,
    );
    let payload = btc_payload(&plan);
    assert!(payload_header(&payload).is_some());
    let other = funded_meta(
        BtcNetwork::Testnet4,
        hd_key(&seed, BtcNetwork::Testnet4, ScriptType::P2tr, 2),
    );
    let plan = plan_for(
        &other,
        recipients()[2],
        SendAmount::Exact(Sats::new(10_000).unwrap()),
        1,
    );
    let payload = btc_payload(&plan);
    assert_eq!(&payload[payload.len() - 19..payload.len() - 16], &[1, 1, 4]);
    assert_eq!(
        &payload[payload.len() - 16..payload.len() - 12],
        &2_u32.to_be_bytes()
    );
    assert!(payload_header(&payload).is_some());
    let mut broken = payload.clone();
    let at = broken.len() - 19;
    broken[at] = 2;
    assert!(payload_header(&broken).is_none());
    assert!(payload_header(&payload[..payload.len() - 1]).is_none());
    // Approval of one account's plan does not sign for another account.
    let ctx = secp_context(&mut OsRandom).unwrap();
    let public = PublicKey::from_secret_key(&ctx, &SecretKey::from_byte_array([5; 32]).unwrap());
    let as_p2wpkh = BtcAccountKey::single(
        [5; 16],
        ScriptType::P2wpkh,
        BtcPubKey::Compressed(public.serialize()),
    )
    .unwrap();
    assert_eq!(as_p2wpkh.identity(), public.serialize());
    let meta = funded_meta(BtcNetwork::Testnet4, as_p2wpkh);
    let plan = plan_for(
        &meta,
        recipients()[2],
        SendAmount::Exact(Sats::new(10_000).unwrap()),
        1,
    );
    let approved = Approved::for_test(
        ChainRef::Bitcoin {
            network: plan.network().id(),
            genesis: plan.network().genesis(),
        },
        AccountRef::Bitcoin(as_p2wpkh.identity()),
        Signer::FromPayload,
        plan.kind(),
        SigningPayload::Btc(btc_payload(&plan)),
    );
    let mut lied = plan.clone();
    lied.account = BtcAccountKey::single(
        [5; 16],
        ScriptType::P2pkh,
        BtcPubKey::Compressed(public.serialize()),
    )
    .unwrap();
    let keys = SeedKeys {
        seed,
        imported: Vec::new(),
        aux: [0; 32],
    };
    assert_eq!(
        sign_plan_with(&keys, approved, &lied, &lied.account),
        Err(SignError::ApprovalMismatch)
    );
}

/// `BtcMeta` JSON: version 1 for BIP84 account 0 (unchanged keys), version 2 for every other
/// account (HD and imported) with strict validation, and the `btc_accounts` container.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "both versions and the container, with their refusals"
)]
fn meta_versions_and_accounts_codec() {
    let seed = about_seed();
    let primary = funded_meta(
        BtcNetwork::Mainnet,
        hd_key(&seed, BtcNetwork::Mainnet, ScriptType::P2wpkh, 0),
    );
    let v1 = primary.to_json();
    let object = v1.as_object().unwrap();
    assert_eq!(
        object.get("version").unwrap().as_number().unwrap().as_u64(),
        Some(1)
    );
    assert!(object.get("account_pubkey").is_some() && object.get("script_type").is_none());
    assert_eq!(BtcMeta::from_json(&v1).unwrap(), primary);
    assert_eq!(
        super::meta::btc_meta_from_json(&v1).unwrap(),
        Some(primary.clone())
    );

    let ctx = secp_context(&mut OsRandom).unwrap();
    let public = PublicKey::from_secret_key(&ctx, &SecretKey::from_byte_array([8; 32]).unwrap());
    let mut accounts = BtcAccounts::default();
    for meta in [
        funded_meta(
            BtcNetwork::Mainnet,
            hd_key(&seed, BtcNetwork::Mainnet, ScriptType::P2tr, 0),
        ),
        funded_meta(
            BtcNetwork::Mainnet,
            hd_key(&seed, BtcNetwork::Mainnet, ScriptType::P2wpkh, 1),
        ),
        funded_meta(
            BtcNetwork::Testnet4,
            hd_key(&seed, BtcNetwork::Testnet4, ScriptType::P2pkh, 0),
        ),
        funded_meta(
            BtcNetwork::Mainnet,
            BtcAccountKey::single(
                [8; 16],
                ScriptType::P2pkh,
                BtcPubKey::Uncompressed(public.serialize_uncompressed()),
            )
            .unwrap(),
        ),
    ] {
        let json = meta.to_json();
        assert_eq!(
            json.as_object()
                .unwrap()
                .get("version")
                .unwrap()
                .as_number()
                .unwrap()
                .as_u64(),
            Some(2)
        );
        assert_eq!(BtcMeta::from_json(&json).unwrap(), meta);
        // A version 2 object is not meta `btc`.
        assert!(super::meta::btc_meta_from_json(&json).is_err());
        accounts.upsert(meta).unwrap();
    }
    assert!(accounts.upsert(primary.clone()).is_err());
    accounts.selected = Some(BtcAccountId::Hd {
        script_type: ScriptType::P2tr,
        account: 0,
    });
    let json = accounts.to_json();
    let decoded = BtcAccounts::from_json(Some(&json)).unwrap();
    assert_eq!(decoded, accounts);
    assert_eq!(
        BtcAccounts::from_json(None).unwrap(),
        BtcAccounts::default()
    );
    assert_eq!(
        decoded.selected_on(BtcNetwork::Mainnet),
        BtcAccountId::Hd {
            script_type: ScriptType::P2tr,
            account: 0
        }
    );
    // The P2TR account is mainnet only: testnet4 falls back to BIP84 account 0.
    assert_eq!(
        decoded.selected_on(BtcNetwork::Testnet4),
        BtcAccountId::PRIMARY
    );
    assert_eq!(
        decoded.next_hd_account(BtcNetwork::Mainnet, ScriptType::P2wpkh),
        Some(2)
    );
    assert_eq!(
        decoded.next_hd_account(BtcNetwork::Mainnet, ScriptType::P2tr),
        Some(1)
    );
    assert_eq!(
        decoded.next_hd_account(BtcNetwork::Testnet4, ScriptType::P2tr),
        Some(0)
    );
    // Strictness: unknown keys, a version 2 BIP84 account 0, a single key with two addresses.
    let text_of = |value: &Value| String::from_utf8(yw_json::to_vec(value)).unwrap();
    let accounts_text = text_of(&json);
    let limits = Limits {
        max_bytes: 1 << 20,
        max_depth: 16,
        max_nodes: 1 << 20,
        max_items: 1 << 20,
    };
    let reparse = |text: &str| {
        BtcAccounts::from_json(Some(&yw_json::parse(text.as_bytes(), &limits).unwrap()))
    };
    assert!(reparse(&accounts_text.replacen("\"version\":1", "\"version\":1,\"x\":1", 1)).is_err());
    assert!(
        reparse(&accounts_text.replacen(
            "\"script_type\":\"p2tr\",\"key\":{\"hd\":{\"account\":0",
            "\"script_type\":\"p2wpkh\",\"key\":{\"hd\":{\"account\":0",
            1
        ))
        .is_err()
    );
    assert!(
        reparse(&accounts_text.replacen(
            "\"receive_next\":1,\"change_next\":0",
            "\"receive_next\":2,\"change_next\":0",
            1
        ))
        .is_err()
    );
    let single_meta = BtcMeta::with_key(
        BtcNetwork::Testnet4,
        BtcAccountKey::single(
            [8; 16],
            ScriptType::P2tr,
            BtcPubKey::Compressed(public.serialize()),
        )
        .unwrap(),
    );
    assert_eq!(
        (single_meta.receive_next(), single_meta.change_next()),
        (1, 0)
    );
    assert!(single_meta.discovery_done());
    assert_eq!(single_meta.watch_set().unwrap().len(), 1);
    let mut single_meta = single_meta;
    assert_eq!(
        single_meta.new_receive_address(true),
        Err(super::meta::MetaError::SingleAddress)
    );
    assert_eq!(
        single_meta.receive_address(),
        Ok(super::meta::ReceiveAddress::Existing(0))
    );
}

/// Key sources: derived keys name the account node, imported keys their record.
#[test]
fn key_sources() {
    let seed = about_seed();
    let account = hd_key(&seed, BtcNetwork::Mainnet, ScriptType::P2shP2wpkh, 4);
    let source = account.key_source(BtcChain::Change, 9);
    assert_eq!(
        source,
        BtcKeySource::Derived {
            script_type: ScriptType::P2shP2wpkh,
            account: 4,
            chain: BtcChain::Change,
            index: 9
        }
    );
    assert_eq!(
        btc_path(
            source.coin(BtcNetwork::Mainnet).unwrap(),
            BtcChain::Change,
            9
        )
        .unwrap()
        .to_string(),
        "m/49'/0'/4'/1/9"
    );
    assert_eq!(
        account.path_text(BtcNetwork::Mainnet, BtcChain::Change, 9),
        "m/49'/0'/4'/1/9"
    );
    assert_eq!(account.display_name(), "호환 세그윗 계정 4");
    let ctx = secp_context(&mut OsRandom).unwrap();
    let public = PublicKey::from_secret_key(&ctx, &SecretKey::from_byte_array([4; 32]).unwrap());
    let single = BtcAccountKey::single(
        [4; 16],
        ScriptType::P2pkh,
        BtcPubKey::Uncompressed(public.serialize_uncompressed()),
    )
    .unwrap();
    assert_eq!(
        single.key_source(BtcChain::Receive, 0),
        BtcKeySource::Imported {
            id: [4; 16],
            script_type: ScriptType::P2pkh,
            compressed: false
        }
    );
    assert_eq!(
        single
            .key_source(BtcChain::Receive, 0)
            .coin(BtcNetwork::Mainnet),
        None
    );
    assert_eq!(single.input_weight(), 716);
    assert_eq!(single.identity(), public.serialize());
    assert!(single.kind(BtcChain::Receive, 1).is_err());
    assert!(single.kind(BtcChain::Change, 0).is_err());
    assert_eq!(single.change_path(7), (BtcChain::Receive, 0));
    assert_eq!(single.display_name(), "가져온 키 · 레거시");
    assert_eq!(BtcAccountId::PRIMARY.activity_tag(), "");
    assert_eq!(account.id().activity_tag(), "p2sh-p2wpkh/4");
    assert_eq!(
        single.id().activity_tag(),
        format!("imported/{}", "04".repeat(16))
    );
}

/// A key-only wallet's accounts (no BIP84 account 0, spec/08 §3.5): the selected account, else
/// the first account of the network, is active and the first one holds the wallet-level tip;
/// removing an account clears its selection and the next holder keeps the higher tip.
#[test]
fn accounts_without_primary() {
    let ctx = secp_context(&mut OsRandom).unwrap();
    let key = |byte: u8, script_type| {
        let public =
            PublicKey::from_secret_key(&ctx, &SecretKey::from_byte_array([byte; 32]).unwrap());
        BtcAccountKey::single(
            [byte; 16],
            script_type,
            BtcPubKey::Compressed(public.serialize()),
        )
        .unwrap()
    };
    let first = key(0x21, ScriptType::P2tr);
    let second = key(0x22, ScriptType::P2pkh);
    let mainnet = key(0x23, ScriptType::P2wpkh);
    let mut accounts = BtcAccounts::default();
    assert_eq!(accounts.active_on(BtcNetwork::Testnet4, false), None);
    assert_eq!(
        accounts.active_on(BtcNetwork::Testnet4, true),
        Some(BtcAccountId::PRIMARY)
    );
    assert_eq!(accounts.tip_holder(BtcNetwork::Testnet4, false), None);
    let mut holder = BtcMeta::with_key(BtcNetwork::Testnet4, first);
    assert_eq!(holder.observe_tip(1_000), Ok(true));
    accounts.upsert(holder).unwrap();
    accounts
        .upsert(BtcMeta::with_key(BtcNetwork::Testnet4, second))
        .unwrap();
    accounts
        .upsert(BtcMeta::with_key(BtcNetwork::Mainnet, mainnet))
        .unwrap();
    assert_eq!(
        accounts.active_on(BtcNetwork::Testnet4, false),
        Some(first.id())
    );
    assert_eq!(
        accounts.active_on(BtcNetwork::Testnet4, true),
        Some(BtcAccountId::PRIMARY)
    );
    assert_eq!(
        accounts.tip_holder(BtcNetwork::Testnet4, false),
        Some(first.id())
    );
    assert_eq!(
        accounts.tip_holder(BtcNetwork::Testnet4, true),
        Some(BtcAccountId::PRIMARY)
    );
    accounts.selected = Some(second.id());
    assert_eq!(
        accounts.active_on(BtcNetwork::Testnet4, false),
        Some(second.id())
    );
    // A selection of the other network falls back to that network's first account.
    assert_eq!(
        accounts.active_on(BtcNetwork::Mainnet, false),
        Some(mainnet.id())
    );
    // Removing the tip holder: the next account keeps the higher tip; the selection stays.
    let removed = accounts
        .remove(BtcNetwork::Testnet4, first.id(), false)
        .unwrap();
    assert_eq!(removed.max_tip_seen(), 1_000);
    assert_eq!(
        accounts.tip_holder(BtcNetwork::Testnet4, false),
        Some(second.id())
    );
    assert_eq!(
        accounts
            .get(BtcNetwork::Testnet4, second.id())
            .unwrap()
            .max_tip_seen(),
        1_000
    );
    assert_eq!(accounts.selected, Some(second.id()));
    // Removing the selected one clears the selection; testnet4 has no account left.
    accounts
        .remove(BtcNetwork::Testnet4, second.id(), false)
        .unwrap();
    assert_eq!(accounts.selected, None);
    assert_eq!(accounts.active_on(BtcNetwork::Testnet4, false), None);
    assert!(
        accounts
            .remove(BtcNetwork::Testnet4, second.id(), false)
            .is_none()
    );
    assert_eq!(accounts.accounts.len(), 1);
}
