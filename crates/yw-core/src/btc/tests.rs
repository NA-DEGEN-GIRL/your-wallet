//! Bitcoin tests that need keys, the vault or crate internals (spec/09 §2.1): BIP84 account
//! nodes and addresses from an unlocked test vault, `CKDpub` against private derivation
//! (spec/08 §14.1, spec/02 §11.4), the BIP143 native P2WPKH signature with the BIP private key
//! (`sign_sighash`, low-R on the first try) and the strict witness signature checker.
#![expect(
    clippy::indexing_slicing,
    reason = "test fixtures index buffers of known length"
)]

use secp256k1::ecdsa::Signature;
use secp256k1::{Message, PublicKey, SecretKey};

use super::address::{BtcAddress, ScriptKind, hash160, p2wpkh_program, parse_address};
use super::amount::Sats;
use super::network::BtcNetwork;
use super::sighash::{bip143_sighash_p2wpkh, hash_outputs, hash_prevouts, hash_sequence};
use super::sign::{WitnessSigError, check_witness_signature, sign_sighash};
use super::tx::{parse_transaction, serialize, txid, vsize, weight};
use crate::bip32::derive_public_child;
use crate::bip32::path::{BtcChain, BtcCoin};
use crate::bip39::Mnemonic;
use crate::entropy::{OsRandom, secp_context};
use crate::hex;
use crate::vault::tests::unlocked_with;

const ABOUT: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// The unlocked `abandon`×11 `about` test vault (shared with `send_tests`, which holds no key
/// material itself).
pub(super) fn about_vault() -> crate::vault::Vault {
    unlocked_with(ABOUT)
}

fn h<const N: usize>(text: &str) -> [u8; N] {
    hex::decode_array::<N>(text).unwrap()
}

/// spec/08 §14.1 account rows: `m/84'/0'/0'` and `m/84'/1'/0'` of `abandon`×11 `about`.
#[test]
fn bip84_account_nodes() {
    let vault = unlocked_with(ABOUT);
    let mainnet = vault.btc_account_xpub(BtcCoin::Mainnet).unwrap();
    assert_eq!(
        hex::encode(&mainnet.pubkey),
        "02707a62fdacc26ea9b63b1c197906f56ee0180d0bcf1966e1a2da34f5f3a09a9b"
    );
    assert_eq!(
        hex::encode(&mainnet.chain_code),
        "4a53a0ab21b9dc95869c4e92a161194e03c0ef3ff5014ac692f433c4765490fc"
    );
    let testnet = vault.btc_account_xpub(BtcCoin::Test).unwrap();
    assert_eq!(
        hex::encode(&testnet.pubkey),
        "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4"
    );
    assert_eq!(
        hex::encode(&testnet.chain_code),
        "3c8c2037ee4c1621da0d348db51163709a622d0d2838dde6d8419c51f6301c62"
    );
    assert_eq!(
        BtcNetwork::Mainnet.coin_type(),
        BtcCoin::Mainnet,
        "coin type of the network table"
    );
    assert_eq!(BtcNetwork::Testnet4.coin_type(), BtcCoin::Test);
}

/// `CKDpub` from the cached account node (two `derive_public_child` steps) equals private
/// derivation (`btc_public_key`) for both coins, both chains, indices 0–19 (spec/08 §14.1).
#[test]
fn ckdpub_equals_private_derivation() {
    let vault = unlocked_with(ABOUT);
    for coin in [BtcCoin::Mainnet, BtcCoin::Test] {
        let account = vault.btc_account_xpub(coin).unwrap();
        for chain in [BtcChain::Receive, BtcChain::Change] {
            let chain_node = derive_public_child(&account, chain.index()).unwrap();
            for index in 0..20 {
                let public = derive_public_child(&chain_node, index).unwrap().pubkey;
                let private = vault.btc_public_key(coin, chain, index).unwrap();
                assert_eq!(public, private, "{coin:?} {chain:?} {index}");
                assert_eq!(
                    p2wpkh_program(&account, chain, index).unwrap(),
                    hash160(&private)
                );
            }
        }
    }
}

/// BIP84 rows (spec/08 §14.1, spec/09 §3.10) with the address strings, through the cached
/// account node, `p2wpkh_program`, `BtcAddress` and back through `parse_address`.
#[test]
fn bip84_addresses() {
    let vault = unlocked_with(ABOUT);
    let rows = [
        (
            BtcNetwork::Mainnet,
            BtcChain::Receive,
            0,
            "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        ),
        (
            BtcNetwork::Mainnet,
            BtcChain::Receive,
            1,
            "03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77",
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
        ),
        (
            BtcNetwork::Mainnet,
            BtcChain::Change,
            0,
            "03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6",
            "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
        ),
        (
            BtcNetwork::Testnet4,
            BtcChain::Receive,
            0,
            "02e7ab2537b5d49e970309aae06e9e49f36ce1c9febbd44ec8e0d1cca0b4f9c319",
            "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl",
        ),
    ];
    for (net, chain, index, pubkey, address) in rows {
        let coin = net.coin_type();
        assert_eq!(
            hex::encode(&vault.btc_public_key(coin, chain, index).unwrap()),
            pubkey
        );
        let account = vault.btc_account_xpub(coin).unwrap();
        let program = p2wpkh_program(&account, chain, index).unwrap();
        let ours = BtcAddress::p2wpkh(net, &program);
        assert_eq!(ours.as_str(), address);
        assert_eq!(ours.to_string(), address);
        assert_eq!(ours.network(), net);
        assert_eq!(ours.kind(), ScriptKind::P2wpkh(program));
        assert_eq!(&ours.script_pubkey()[2..], program.as_slice());
        assert_eq!(parse_address(address, net), Ok(ScriptKind::P2wpkh(program)));
    }
    let account = vault.btc_account_xpub(BtcCoin::Mainnet).unwrap();
    assert_eq!(
        hex::encode(&p2wpkh_program(&account, BtcChain::Receive, 0).unwrap()),
        "c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2"
    );
    assert_eq!(
        p2wpkh_program(&account, BtcChain::Receive, 0x8000_0000),
        Err(crate::error::KeyError::InvalidPath)
    );
}

/// spec/09 §3.10 [local] 24-word rows (`abandon`×23 `art`, mainnet).
#[test]
fn bip84_art_rows() {
    let art = Mnemonic::from_entropy(&[0; 32]).unwrap().phrase();
    let vault = unlocked_with(art.expose());
    let account = vault.btc_account_xpub(BtcCoin::Mainnet).unwrap();
    assert_eq!(
        hex::encode(
            &vault
                .btc_public_key(BtcCoin::Mainnet, BtcChain::Receive, 0)
                .unwrap()
        ),
        "03c5db199831f23a3a1575518c8e9e948bfd495481aac442dec64b447ee76bd6fa"
    );
    for (chain, index, address) in [
        (
            BtcChain::Receive,
            0,
            "bc1qzmtrqsfuaf6l6kkcsseumq26ukaphfj9skkug6",
        ),
        (
            BtcChain::Receive,
            1,
            "bc1qyn0ml52dy0udru3nafudt6af7x2kv7ngysfk0k",
        ),
        (
            BtcChain::Change,
            0,
            "bc1qes80p0st92xjem9aw48v57fk35f44kjzm2064m",
        ),
    ] {
        let program = p2wpkh_program(&account, chain, index).unwrap();
        assert_eq!(
            BtcAddress::p2wpkh(BtcNetwork::Mainnet, &program).as_str(),
            address
        );
    }
}

const BIP143_UNSIGNED: &str = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
/// BIP143 native P2WPKH: the second input's key.
const BIP143_PRIVATE_KEY: &str = "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9";
const BIP143_PUBKEY: &str = "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357";
const BIP143_WITNESS_SIG: &str = "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01";
/// First input's scriptSig in the BIP's signed transaction (P2PK, not ours).
const BIP143_P2PK_SCRIPT_SIG: &str = "4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01";
const BIP143_SIGNED: &str = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";

/// BIP143 Native P2WPKH (spec/08 §14.1): hash parts, sighash, the low-R RFC 6979 signature equal
/// to the BIP's byte for byte on the first try, and the signed transaction rebuilt from it.
#[test]
fn bip143_native_p2wpkh_signature() {
    let unsigned = parse_transaction(&hex::decode(BIP143_UNSIGNED).unwrap()).unwrap();
    assert_eq!(
        hex::encode(&hash_prevouts(&unsigned)),
        "96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37"
    );
    assert_eq!(
        hex::encode(&hash_sequence(&unsigned)),
        "52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b"
    );
    assert_eq!(
        hex::encode(&hash_outputs(&unsigned)),
        "863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5"
    );
    let ctx = secp_context(&mut OsRandom).unwrap();
    let mut secret = SecretKey::from_byte_array(h::<32>(BIP143_PRIVATE_KEY)).unwrap();
    let public = PublicKey::from_secret_key(&ctx, &secret).serialize();
    assert_eq!(hex::encode(&public), BIP143_PUBKEY);
    let program = hash160(&public);
    assert_eq!(
        hex::encode(&program),
        "1d0f172a0ecb48aee1be1f2687d2963ae33f71a1"
    );
    let sighash =
        bip143_sighash_p2wpkh(&unsigned, 1, &program, Sats::new(600_000_000).unwrap()).unwrap();
    assert_eq!(
        hex::encode(&sighash),
        "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
    );
    assert_eq!(
        bip143_sighash_p2wpkh(&unsigned, 2, &program, Sats::ZERO),
        None
    );
    let item = sign_sighash(&ctx, &secret, &sighash).unwrap();
    assert_eq!(hex::encode(&item), BIP143_WITNESS_SIG);
    // Low-R on the first try: the plain RFC 6979 signature is already the low-R one.
    let message = Message::from_digest(sighash);
    assert_eq!(
        ctx.sign_ecdsa(message, &secret),
        ctx.sign_ecdsa_low_r(message, &secret)
    );
    secret.non_secure_erase();
    assert_eq!(check_witness_signature(&item, &public, &sighash), Ok(()));

    let mut signed = unsigned;
    signed.inputs[0].script_sig = hex::decode(BIP143_P2PK_SCRIPT_SIG).unwrap();
    signed.inputs[1].witness = vec![item, public.to_vec()];
    let bytes = serialize(&signed, true);
    assert_eq!(hex::encode(&bytes), BIP143_SIGNED);
    assert_eq!(parse_transaction(&bytes).unwrap(), signed);
    assert_eq!(
        txid(&signed).to_display_hex(),
        "e8151a2af31c368a35053ddd4bdb285a8595c769a3ad83e0fa02314a602d4609"
    );
    assert_eq!(weight(&signed), 1042);
    assert_eq!(vsize(&signed), 261);
}

/// `n - s` for a 32-byte big-endian `s < n`.
fn negate_scalar(s: &[u8]) -> [u8; 32] {
    let order = h::<32>("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    let mut out = [0_u8; 32];
    let mut borrow = 0_i16;
    for index in (0..32).rev() {
        let mut value = i16::from(order[index]) - i16::from(s[index]) - borrow;
        borrow = i16::from(value < 0);
        if value < 0 {
            value += 256;
        }
        out[index] = u8::try_from(value).unwrap();
    }
    out
}

fn with_sighash_byte(der: &[u8]) -> Vec<u8> {
    let mut item = der.to_vec();
    item.push(0x01);
    item
}

/// spec/08 §11.2-3/-5 rejections of the strict witness signature checker.
#[test]
#[expect(clippy::too_many_lines, reason = "one case per checker rule")]
fn witness_signature_checker_rejections() {
    let item = h::<71>(BIP143_WITNESS_SIG);
    let public = h::<33>(BIP143_PUBKEY);
    let sighash = h::<32>("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");
    let der = &item[..70];
    assert_eq!(check_witness_signature(&item, &public, &sighash), Ok(()));

    let mut other_type = item;
    other_type[70] = 0x81;
    assert_eq!(
        check_witness_signature(&other_type, &public, &sighash),
        Err(WitnessSigError::SighashType)
    );
    assert_eq!(
        check_witness_signature(&[], &public, &sighash),
        Err(WitnessSigError::SighashType)
    );
    assert_eq!(
        check_witness_signature(&item[..70], &public, &sighash),
        Err(WitnessSigError::SighashType)
    );

    // High-S twin: s > n/2 needs 33 DER bytes, so with a 32-byte r the DER is 71 bytes.
    let high_s_item = |signature: &Signature| {
        let compact = signature.serialize_compact();
        let mut high = compact;
        high[32..].copy_from_slice(&negate_scalar(&compact[32..]));
        with_sighash_byte(
            Signature::from_compact(&high)
                .unwrap()
                .serialize_der()
                .as_ref(),
        )
    };
    let twin = high_s_item(&Signature::from_der(der).unwrap());
    assert_eq!(twin.len(), 72);
    assert_eq!(
        check_witness_signature(&twin, &public, &sighash),
        Err(WitnessSigError::DerTooLong)
    );
    // With a 31-byte r (r < 2^247) the high-S twin fits in 70 DER bytes and only low-S rejects it.
    let ctx = secp_context(&mut OsRandom).unwrap();
    let secret = SecretKey::from_byte_array(h::<32>(BIP143_PRIVATE_KEY)).unwrap();
    let (short_r, short_hash) = (0_u16..=u16::MAX)
        .find_map(|seed| {
            let mut digest = [0x5a_u8; 32];
            digest[..2].copy_from_slice(&seed.to_be_bytes());
            let signature = ctx.sign_ecdsa(Message::from_digest(digest), &secret);
            let compact = signature.serialize_compact();
            (compact[0] == 0 && compact[1] < 0x80).then_some((signature, digest))
        })
        .unwrap();
    let short_item = with_sighash_byte(short_r.serialize_der().as_ref());
    assert_eq!(
        check_witness_signature(&short_item, &public, &short_hash),
        Ok(())
    );
    let high_short = high_s_item(&short_r);
    assert_eq!(high_short.len(), 71);
    assert_eq!(
        check_witness_signature(&high_short, &public, &short_hash),
        Err(WitnessSigError::HighS)
    );

    // BER-style zero padding of the 31-byte r (70 bytes): not strict DER or not canonical.
    let short_der = short_r.serialize_der();
    let short_der = short_der.as_ref();
    let mut padded = vec![0x30, short_der[1] + 1, 0x02, short_der[3] + 1, 0x00];
    padded.extend_from_slice(&short_der[4..]);
    assert_eq!(padded.len(), 70);
    let result = check_witness_signature(&with_sighash_byte(&padded), &public, &short_hash);
    assert!(
        matches!(
            result,
            Err(WitnessSigError::DerInvalid | WitnessSigError::DerNotCanonical)
        ),
        "{result:?}"
    );
    let mut garbage = with_sighash_byte(der);
    garbage[0] = 0x31;
    assert_eq!(
        check_witness_signature(&garbage, &public, &sighash),
        Err(WitnessSigError::DerInvalid)
    );
    let long = with_sighash_byte(&[0x30; 71]);
    assert_eq!(
        check_witness_signature(&long, &public, &sighash),
        Err(WitnessSigError::DerTooLong)
    );

    // High-R: search RFC 6979 signatures (no grinding) until r ≥ 2^255.
    let (high_r_item, high_r_hash) = (0_u8..=255)
        .find_map(|seed| {
            let digest = [seed; 32];
            let signature = ctx.sign_ecdsa(Message::from_digest(digest), &secret);
            (signature.serialize_compact()[0] & 0x80 != 0).then(|| {
                (
                    with_sighash_byte(signature.serialize_der().as_ref()),
                    digest,
                )
            })
        })
        .unwrap();
    let result = check_witness_signature(&high_r_item, &public, &high_r_hash);
    assert!(
        matches!(
            result,
            Err(WitnessSigError::HighR | WitnessSigError::DerTooLong)
        ),
        "{result:?}"
    );

    let mut uncompressed_prefix = public;
    uncompressed_prefix[0] = 0x04;
    assert_eq!(
        check_witness_signature(&item, &uncompressed_prefix, &sighash),
        Err(WitnessSigError::PublicKey)
    );
    assert_eq!(
        check_witness_signature(&item, &public[..32], &sighash),
        Err(WitnessSigError::PublicKey)
    );
    let other_key = h::<33>("0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c");
    assert_eq!(
        check_witness_signature(&item, &other_key, &sighash),
        Err(WitnessSigError::VerifyFailed)
    );
    let mut other_hash = sighash;
    other_hash[0] ^= 1;
    assert_eq!(
        check_witness_signature(&item, &public, &other_hash),
        Err(WitnessSigError::VerifyFailed)
    );
}

/// `sign_sighash` inside `Vault::with_secp_key` signs with the BIP84 key whose HASH160 is the
/// program of the cached account node (the spec/08 §3.1 signing-time check).
#[test]
fn sign_inside_with_secp_key() {
    let vault = unlocked_with(ABOUT);
    let account = vault.btc_account_xpub(BtcCoin::Test).unwrap();
    let program = p2wpkh_program(&account, BtcChain::Receive, 3).unwrap();
    let sighash = [0x42; 32];
    let (item, public) = vault
        .with_secp_key(
            crate::vault::KeyRef::Btc {
                coin: BtcCoin::Test,
                chain: BtcChain::Receive,
                index: 3,
            },
            |ctx, secret| {
                let public = PublicKey::from_secret_key(ctx, secret).serialize();
                assert_eq!(hash160(&public), program);
                Ok((sign_sighash(ctx, secret, &sighash).unwrap(), public))
            },
        )
        .unwrap();
    assert!(item.len() <= 71);
    assert_eq!(check_witness_signature(&item, &public, &sighash), Ok(()));
}

/// A 2-input 2-output P2WPKH transaction signed with vault keys: every witness passes the strict
/// checker, the bytes round-trip, and the real weight is within the spec/08 §7.2 estimate.
#[test]
fn signed_p2wpkh_weight_within_estimate() {
    use super::script::p2wpkh_script_pubkey;
    use super::tx::{OutPoint, Transaction, TxIn, TxOut, Txid, estimate_vsize, estimate_weight};
    use super::{BTC_SEQUENCE, BTC_TX_VERSION};

    let vault = unlocked_with(ABOUT);
    let account = vault.btc_account_xpub(BtcCoin::Test).unwrap();
    let keys = [(BtcChain::Receive, 0_u32), (BtcChain::Change, 5)];
    let amounts = [Sats::new(70_000).unwrap(), Sats::new(40_000).unwrap()];
    let mut tx = Transaction {
        version: BTC_TX_VERSION,
        inputs: keys
            .iter()
            .enumerate()
            .map(|(position, _)| TxIn {
                prevout: OutPoint {
                    txid: Txid::from_bytes([u8::try_from(position).unwrap() + 1; 32]),
                    vout: 1,
                },
                script_sig: Vec::new(),
                sequence: BTC_SEQUENCE,
                witness: Vec::new(),
            })
            .collect(),
        outputs: vec![
            TxOut {
                value: Sats::new(100_000).unwrap(),
                script_pubkey: p2wpkh_script_pubkey(&[0x55; 20]).to_vec(),
            },
            TxOut {
                value: Sats::new(9_000).unwrap(),
                script_pubkey: p2wpkh_script_pubkey(
                    &p2wpkh_program(&account, BtcChain::Change, 6).unwrap(),
                )
                .to_vec(),
            },
        ],
        lock_time: 120_000,
    };
    let unsigned = tx.clone();
    for (position, ((chain, index), amount)) in keys.iter().zip(amounts).enumerate() {
        let program = p2wpkh_program(&account, *chain, *index).unwrap();
        let sighash = bip143_sighash_p2wpkh(&unsigned, position, &program, amount).unwrap();
        let witness = vault
            .with_secp_key(
                crate::vault::KeyRef::Btc {
                    coin: BtcCoin::Test,
                    chain: *chain,
                    index: *index,
                },
                |ctx, secret| {
                    let public = PublicKey::from_secret_key(ctx, secret).serialize();
                    assert_eq!(hash160(&public), program);
                    Ok(vec![
                        sign_sighash(ctx, secret, &sighash).unwrap(),
                        public.to_vec(),
                    ])
                },
            )
            .unwrap();
        assert_eq!(
            check_witness_signature(&witness[0], &witness[1], &sighash),
            Ok(())
        );
        tx.inputs[position].witness = witness;
    }
    let bytes = serialize(&tx, true);
    assert_eq!(parse_transaction(&bytes).unwrap(), tx);
    assert_eq!(serialize(&tx, false), serialize(&unsigned, false));
    assert_eq!(txid(&tx), txid(&unsigned));
    let estimate = estimate_weight(2, &[22, 22]).unwrap();
    assert!(weight(&tx) <= estimate, "{} > {estimate}", weight(&tx));
    assert!(vsize(&tx) <= estimate_vsize(2, &[22, 22]).unwrap());
    assert!(
        estimate - weight(&tx) <= 2,
        "low-R signatures are 71 or 70 bytes"
    );
}
