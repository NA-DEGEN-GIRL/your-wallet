//! Zcash core tests (spec/12 §14): the official zcash-test-vectors files (F4Jumble, ZIP 316
//! unified addresses, ZIP 320 TEX, ZIP 244 txid and `SIGHASH_ALL`), BIP44 derivation against the
//! ZIP 320 vector keys, and one mocked end-to-end send (plan → approval → vault signature →
//! post-sign verification → journal record → state transitions).
#![expect(
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "test fixtures index buffers of known length; the v5 test parser is one table"
)]

use secp256k1::PublicKey;
use yw_json::{Limits, Value};

use super::address::{
    RecipientForm, ZecAddressError, ZecDest, encode_tex, parse_recipient, unified_items,
};
use super::f4jumble::{f4jumble, f4jumble_inv};
use super::sighash::{ZecPrevout, sighash_all_with};
use super::tx::{ZecOutPoint, ZecTx, ZecTxIn, ZecTxOut, parse_tx, serialize_tx, txid_with};
use super::upgrade::{ConsensusObservation, UpgradeError, tx_consensus};
use super::*;
use crate::approval::ApprovalStore;
use crate::bip32::path::zec_path;
use crate::btc::address::hash160;
use crate::entropy::{OsRandom, secp_context};
use crate::hex;
use crate::journal::JournalPlain;
use crate::journal::zec::{self as zj, ZecTransition, ZecTxState};

const F4: &str = include_str!("../../tests/vectors/zec/f4jumble.json");
const UA: &str = include_str!("../../tests/vectors/zec/unified_address.json");
const TEX: &str = include_str!("../../tests/vectors/zec/zip_0320.json");
const ZIP244: &str = include_str!("../../tests/vectors/zec/zip_0244.json");

/// The data rows of a zcash-test-vectors file (row 0 = source, row 1 = header).
fn rows(text: &str) -> Vec<Vec<Value>> {
    let limits = Limits {
        max_bytes: 4 << 20,
        ..Limits::RESPONSE
    };
    let _: &Limits = &limits;
    let root = yw_json::parse(text.as_bytes(), &limits).unwrap();
    root.as_array().unwrap()[2..]
        .iter()
        .map(|row| row.as_array().unwrap().to_vec())
        .collect()
}

fn bytes(value: &Value) -> Option<Vec<u8>> {
    value.as_str().map(|text| hex::decode(text).unwrap())
}

#[test]
fn f4jumble_official_vectors() {
    let rows = rows(F4);
    assert_eq!(rows.len(), 8);
    for row in rows {
        let normal = bytes(&row[0]).unwrap();
        let jumbled = bytes(&row[1]).unwrap();
        assert_eq!(f4jumble(&normal).unwrap(), jumbled, "len {}", normal.len());
        assert_eq!(
            f4jumble_inv(&jumbled).unwrap(),
            normal,
            "len {}",
            normal.len()
        );
    }
    assert!(f4jumble(&[0; 37]).is_none());
}

#[test]
fn unified_address_official_vectors() {
    let rows = rows(UA);
    assert_eq!(rows.len(), 60);
    let mut with_transparent = 0;
    for row in rows {
        let ua = row[6].as_str().unwrap();
        let expected = match (bytes(&row[0]), bytes(&row[1])) {
            (Some(p2pkh), None) => Some(ZecDest::P2pkh(p2pkh.try_into().unwrap())),
            (None, Some(p2sh)) => Some(ZecDest::P2sh(p2sh.try_into().unwrap())),
            (None, None) => None,
            _ => unreachable!("both transparent receivers"),
        };
        let parsed = parse_recipient(ua, ZecNetwork::Mainnet);
        match expected {
            Some(dest) => {
                with_transparent += 1;
                let recipient = parsed.unwrap();
                assert_eq!(recipient.dest, dest, "{ua}");
                assert_eq!(recipient.form, RecipientForm::Unified);
            }
            None => assert_eq!(parsed, Err(ZecAddressError::UnifiedNoTransparent), "{ua}"),
        }
        // Every item of the vector is present with its length.
        let decoded = crate::btc::bech32::decode_limited(ua, 1_000).unwrap();
        let jumbled = crate::btc::bech32::from_five_bits(&decoded.data).unwrap();
        let items = unified_items(&jumbled, "u").unwrap();
        if let Some(sapling) = bytes(&row[2]) {
            assert!(items.contains(&(2, sapling)));
        }
        if let Some(orchard) = bytes(&row[3]) {
            assert!(items.contains(&(3, orchard)));
        }
        if let Some(code) = row[4].as_number().and_then(yw_json::Number::as_u64) {
            assert!(items.contains(&(code, bytes(&row[5]).unwrap())));
        }
        // The other network refuses it.
        assert_eq!(
            parse_recipient(ua, ZecNetwork::Testnet).err(),
            Some(if expected.is_some() {
                ZecAddressError::WrongNetwork
            } else {
                ZecAddressError::UnifiedNoTransparent
            })
        );
    }
    assert!(with_transparent > 10);
}

/// ZIP 320 vectors: the t-address and the TEX address of the same P2PKH hash, and the BIP44 key
/// `m/44'/133'/{account}'/0/{index}` of the zcash-test-vectors seed `00 01 … 1f` (64-byte form:
/// the test-vector seed is 32 bytes; BIP32 takes it as is).
#[test]
fn tex_official_vectors_and_bip44_path() {
    let rows = rows(TEX);
    assert_eq!(rows.len(), 15);
    for row in rows {
        let t_addr = row[0].as_str().unwrap();
        let hash: [u8; 20] = bytes(&row[1]).unwrap().try_into().unwrap();
        let tex = row[2].as_str().unwrap();
        let t = parse_recipient(t_addr, ZecNetwork::Mainnet).unwrap();
        assert_eq!(t.dest, ZecDest::P2pkh(hash));
        assert_eq!(t.form, RecipientForm::Transparent);
        assert_eq!(ZecDest::P2pkh(hash).encode(ZecNetwork::Mainnet), t_addr);
        let parsed = parse_recipient(tex, ZecNetwork::Mainnet).unwrap();
        assert_eq!(parsed.dest, ZecDest::P2pkh(hash));
        assert_eq!(parsed.form, RecipientForm::Tex);
        assert_eq!(encode_tex(&hash, ZecNetwork::Mainnet), tex);
        assert_eq!(
            parse_recipient(tex, ZecNetwork::Testnet),
            Err(ZecAddressError::WrongNetwork)
        );
    }
}

#[test]
fn recipient_policy() {
    let net = ZecNetwork::Testnet;
    let hash = [7_u8; 20];
    let tm = ZecDest::P2pkh(hash).encode(net);
    assert!(tm.starts_with("tm"));
    let t2 = ZecDest::P2sh(hash).encode(net);
    assert!(t2.starts_with("t2"));
    assert_eq!(parse_recipient(&t2, net).unwrap().dest, ZecDest::P2sh(hash));
    let t1 = ZecDest::P2pkh(hash).encode(ZecNetwork::Mainnet);
    assert!(t1.starts_with("t1"));
    assert!(
        ZecDest::P2sh(hash)
            .encode(ZecNetwork::Mainnet)
            .starts_with("t3")
    );
    assert_eq!(
        parse_recipient(&t1, net),
        Err(ZecAddressError::WrongNetwork)
    );
    let textest = encode_tex(&hash, net);
    assert!(textest.starts_with("textest1"));
    assert_eq!(
        parse_recipient(&textest, net).unwrap().form,
        RecipientForm::Tex
    );
    assert_eq!(parse_recipient("", net), Err(ZecAddressError::Empty));
    assert_eq!(
        parse_recipient(
            "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9sly",
            net
        ),
        Err(ZecAddressError::Shielded)
    );
    // A Bitcoin address is not a Zcash address.
    assert!(parse_recipient("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", net).is_err());
    let mut broken = tm.clone();
    broken.pop();
    broken.push(if tm.ends_with('a') { 'b' } else { 'a' });
    assert_eq!(
        parse_recipient(&broken, net),
        Err(ZecAddressError::Checksum)
    );
}

// ----- ZIP 244: a test-only v5 parser for the shielded parts of the official vectors ---------

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let out = &self.bytes[self.at..self.at + n];
        self.at += n;
        out
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().unwrap())
    }
    fn compact(&mut self) -> usize {
        match self.take(1)[0] {
            0xfd => usize::from(u16::from_le_bytes(self.take(2).try_into().unwrap())),
            0xfe => self.u32() as usize,
            small => usize::from(small),
        }
    }
}

fn b2(persona: &[u8; 16], parts: &[&[u8]]) -> [u8; 32] {
    super::blake2b::blake2b_256(persona, parts)
}

/// Parses a v5 transaction: the transparent part as [`ZecTx`] plus the ZIP 244 T.3 / T.4
/// Sapling and Orchard digests (ZIP 225 field layout).
fn parse_full_v5(raw: &[u8]) -> (ZecTx, [u8; 32], [u8; 32]) {
    let mut c = Cursor { bytes: raw, at: 0 };
    assert_eq!(c.u32(), super::tx::V5_HEADER);
    assert_eq!(c.u32(), super::tx::V5_VERSION_GROUP_ID);
    let branch_id = c.u32();
    let lock_time = c.u32();
    let expiry_height = c.u32();
    let mut inputs = Vec::new();
    for _ in 0..c.compact() {
        let txid: [u8; 32] = c.take(32).try_into().unwrap();
        let index = c.u32();
        let len = c.compact();
        let script_sig = c.take(len).to_vec();
        let sequence = c.u32();
        inputs.push(ZecTxIn {
            prevout: ZecOutPoint { txid, index },
            script_sig,
            sequence,
        });
    }
    let mut outputs = Vec::new();
    for _ in 0..c.compact() {
        let value = u64::from_le_bytes(c.take(8).try_into().unwrap());
        let len = c.compact();
        outputs.push(ZecTxOut {
            value,
            script_pubkey: c.take(len).to_vec(),
        });
    }
    // Sapling.
    let n_spends = c.compact();
    let spends: Vec<&[u8]> = (0..n_spends).map(|_| c.take(96)).collect();
    let n_outputs = c.compact();
    let souts: Vec<&[u8]> = (0..n_outputs).map(|_| c.take(756)).collect();
    let sapling = if n_spends + n_outputs > 0 {
        let value_balance = c.take(8);
        let anchor = if n_spends > 0 { c.take(32) } else { &[][..] };
        c.take(192 * n_spends + 64 * n_spends + 192 * n_outputs + 64);
        let spends_digest = if n_spends > 0 {
            let nullifiers: Vec<u8> = spends.iter().flat_map(|s| s[32..64].to_vec()).collect();
            let noncompact: Vec<u8> = spends
                .iter()
                .flat_map(|s| [&s[..32], anchor, &s[64..96]].concat())
                .collect();
            b2(
                b"ZTxIdSSpendsHash",
                &[
                    &b2(b"ZTxIdSSpendCHash", &[&nullifiers]),
                    &b2(b"ZTxIdSSpendNHash", &[&noncompact]),
                ],
            )
        } else {
            b2(b"ZTxIdSSpendsHash", &[])
        };
        let outputs_digest = if n_outputs > 0 {
            // cv 32, cmu 32, epk 32, enc 580, out 80
            let compact: Vec<u8> = souts.iter().flat_map(|o| o[32..148].to_vec()).collect();
            let memos: Vec<u8> = souts.iter().flat_map(|o| o[148..660].to_vec()).collect();
            let noncompact: Vec<u8> = souts
                .iter()
                .flat_map(|o| [&o[..32], &o[660..756]].concat())
                .collect();
            b2(
                b"ZTxIdSOutputHash",
                &[
                    &b2(b"ZTxIdSOutC__Hash", &[&compact]),
                    &b2(b"ZTxIdSOutM__Hash", &[&memos]),
                    &b2(b"ZTxIdSOutN__Hash", &[&noncompact]),
                ],
            )
        } else {
            b2(b"ZTxIdSOutputHash", &[])
        };
        b2(
            b"ZTxIdSaplingHash",
            &[&spends_digest, &outputs_digest, value_balance],
        )
    } else {
        b2(b"ZTxIdSaplingHash", &[])
    };
    // Orchard: cv 32, nf 32, rk 32, cmx 32, epk 32, enc 580, out 80.
    let n_actions = c.compact();
    let actions: Vec<&[u8]> = (0..n_actions).map(|_| c.take(820)).collect();
    let orchard = if n_actions > 0 {
        let flags = c.take(1);
        let value_balance = c.take(8);
        let anchor = c.take(32);
        let proofs = c.compact();
        c.take(proofs + 64 * n_actions + 64);
        let compact: Vec<u8> = actions
            .iter()
            .flat_map(|a| [&a[32..64], &a[96..128], &a[128..160], &a[160..212]].concat())
            .collect();
        let memos: Vec<u8> = actions.iter().flat_map(|a| a[212..724].to_vec()).collect();
        let noncompact: Vec<u8> = actions
            .iter()
            .flat_map(|a| [&a[..32], &a[64..96], &a[724..820]].concat())
            .collect();
        b2(
            b"ZTxIdOrchardHash",
            &[
                &b2(b"ZTxIdOrcActCHash", &[&compact]),
                &b2(b"ZTxIdOrcActMHash", &[&memos]),
                &b2(b"ZTxIdOrcActNHash", &[&noncompact]),
                flags,
                value_balance,
                anchor,
            ],
        )
    } else {
        b2(b"ZTxIdOrchardHash", &[])
    };
    assert_eq!(c.at, raw.len(), "trailing bytes");
    (
        ZecTx {
            branch_id,
            lock_time,
            expiry_height,
            inputs,
            outputs,
        },
        sapling,
        orchard,
    )
}

#[test]
fn zip244_official_vectors() {
    let rows = rows(ZIP244);
    assert_eq!(rows.len(), 10);
    let mut sighashes = 0;
    for row in rows {
        let raw = bytes(&row[0]).unwrap();
        let (tx, sapling, orchard) = parse_full_v5(&raw);
        assert_eq!(
            txid_with(&tx, &sapling, &orchard).to_vec(),
            bytes(&row[1]).unwrap()
        );
        let (Some(index), Some(expected)) = (
            row[5].as_number().and_then(yw_json::Number::as_u64),
            bytes(&row[7]),
        ) else {
            continue;
        };
        let amounts = row[3].as_array().unwrap();
        let scripts = row[4].as_array().unwrap();
        let prevouts: Vec<ZecPrevout> = amounts
            .iter()
            .zip(scripts)
            .map(|(value, script)| ZecPrevout {
                value: value.as_number().and_then(yw_json::Number::as_u64).unwrap(),
                script_pubkey: bytes(script).unwrap(),
            })
            .collect();
        let index = usize::try_from(index).unwrap();
        assert_eq!(
            sighash_all_with(&tx, index, &prevouts, &sapling, &orchard)
                .unwrap()
                .to_vec(),
            expected
        );
        sighashes += 1;
    }
    assert!(sighashes >= 5);
}

#[test]
fn transparent_v5_round_trip_and_strict_parse() {
    let tx = sample_tx(ZecNetwork::Testnet);
    let raw = serialize_tx(&tx);
    assert_eq!(&raw[..8], &[0x05, 0, 0, 0x80, 0x0a, 0x27, 0xa7, 0x26]);
    assert_eq!(&raw[raw.len() - 3..], &[0, 0, 0]);
    assert_eq!(parse_tx(&raw).unwrap(), tx);
    let mut shielded = raw.clone();
    let last = shielded.len() - 1;
    shielded[last] = 1;
    assert!(parse_tx(&shielded).is_err());
    let mut trailing = raw;
    trailing.push(0);
    assert!(parse_tx(&trailing).is_err());
}

fn sample_tx(network: ZecNetwork) -> ZecTx {
    let dest = ZecDest::P2pkh([9; 20]);
    ZecTx {
        branch_id: 0x7719_0AD9,
        lock_time: 0,
        expiry_height: 4_500_120,
        inputs: vec![ZecTxIn {
            prevout: ZecOutPoint {
                txid: [3; 32],
                index: 1,
            },
            script_sig: Vec::new(),
            sequence: ZEC_SEQUENCE,
        }],
        outputs: vec![ZecTxOut {
            value: 50_000 + u64::from(network.id()),
            script_pubkey: dest.script_pubkey(),
        }],
    }
}

#[test]
fn consensus_table_and_expiry() {
    let nu7 = 0x7719_0AD9;
    // Mainnet after NU7: delta 120, no pending upgrade.
    let observed = ConsensusObservation {
        tip: 3_544_634,
        next_branch: nu7,
        upgrades: vec![(0xC2D6_D0B4, 1_687_104), (nu7, 3_543_405)],
    };
    let consensus = tx_consensus(ZecNetwork::Mainnet, &observed).unwrap();
    assert_eq!(consensus.branch_id, nu7);
    assert_eq!(consensus.expiry_height, 3_544_635 + 120);
    assert_eq!(consensus.upgrade_name, "NU7");
    // The node claims NU6.3 after the NU7 height: mismatch.
    let stale = ConsensusObservation {
        next_branch: 0x37A5_165B,
        ..observed.clone()
    };
    assert!(matches!(
        tx_consensus(ZecNetwork::Mainnet, &stale),
        Err(UpgradeError::BranchMismatch { .. })
    ));
    // Unknown branch id.
    let unknown = ConsensusObservation {
        next_branch: 0x1234_5678,
        ..observed.clone()
    };
    assert_eq!(
        tx_consensus(ZecNetwork::Mainnet, &unknown),
        Err(UpgradeError::UnknownBranch(0x1234_5678))
    );
    // Testnet before NU7 (4,465,026): expiry capped below the activation, then refused when
    // too close.
    let before = ConsensusObservation {
        tip: 4_465_000,
        next_branch: 0x37A5_165B,
        upgrades: vec![(nu7, 4_465_026)],
    };
    let capped = tx_consensus(ZecNetwork::Testnet, &before).unwrap();
    assert_eq!(capped.expiry_height, 4_465_025);
    let close = ConsensusObservation {
        tip: 4_465_022,
        ..before
    };
    assert_eq!(
        tx_consensus(ZecNetwork::Testnet, &close),
        Err(UpgradeError::UpgradeTooClose { height: 4_465_026 })
    );
}

// ----- mocked end-to-end send ------------------------------------------------------------

const ABOUT: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn utxo(n: u8, value: u64) -> ZecUtxo {
    ZecUtxo {
        outpoint: ZecOutPoint {
            txid: [n; 32],
            index: u32::from(n),
        },
        value,
        height: Some(4_000_000),
        coinbase: false,
    }
}

/// Plan → approval (issue, consume) → vault signature → post-sign verification → journal
/// (`Signed`, one-in-flight block, reserved inputs, `Broadcast`, `Mined`) on testnet, with the
/// derived key `m/44'/1'/0'/0/0` cross-checked against private derivation.
#[test]
fn mocked_end_to_end_send() {
    let vault = crate::vault::tests::unlocked_with(ABOUT);
    let pubkey = vault.zec_public_key(true, 0, 0).unwrap();
    // Private derivation through the path helper gives the same key.
    let ctx = secp_context(&mut OsRandom).unwrap();
    let path = zec_path(true, 0, 0).unwrap();
    assert_eq!(path.to_string(), "m/44'/1'/0'/0/0");
    let seed = crate::bip39::Mnemonic::parse(ABOUT)
        .unwrap()
        .to_seed(&crate::password::Bip39Passphrase::empty())
        .unwrap();
    let secret = crate::bip32::secret_key_from_seed(&ctx, seed.expose(), &path).unwrap();
    assert_eq!(
        PublicKey::from_secret_key(&ctx, &secret).serialize(),
        pubkey
    );

    let account = ZecAccount {
        network: ZecNetwork::Testnet,
        source: ZecKeySource::DEFAULT,
        pubkey,
    };
    assert!(account.address().starts_with("tm"));
    let recipient = parse_recipient(
        &encode_tex(&[0x42; 20], ZecNetwork::Testnet),
        ZecNetwork::Testnet,
    )
    .unwrap();
    let consensus = tx_consensus(
        ZecNetwork::Testnet,
        &ConsensusObservation {
            tip: 4_470_000,
            next_branch: 0x7719_0AD9,
            upgrades: vec![(0x7719_0AD9, 4_465_026)],
        },
    )
    .unwrap();
    let request = ZecSendRequest {
        recipient,
        amount: ZecAmount::Exact(150_000),
        utxos: vec![utxo(1, 100_000), utxo(2, 80_000), utxo(3, 5_000)],
        reserved: Vec::new(),
        consensus,
    };
    let plan = plan_send(&account, &request).unwrap();
    assert_eq!(plan.inputs.len(), 2);
    assert_eq!(plan.fee, 10_000);
    assert_eq!(plan.change, 20_000);
    assert_eq!(plan.tx.outputs[1].script_pubkey, account.script_pubkey());

    let id = crate::approval::ApprovalId([5; 16]);
    let draft = display::build_zec_request(id, &plan).unwrap();
    let mut store = ApprovalStore::new();
    let issued = store.issue(draft, 1_000, 1_700_000_000_000).unwrap();
    let approved = store.consume(issued.id, issued.digest, 1_001).unwrap();
    let signed = sign_plan(&vault, approved, &plan).unwrap();
    assert_eq!(
        verify_signed(&signed.raw, &plan, false).unwrap(),
        signed.txid
    );
    // A tampered byte fails the post-sign verification.
    let mut tampered = signed.raw.clone();
    let at = tampered.len() - 10;
    tampered[at] ^= 1;
    assert!(verify_signed(&tampered, &plan, false).is_err());
    // A second consume of the same approval is refused by the store.
    assert!(store.consume(issued.id, issued.digest, 1_002).is_err());

    // Journal: record first, then the one-in-flight block and reserved inputs.
    let mut journal = JournalPlain::default();
    zj::check_plan_allowed(&journal, &account).unwrap();
    let record = zj::ZecRecord::new_signed(&plan, &signed, 1_700_000_000_500);
    zj::push_record(&mut journal, &record).unwrap();
    let decoded = zj::ZecEntries::from_plain(&journal);
    assert_eq!(decoded.corrupt, 0);
    assert_eq!(decoded.records[0].1, record);
    assert_eq!(
        zj::check_plan_allowed(&journal, &account),
        Err(zj::ZecJournalBlock::InFlight)
    );
    assert_eq!(
        zj::reserved_inputs(&journal, ZecNetwork::Testnet),
        vec![utxo(1, 0).outpoint, utxo(2, 0).outpoint]
    );
    let txid = record.txid();
    assert_eq!(txid, signed.txid);
    assert_eq!(
        zj::apply(&mut journal, &txid, ZecTransition::Broadcast),
        Some(ZecTxState::Broadcast)
    );
    assert_eq!(
        zj::apply(&mut journal, &txid, ZecTransition::Discarded),
        None,
        "a disclosed record is never discarded"
    );
    assert_eq!(
        zj::apply(&mut journal, &txid, ZecTransition::Mined(4_470_003)),
        Some(ZecTxState::Confirmed)
    );
    zj::check_plan_allowed(&journal, &account).unwrap();
    assert!(zj::reserved_inputs(&journal, ZecNetwork::Testnet).is_empty());

    // Past expiry, unknown to the node, every input spent: "may have been included" — terminal
    // (no resend, sending allowed again) but its inputs stay reserved.
    let mut spent = JournalPlain::default();
    zj::push_record(&mut spent, &record).unwrap();
    assert_eq!(
        zj::apply(&mut spent, &txid, ZecTransition::InputsSpent),
        Some(ZecTxState::InputsSpent)
    );
    zj::check_plan_allowed(&spent, &account).unwrap();
    assert_eq!(
        zj::reserved_inputs(&spent, ZecNetwork::Testnet),
        vec![utxo(1, 0).outpoint, utxo(2, 0).outpoint]
    );
    assert_eq!(zj::apply(&mut spent, &txid, ZecTransition::Expired), None);

    // The signature is from the derived key: HASH160 matches the account address.
    assert_eq!(hash160(&pubkey), account.pubkey_hash());
}

#[test]
fn planning_rules() {
    let account = ZecAccount {
        network: ZecNetwork::Mainnet,
        source: ZecKeySource::DEFAULT,
        pubkey: [2; 33],
    };
    let recipient = parse_recipient(
        &ZecDest::P2sh([1; 20]).encode(ZecNetwork::Mainnet),
        ZecNetwork::Mainnet,
    )
    .unwrap();
    let consensus = tx_consensus(
        ZecNetwork::Mainnet,
        &ConsensusObservation {
            tip: 3_544_634,
            next_branch: 0x7719_0AD9,
            upgrades: Vec::new(),
        },
    )
    .unwrap();
    let mut request = ZecSendRequest {
        recipient,
        amount: ZecAmount::Max,
        utxos: vec![utxo(1, 100_000), utxo(2, 30_000)],
        reserved: vec![utxo(2, 0).outpoint],
        consensus,
    };
    // Send-max skips the reserved input.
    let plan = plan_send(&account, &request).unwrap();
    assert_eq!(plan.inputs.len(), 1);
    assert_eq!(plan.amount, 90_000);
    assert_eq!(plan.change, 0);
    // Unconfirmed and coinbase outputs are never selected.
    request.reserved.clear();
    request.utxos = vec![
        ZecUtxo {
            height: None,
            ..utxo(1, 100_000)
        },
        ZecUtxo {
            coinbase: true,
            ..utxo(2, 100_000)
        },
    ];
    assert_eq!(plan_send(&account, &request), Err(ZecPlanError::NoFunds));
    // Change below the dust floor is folded into the fee.
    request.utxos = vec![utxo(1, 100_000)];
    request.amount = ZecAmount::Exact(89_500);
    let plan = plan_send(&account, &request).unwrap();
    assert_eq!(plan.change, 0);
    assert_eq!(plan.fee, 10_500);
    request.amount = ZecAmount::Exact(500);
    assert_eq!(
        plan_send(&account, &request),
        Err(ZecPlanError::AmountInvalid)
    );
    // Send-max with more eligible outputs than one transaction spends: the largest 50 (dust is
    // never eligible).
    request.amount = ZecAmount::Max;
    request.utxos = (1..=60_u8)
        .map(|n| utxo(n, 100_000 + u64::from(n)))
        .chain([utxo(200, crate::zec::ZEC_MIN_UTXO)])
        .collect();
    let plan = plan_send(&account, &request).unwrap();
    assert_eq!(plan.inputs.len(), crate::zec::ZEC_MAX_INPUTS);
    assert_eq!(plan.excluded_inputs, 10);
    assert!(plan.inputs.iter().all(|input| input.value > 100_010));
}
