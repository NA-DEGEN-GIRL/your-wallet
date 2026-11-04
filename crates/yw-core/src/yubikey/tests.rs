//! End-to-end tests against the APDU emulator (spec/10 §12.1). No real card is ever used.

use secp256k1::{Message, PublicKey, Secp256k1};

use super::apdu::ApduMode;
use super::enrol::{EnrolAuth, EnrolError, Enrolled, enrol_card, master_fingerprint, preview};
use super::mock::{MockCard, ToyCipher};
use super::plan::{
    BtcUse, CardSlot, KeyRole, PgpKey, PinPolicy, PivSlot, PlanError, PlannedSlot, TouchPolicy,
    accounts, slot_on_card, validate_plan,
};
use super::record::{HwKeyRecord, HwPublicKey, records_consistent};
use super::sign::{CardKey, check_key, sign_btc, sign_evm, sign_sol};
use super::{CardError, Firmware};
use crate::bip32::path::AccountIndex;
use crate::bip39::Mnemonic;
use crate::btc::account::ScriptType;
use crate::btc::network::BtcNetwork;
use crate::password::Bip39Passphrase;

const ABOUT: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const OTHER: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

fn seed_of(phrase: &str) -> [u8; 64] {
    *Mnemonic::parse(phrase)
        .unwrap()
        .to_seed(&Bip39Passphrase::empty())
        .unwrap()
        .expose()
}

fn evm(index: u32) -> KeyRole {
    KeyRole::Evm {
        index: AccountIndex::new(index).unwrap(),
        btc: None,
    }
}

fn btc(index: u32) -> KeyRole {
    KeyRole::Btc {
        network: BtcNetwork::Mainnet,
        script: ScriptType::P2wpkh,
        index,
    }
}

fn sol(index: u32) -> KeyRole {
    KeyRole::Sol {
        index: AccountIndex::new(index).unwrap(),
    }
}

fn sig(role: KeyRole) -> PlannedSlot {
    PlannedSlot::recommended(CardSlot::OpenPgp(PgpKey::Sig), role)
}

fn aut(role: KeyRole) -> PlannedSlot {
    PlannedSlot::recommended(CardSlot::OpenPgp(PgpKey::Aut), role)
}

fn piv(id: u8, role: KeyRole) -> PlannedSlot {
    PlannedSlot::recommended(CardSlot::Piv(PivSlot::new(id).unwrap()), role)
}

fn default_auth() -> EnrolAuth<'static> {
    EnrolAuth {
        admin_pin: b"12345678",
        management_key: &super::piv::DEFAULT_MANAGEMENT_KEY,
        cipher: Some(&ToyCipher),
        challenge: [0x5C; 16],
    }
}

fn enrol(
    card: &mut MockCard,
    phrase: &str,
    slots: &[PlannedSlot],
    records: &[HwKeyRecord],
) -> Result<Enrolled, EnrolError> {
    enrol_card(
        card,
        ApduMode::Short,
        &seed_of(phrase),
        slots,
        records,
        &default_auth(),
    )
}

fn card_key(record: &HwKeyRecord, position: usize) -> CardKey {
    let slot = record.slots[position];
    CardKey {
        serial: record.serial,
        slot: slot.slot,
        public: slot.public,
    }
}

fn recommended_plan() -> Vec<PlannedSlot> {
    vec![
        sig(evm(0)),
        aut(btc(0)),
        piv(0x82, sol(0)),
        piv(0x83, sol(1)),
    ]
}

#[test]
fn enrol_recommended_plan_and_public_keys_match_known_vectors() {
    let mut card = MockCard::new(12_345_678);
    let enrolled = enrol(&mut card, ABOUT, &recommended_plan(), &[]).unwrap();
    let record = &enrolled.record;
    assert_eq!(record.serial, 12_345_678);
    assert_eq!(record.firmware, Firmware::new(5, 7, 4));
    assert_eq!(record.slots.len(), 4);
    assert!(enrolled.defaults.openpgp_admin && enrolled.defaults.piv_pin);
    assert!(enrolled.defaults.piv_management);
    let ctx = Secp256k1::new();
    let lines: Vec<Vec<String>> = record
        .slots
        .iter()
        .map(|slot| super::plan::addresses(&ctx, slot.role, &slot.public).unwrap())
        .collect();
    assert_eq!(lines[0], ["0x9858EfFD232B4033E47d90003D41EC34EcaEda94"]);
    assert_eq!(lines[1], ["bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"]);
    assert_eq!(lines[2], ["HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"]);
    assert_eq!(record.slots[0].role.path_text(), "m/44'/60'/0'/0/0");
    assert_eq!(record.slots[1].role.path_text(), "m/84'/0'/0'/0/0");
    assert_eq!(record.slots[2].role.path_text(), "m/44'/501'/0'/0'");
    assert_eq!(record.slots[3].role.path_text(), "m/44'/501'/1'/0'");
    // The preview (no card) shows the same keys.
    let shown = preview(&ctx, &seed_of(ABOUT), &recommended_plan()).unwrap();
    for (line, slot) in shown.iter().zip(&record.slots) {
        assert_eq!(line.public, slot.public);
        assert_eq!(line.path, slot.role.path_text());
    }
    // The card holds what was planned: secp256k1 attributes, fixed touch, PIV policies.
    assert_eq!(
        card.pgp_attributes[0],
        super::openpgp::secp256k1_attributes()
    );
    assert_eq!(card.pgp_uif, [0x02, 0x00, 0x02]);
    assert_eq!(card.piv_keys.len(), 2);
    assert!(
        card.piv_keys
            .iter()
            .all(|(_, key)| key.pin_policy == 3 && key.touch_policy == 2)
    );
    // Extended APDUs give the same result.
    let mut card = MockCard::new(7);
    let extended = enrol_card(
        &mut card,
        ApduMode::Extended,
        &seed_of(ABOUT),
        &recommended_plan(),
        &[],
        &default_auth(),
    )
    .unwrap();
    assert_eq!(
        extended
            .record
            .slots
            .iter()
            .map(|slot| slot.public)
            .collect::<Vec<_>>(),
        record
            .slots
            .iter()
            .map(|slot| slot.public)
            .collect::<Vec<_>>()
    );
}

#[test]
fn evm_signature_recovers_the_enrolled_address_even_with_high_s() {
    let mut card = MockCard::new(1);
    let record = enrol(&mut card, ABOUT, &recommended_plan(), &[])
        .unwrap()
        .record;
    card.high_s = true;
    card.log.clear();
    let ctx = Secp256k1::new();
    let key = card_key(&record, 0);
    let expected = super::plan::evm_address(&key.public).unwrap();
    for byte in 0..8_u8 {
        let digest = [byte.wrapping_mul(29); 32];
        let (parity, compact) =
            sign_evm(&ctx, &mut card, ApduMode::Short, &key, b"123456", digest).unwrap();
        assert_eq!(
            crate::evm::sign::recover_address(digest, parity, &compact),
            Some(expected)
        );
        // low-s
        assert!(compact[32] < 0x80);
    }
    assert_eq!(card.touches, 8);
    assert!(
        !card.saw_write(),
        "signing must not send any write instruction"
    );
}

#[test]
fn btc_p2wpkh_signature_verifies_over_a_bip143_sighash() {
    use crate::btc::amount::Sats;
    use crate::btc::tx::{OutPoint, Transaction, TxIn, TxOut, Txid};
    let mut card = MockCard::new(2);
    let record = enrol(&mut card, ABOUT, &recommended_plan(), &[])
        .unwrap()
        .record;
    card.high_s = true;
    let key = card_key(&record, 1);
    let HwPublicKey::Secp256k1(public) = key.public else {
        unreachable!("secp key");
    };
    let program = crate::btc::address::hash160(&public);
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: Txid::from_bytes([0x11; 32]),
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: 0xFFFF_FFFD,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: Sats::new(90_000).unwrap(),
            script_pubkey: vec![
                0x00, 0x14, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            ],
        }],
        lock_time: 0,
    };
    let sighash =
        crate::btc::sighash::bip143_sighash_p2wpkh(&tx, 0, &program, Sats::new(100_000).unwrap())
            .unwrap();
    let ctx = Secp256k1::new();
    card.log.clear();
    let der = sign_btc(&ctx, &mut card, ApduMode::Short, &key, b"123456", sighash).unwrap();
    let signature = secp256k1::ecdsa::Signature::from_der(&der).unwrap();
    let mut normalised = signature;
    normalised.normalize_s();
    assert_eq!(normalised, signature, "low-s");
    ctx.verify_ecdsa(
        Message::from_digest(sighash),
        &signature,
        &PublicKey::from_slice(&public).unwrap(),
    )
    .unwrap();
    // AUT signs through INTERNAL AUTHENTICATE with PW1 mode 82.
    assert!(card.log.iter().any(|header| header[1] == 0x88));
    assert!(
        card.log
            .iter()
            .any(|header| header == &[0x00, 0x20, 0x00, 0x82])
    );
    assert!(!card.saw_write());
}

#[test]
fn solana_signature_verifies_with_the_enrolled_key() {
    let mut card = MockCard::new(3);
    let record = enrol(&mut card, ABOUT, &recommended_plan(), &[])
        .unwrap()
        .record;
    card.log.clear();
    let key = card_key(&record, 3);
    // A 1,000-byte message needs short-APDU chaining.
    let message = vec![0xA5; 1_000];
    let signature = sign_sol(&mut card, ApduMode::Short, &key, b"123456", &message).unwrap();
    let HwPublicKey::Ed25519(public) = key.public else {
        unreachable!("ed key");
    };
    ed25519_dalek::VerifyingKey::from_bytes(&public)
        .unwrap()
        .verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&signature))
        .unwrap();
    assert!(!card.saw_write());
    // PIN policy "always": a second sign without VERIFY is refused by the card; our flow always
    // verifies, so it succeeds.
    sign_sol(&mut card, ApduMode::Extended, &key, b"123456", b"again").unwrap();
}

#[test]
fn card_errors_are_reported() {
    let mut card = MockCard::new(4);
    let record = enrol(&mut card, ABOUT, &recommended_plan(), &[])
        .unwrap()
        .record;
    let ctx = Secp256k1::new();
    let key = card_key(&record, 0);
    assert_eq!(
        sign_evm(&ctx, &mut card, ApduMode::Short, &key, b"654321", [1; 32]),
        Err(CardError::WrongPin { retries: 2 })
    );
    card.refuse_touch = true;
    assert_eq!(
        sign_evm(&ctx, &mut card, ApduMode::Short, &key, b"123456", [1; 32]),
        Err(CardError::SecurityStatus)
    );
    card.refuse_touch = false;
    card.corrupt_signature = true;
    assert_eq!(
        sign_evm(&ctx, &mut card, ApduMode::Short, &key, b"123456", [1; 32]),
        Err(CardError::BadSignature)
    );
    let sol_key = card_key(&record, 2);
    assert_eq!(
        sign_sol(&mut card, ApduMode::Short, &sol_key, b"123456", b"m"),
        Err(CardError::BadSignature)
    );
    card.corrupt_signature = false;
    // Another card (serial) is refused before any PIN is sent.
    let mut other = MockCard::new(99);
    other.log.clear();
    assert_eq!(
        sign_evm(&ctx, &mut other, ApduMode::Short, &key, b"123456", [1; 32]),
        Err(CardError::WrongCard)
    );
    assert!(!other.log.iter().any(|header| header[1] == 0x20));
    // A slot overwritten after enrolment.
    card.pgp_keys[0] = Some([0x77; 32]);
    assert_eq!(
        check_key(&mut card, ApduMode::Short, &key),
        Err(CardError::KeyMismatch)
    );
    // Wrong PIN three times blocks.
    let mut card = MockCard::new(5);
    let record = enrol(&mut card, ABOUT, &recommended_plan(), &[])
        .unwrap()
        .record;
    let key = card_key(&record, 0);
    for retries in [2, 1, 0] {
        assert_eq!(
            sign_evm(&ctx, &mut card, ApduMode::Short, &key, b"000000", [1; 32]),
            Err(CardError::WrongPin { retries })
        );
    }
    assert_eq!(
        sign_evm(&ctx, &mut card, ApduMode::Short, &key, b"123456", [1; 32]),
        Err(CardError::PinBlocked)
    );
}

#[test]
fn enrolment_refusals() {
    // KDF, old firmware, wrong admin PIN, wrong management key, missing applet.
    let mut card = MockCard::new(6);
    card.kdf = true;
    assert_eq!(
        enrol(&mut card, ABOUT, &recommended_plan(), &[]).err(),
        Some(EnrolError::Card(CardError::KdfEnabled))
    );
    let mut card = MockCard::new(6);
    card.firmware = Firmware::new(5, 4, 3);
    assert_eq!(
        enrol(&mut card, ABOUT, &[piv(0x82, sol(0))], &[]).err(),
        Some(EnrolError::Card(CardError::FirmwareTooOld))
    );
    // OpenPGP-only plans work on 5.4 (secp256k1 since 5.2.3).
    enrol(&mut card, ABOUT, &[sig(evm(0))], &[]).unwrap();
    let mut card = MockCard::new(6);
    card.pw3 = b"another-admin".to_vec();
    assert_eq!(
        enrol(&mut card, ABOUT, &recommended_plan(), &[]).err(),
        Some(EnrolError::Card(CardError::WrongPin { retries: 2 }))
    );
    assert!(card.pgp_keys.iter().all(Option::is_none), "nothing written");
    let mut card = MockCard::new(6);
    card.mgmt_key = vec![9; 24];
    assert_eq!(
        enrol(&mut card, ABOUT, &[piv(0x82, sol(0))], &[]).err(),
        Some(EnrolError::Card(CardError::SecurityStatus))
    );
    assert!(card.piv_keys.is_empty());
    // Re-enrolling a card whose SIG touch policy is already fixed: the same fixed policy is
    // kept (no UIF write), another one is refused before any key is written.
    let mut card = MockCard::new(8);
    enrol(&mut card, ABOUT, &[sig(evm(0))], &[]).unwrap();
    enrol(&mut card, ABOUT, &[sig(evm(5))], &[]).unwrap();
    let mut cached = sig(evm(6));
    cached.touch = TouchPolicy::CachedFixed;
    let before = card.pgp_keys[0];
    assert_eq!(
        enrol(&mut card, ABOUT, &[cached], &[]).err(),
        Some(EnrolError::Card(CardError::Conditions))
    );
    assert_eq!(card.pgp_keys[0], before);
    let mut card = MockCard::new(6);
    card.has_openpgp = false;
    assert_eq!(
        enrol(&mut card, ABOUT, &[sig(evm(0))], &[]).err(),
        Some(EnrolError::Card(CardError::AppletMissing))
    );
}

#[test]
fn path_selection_and_duplicate_refusal() {
    // Any index per slot.
    let plan = [sig(evm(7)), aut(btc(19)), piv(0x9A, sol(4))];
    validate_plan(&plan).unwrap();
    assert_eq!(plan[0].role.path_text(), "m/44'/60'/0'/0/7");
    assert_eq!(plan[1].role.path_text(), "m/84'/0'/0'/0/19");
    assert_eq!(plan[2].role.path_text(), "m/44'/501'/4'/0'");
    let legacy = KeyRole::Btc {
        network: BtcNetwork::Testnet4,
        script: ScriptType::P2pkh,
        index: 3,
    };
    assert_eq!(legacy.path_text(), "m/44'/1'/0'/0/3");
    let nested = KeyRole::Btc {
        network: BtcNetwork::Mainnet,
        script: ScriptType::P2shP2wpkh,
        index: 0,
    };
    assert_eq!(nested.path_text(), "m/49'/0'/0'/0/0");
    // Same path twice on one card (also with the shared-BTC variant of the same EVM key).
    let shared = KeyRole::Evm {
        index: AccountIndex::new(7).unwrap(),
        btc: Some(BtcUse {
            network: BtcNetwork::Mainnet,
            script: ScriptType::P2wpkh,
        }),
    };
    assert_eq!(
        validate_plan(&[sig(evm(7)), aut(shared)]),
        Err(PlanError::DuplicatePath(CardSlot::OpenPgp(PgpKey::Aut)))
    );
    assert_eq!(
        validate_plan(&[piv(0x82, sol(1)), piv(0x83, sol(1))]),
        Err(PlanError::DuplicatePath(CardSlot::Piv(
            PivSlot::new(0x83).unwrap()
        )))
    );
    assert_eq!(
        validate_plan(&[sig(evm(0)), sig(evm(1))]),
        Err(PlanError::DuplicateSlot(CardSlot::OpenPgp(PgpKey::Sig)))
    );
    // Wrong applet, Taproot, PIV attestation slot, fixed touch on PIV.
    let wrong = PlannedSlot::recommended(CardSlot::OpenPgp(PgpKey::Sig), sol(0));
    assert_eq!(
        validate_plan(&[wrong]),
        Err(PlanError::WrongApplet(wrong.slot))
    );
    let taproot = KeyRole::Btc {
        network: BtcNetwork::Mainnet,
        script: ScriptType::P2tr,
        index: 0,
    };
    assert_eq!(
        validate_plan(&[sig(taproot)]),
        Err(PlanError::UnsupportedRole(CardSlot::OpenPgp(PgpKey::Sig)))
    );
    assert!(PivSlot::new(0xF9).is_err() && PivSlot::new(0x9B).is_err());
    let mut fixed = piv(0x82, sol(0));
    fixed.touch = TouchPolicy::AlwaysFixed;
    assert_eq!(validate_plan(&[fixed]), Err(PlanError::Policy(fixed.slot)));
    let mut no_pin = piv(0x82, sol(0));
    no_pin.pin = PinPolicy::NotApplicable;
    assert_eq!(
        validate_plan(&[no_pin]),
        Err(PlanError::Policy(no_pin.slot))
    );
    assert_eq!(validate_plan(&[]), Err(PlanError::SlotCount));
    // All 20 retired + 4 standard PIV slots: 24 Solana accounts on one card.
    let full: Vec<PlannedSlot> = (0..20_u8)
        .map(|n| PivSlot::retired(n).unwrap().id())
        .chain(PivSlot::STANDARD)
        .zip(0_u32..)
        .map(|(id, index)| piv(id, sol(index)))
        .collect();
    validate_plan(&full).unwrap();
    assert!(super::plan::all_hardened(
        &match full[0].role.path().unwrap() {
            super::plan::KeyPath::Slip10(path) => path.components().to_vec(),
            super::plan::KeyPath::Bip32(_) => Vec::new(),
        }
    ));
}

#[test]
fn several_yubikeys_with_different_index_ranges_and_backup_copies() {
    // #1: EVM 0/1, #2: EVM 2/3, #3: EVM 4/5 — 6 secp256k1 keys from one mnemonic; #4 is a backup
    // copy of #1.
    let mut records: Vec<HwKeyRecord> = Vec::new();
    for (serial, first) in [(101_u32, 0_u32), (102, 2), (103, 4)] {
        let mut card = MockCard::new(serial);
        let plan = [sig(evm(first)), aut(evm(first + 1))];
        records.push(enrol(&mut card, ABOUT, &plan, &records).unwrap().record);
    }
    // Same path on another card without the backup flag is refused before anything is written.
    let mut card = MockCard::new(104);
    assert_eq!(
        enrol(&mut card, ABOUT, &[sig(evm(0))], &records).err(),
        Some(EnrolError::Plan(PlanError::PathOnOtherCard(
            CardSlot::OpenPgp(PgpKey::Sig)
        )))
    );
    assert!(card.pgp_keys.iter().all(Option::is_none));
    // Backup flag on a path no other card has.
    let mut flagged = sig(evm(9));
    flagged.backup_copy = true;
    assert_eq!(
        enrol(&mut card, ABOUT, &[flagged], &records).err(),
        Some(EnrolError::Plan(PlanError::NotACopy(flagged.slot)))
    );
    // The explicit backup copy of #1 (the slots may differ: SIG/AUT swapped).
    let mut copy_sig = sig(evm(1));
    copy_sig.backup_copy = true;
    let mut copy_aut = aut(evm(0));
    copy_aut.backup_copy = true;
    records.push(
        enrol(&mut card, ABOUT, &[copy_sig, copy_aut], &records)
            .unwrap()
            .record,
    );
    // The same card again, and a different mnemonic.
    let mut again = MockCard::new(101);
    assert_eq!(
        enrol(&mut again, ABOUT, &[sig(evm(8))], &records).err(),
        Some(EnrolError::Plan(PlanError::CardAlreadyEnrolled))
    );
    let mut stranger = MockCard::new(105);
    assert_eq!(
        enrol(&mut stranger, OTHER, &[sig(evm(8))], &records).err(),
        Some(EnrolError::Plan(PlanError::DifferentMnemonic))
    );
    assert!(records_consistent(&records));

    let map = accounts(&records);
    assert_eq!(map.len(), 6);
    let indices: Vec<u32> = map
        .iter()
        .map(|account| match account.role {
            KeyRole::Evm { index, .. } => index.get(),
            _ => u32::MAX,
        })
        .collect();
    assert_eq!(indices, [0, 1, 2, 3, 4, 5]);
    let holders = |position: usize| -> Vec<(u32, CardSlot)> {
        map[position]
            .holders
            .iter()
            .map(|holder| (holder.serial, holder.slot))
            .collect()
    };
    assert_eq!(
        holders(0),
        [
            (101, CardSlot::OpenPgp(PgpKey::Sig)),
            (104, CardSlot::OpenPgp(PgpKey::Aut))
        ]
    );
    assert_eq!(
        holders(1),
        [
            (101, CardSlot::OpenPgp(PgpKey::Aut)),
            (104, CardSlot::OpenPgp(PgpKey::Sig))
        ]
    );
    assert_eq!(holders(4), [(103, CardSlot::OpenPgp(PgpKey::Sig))]);
    // Sign account 1 with the backup card: the slot map routes to its SIG slot.
    let holder = slot_on_card(&records, evm(1), 104).unwrap();
    assert_eq!(holder.slot, CardSlot::OpenPgp(PgpKey::Sig));
    assert!(slot_on_card(&records, evm(1), 102).is_none());
    let ctx = Secp256k1::new();
    let key = CardKey {
        serial: 104,
        slot: holder.slot,
        public: map[1].public,
    };
    let (parity, compact) =
        sign_evm(&ctx, &mut card, ApduMode::Short, &key, b"123456", [3; 32]).unwrap();
    assert_eq!(
        crate::evm::sign::recover_address([3; 32], parity, &compact),
        Some(super::plan::evm_address(&map[1].public).unwrap())
    );
    // The fingerprints identify the mnemonic.
    assert_eq!(
        records[0].fingerprint,
        master_fingerprint(&ctx, &seed_of(ABOUT)).unwrap()
    );
    assert_eq!(records[0].fingerprint, [0x73, 0xc5, 0xda, 0x0a]);
}

#[test]
fn slot_map_record_round_trip_and_strict_decode() {
    let mut card = MockCard::new(0x0102_0304);
    let mut plan = recommended_plan();
    plan.push(piv(0x95, sol(19)));
    plan[1].touch = TouchPolicy::CachedFixed;
    let record = enrol(&mut card, ABOUT, &plan, &[]).unwrap().record;
    let mut bytes = Vec::new();
    record.encode_into(&mut bytes).unwrap();
    assert_eq!(bytes.len(), record.body_len());
    assert_eq!(bytes.len(), 12 + 5 * 48);
    let (decoded, rest) = HwKeyRecord::decode(&bytes).unwrap();
    assert!(rest.is_empty());
    assert_eq!(decoded, record);
    // Trailing bytes are returned to the caller (the vault codec rejects them).
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(HwKeyRecord::decode(&longer).unwrap().1, [0]);
    // Every single-byte corruption of a code or reserved byte is refused or changes the record.
    for position in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[position] ^= 0x01;
        if let Some((other, _)) = HwKeyRecord::decode(&changed) {
            assert_ne!(other, record, "byte {position}");
        }
    }
    // Specific refusals: slot count 0, reserved byte, unknown applet, Ed25519 pad byte.
    let mut zero = bytes.clone();
    zero[11] = 0;
    assert!(HwKeyRecord::decode(&zero).is_none());
    let mut reserved = bytes.clone();
    reserved[12 + 47] = 1;
    assert!(HwKeyRecord::decode(&reserved).is_none());
    let mut applet = bytes.clone();
    applet[12] = 9;
    assert!(HwKeyRecord::decode(&applet).is_none());
    let mut pad = bytes.clone();
    pad[12 + 2 * 48 + 12] = 1;
    assert!(HwKeyRecord::decode(&pad).is_none());
    // A duplicated path inside one record.
    let mut duplicate = record.clone();
    duplicate.slots[3].role = duplicate.slots[2].role;
    duplicate.slots[3].public = duplicate.slots[2].public;
    assert!(duplicate.encode_into(&mut Vec::new()).is_err());
    // Cross-record: same path with another public key.
    let mut forged = record.clone();
    forged.serial = 1;
    forged.slots[0].public = record.slots[1].public;
    assert!(!records_consistent(&[record.clone(), forged]));
}
