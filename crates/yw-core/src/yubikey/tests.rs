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
        piv_pin: b"",
        cipher: Some(&ToyCipher),
        challenge: [0x5C; 16],
        overwrite: false,
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
    assert_eq!(
        record.slots[0].role.path_text_in(crate::lang::Lang::Ko),
        "m/44'/60'/0'/0/0"
    );
    assert_eq!(
        record.slots[1].role.path_text_in(crate::lang::Lang::Ko),
        "m/84'/0'/0'/0/0"
    );
    assert_eq!(
        record.slots[2].role.path_text_in(crate::lang::Lang::Ko),
        "m/44'/501'/0'/0'"
    );
    assert_eq!(
        record.slots[3].role.path_text_in(crate::lang::Lang::Ko),
        "m/44'/501'/1'/0'"
    );
    // The preview (no card) shows the same keys.
    let shown = preview(&ctx, &seed_of(ABOUT), &recommended_plan()).unwrap();
    for (line, slot) in shown.iter().zip(&record.slots) {
        assert_eq!(line.public, slot.public);
        assert_eq!(line.path, slot.role.path_text_in(crate::lang::Lang::Ko));
    }
    // The card holds what was planned: secp256k1 attributes, fixed touch, PIV policies.
    assert_eq!(
        card.pgp_attributes[0],
        super::openpgp::secp256k1_attributes()
    );
    assert_eq!(card.pgp_uif, [0x01, 0x00, 0x01]);
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
    // Re-enrolling a card whose SIG touch policy is already fixed (the user agreed to replace
    // the key there): the same fixed policy is kept (no UIF write), another one is refused
    // before any key is written.
    let mut card = MockCard::new(8);
    let fixed = |role| {
        let mut planned = sig(role);
        planned.touch = TouchPolicy::AlwaysFixed;
        planned
    };
    let overwrite = EnrolAuth {
        overwrite: true,
        ..default_auth()
    };
    let replace = |card: &mut MockCard, slots: &[PlannedSlot]| {
        enrol_card(
            card,
            ApduMode::Short,
            &seed_of(ABOUT),
            slots,
            &[],
            &overwrite,
        )
    };
    enrol(&mut card, ABOUT, &[fixed(evm(0))], &[]).unwrap();
    replace(&mut card, &[fixed(evm(5))]).unwrap();
    let mut cached = sig(evm(6));
    cached.touch = TouchPolicy::CachedFixed;
    let before = card.pgp_keys[0];
    card.log.clear();
    assert_eq!(
        replace(&mut card, &[cached]).err(),
        Some(EnrolError::Card(CardError::Conditions))
    );
    assert_eq!(card.pgp_keys[0], before);
    assert!(!card.saw_write() && !card.log.iter().any(|header| header[1] == 0x20));
    // A 5.7.2 card refusing the Ed25519 import gets the specific message; on 5.7.4 the same
    // refusal stays a plain data error.
    let mut card = MockCard::new(9);
    card.firmware = Firmware::new(5, 7, 2);
    card.refuse_ed25519_import = true;
    assert_eq!(
        enrol(&mut card, ABOUT, &[piv(0x82, sol(0))], &[]).err(),
        Some(EnrolError::Card(CardError::Ed25519ImportRefused))
    );
    card.firmware = Firmware::new(5, 7, 4);
    assert_eq!(
        enrol(&mut card, ABOUT, &[piv(0x82, sol(0))], &[]).err(),
        Some(EnrolError::Partial(CardError::WrongData))
    );
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
    assert_eq!(
        plan[0].role.path_text_in(crate::lang::Lang::Ko),
        "m/44'/60'/0'/0/7"
    );
    assert_eq!(
        plan[1].role.path_text_in(crate::lang::Lang::Ko),
        "m/84'/0'/0'/0/19"
    );
    assert_eq!(
        plan[2].role.path_text_in(crate::lang::Lang::Ko),
        "m/44'/501'/4'/0'"
    );
    let legacy = KeyRole::Btc {
        network: BtcNetwork::Testnet4,
        script: ScriptType::P2pkh,
        index: 3,
    };
    assert_eq!(
        legacy.path_text_in(crate::lang::Lang::Ko),
        "m/44'/1'/0'/0/3"
    );
    let nested = KeyRole::Btc {
        network: BtcNetwork::Mainnet,
        script: ScriptType::P2shP2wpkh,
        index: 0,
    };
    assert_eq!(
        nested.path_text_in(crate::lang::Lang::Ko),
        "m/49'/0'/0'/0/0"
    );
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
    // Same path on another card without the backup flag is a copy too, and may sit next to a
    // new key (2026-11-12): #1's EVM 0 and a new EVM 9.
    let mut mixed = MockCard::new(105);
    let enrolled = enrol(&mut mixed, ABOUT, &[sig(evm(0)), aut(evm(9))], &records).unwrap();
    assert_eq!(
        enrolled.record.slots.first().map(|slot| slot.public),
        records
            .first()
            .and_then(|record| record.slots.first())
            .map(|slot| slot.public)
    );
    let mut card = MockCard::new(104);
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

/// spec/10 §9.2: the PIN check before signing sends no write and no signing command, counts a
/// wrong PIN like a signature would, accepts the right one (OpenPGP PW1 and PIV), refuses
/// another card before any VERIFY, and the signature afterwards still verifies the PIN itself.
#[test]
fn pin_check_before_signing() {
    use super::sign::check_pin;
    let mut card = MockCard::new(6);
    let record = enrol(&mut card, ABOUT, &recommended_plan(), &[])
        .unwrap()
        .record;
    card.log.clear();
    let evm_key = card_key(&record, 0);
    let sol_key = card_key(&record, 2);
    assert_eq!(
        check_pin(&mut card, ApduMode::Short, &evm_key, b"000000"),
        Err(CardError::WrongPin { retries: 2 })
    );
    check_pin(&mut card, ApduMode::Short, &evm_key, b"123456").unwrap();
    check_pin(&mut card, ApduMode::Short, &sol_key, b"123456").unwrap();
    assert_eq!(
        check_pin(&mut card, ApduMode::Short, &sol_key, b"999999"),
        Err(CardError::WrongPin { retries: 2 })
    );
    assert!(!card.saw_write());
    // No PSO:CDS, INTERNAL AUTHENTICATE or GENERAL AUTHENTICATE.
    assert!(
        !card
            .log
            .iter()
            .any(|header| matches!(header[1], 0x2A | 0x88 | 0x87))
    );
    let ctx = Secp256k1::new();
    sign_evm(
        &ctx,
        &mut card,
        ApduMode::Short,
        &evm_key,
        b"123456",
        [3; 32],
    )
    .unwrap();
    let mut other = MockCard::new(98);
    other.log.clear();
    assert_eq!(
        check_pin(&mut other, ApduMode::Short, &evm_key, b"123456"),
        Err(CardError::WrongCard)
    );
    assert!(!other.log.iter().any(|header| header[1] == 0x20));
}

/// spec/10 §7.5 "가져오기 없이 등록": a card that already holds the planned keys gives the same
/// record without any write; a card holding other keys (or none) is refused.
#[test]
fn adopt_card_reads_the_keys_back_without_writing() {
    use super::enrol::adopt_card;
    let mut card = MockCard::new(31_000_001);
    let enrolled = enrol(&mut card, ABOUT, &recommended_plan(), &[]).unwrap();
    card.log.clear();
    let adopted = adopt_card(
        &mut card,
        ApduMode::Short,
        &seed_of(ABOUT),
        &recommended_plan(),
        &[],
    )
    .unwrap();
    assert_eq!(adopted.record, enrolled.record);
    assert!(!card.saw_write(), "{:x?}", card.log);
    // Another mnemonic's keys are not on this card: nothing is recorded.
    assert_eq!(
        adopt_card(
            &mut card,
            ApduMode::Short,
            &seed_of(OTHER),
            &recommended_plan(),
            &[]
        ),
        Err(EnrolError::Card(CardError::KeyMismatch))
    );
    // An empty card: the OpenPGP slot answers "no key".
    let mut empty = MockCard::new(31_000_002);
    assert!(
        adopt_card(
            &mut empty,
            ApduMode::Short,
            &seed_of(ABOUT),
            &[sig(evm(0))],
            &[]
        )
        .is_err()
    );
    assert!(!empty.saw_write());
    // Already enrolled serial: refused before any slot is read.
    assert_eq!(
        adopt_card(
            &mut card,
            ApduMode::Short,
            &seed_of(ABOUT),
            &recommended_plan(),
            core::slice::from_ref(&enrolled.record)
        ),
        Err(EnrolError::Plan(PlanError::CardAlreadyEnrolled))
    );
}

/// The checks the confirmation screen can run before any card contact (spec/10 §7.2) and the
/// address texts of the slot-map screens.
#[test]
fn validate_before_card_and_address_texts() {
    use super::plan::{address_texts, validate_before_card};
    let mut card = MockCard::new(31_000_003);
    let first = enrol(&mut card, ABOUT, &[sig(evm(0)), aut(btc(0))], &[]).unwrap();
    let records = [first.record.clone()];
    let fingerprint = first.record.fingerprint;
    // Another card's path is a copy with or without the flag (2026-11-12).
    assert_eq!(
        validate_before_card(&records, fingerprint, &[sig(evm(0)), aut(evm(7))]),
        Ok(())
    );
    let mut copy = sig(evm(0));
    copy.backup_copy = true;
    assert_eq!(validate_before_card(&records, fingerprint, &[copy]), Ok(()));
    assert_eq!(
        validate_before_card(&records, [0; 4], &[sig(evm(5))]),
        Err(PlanError::DifferentMnemonic)
    );
    assert_eq!(
        validate_before_card(&records, fingerprint, &[sig(evm(1)), aut(evm(1))]),
        Err(PlanError::DuplicatePath(CardSlot::OpenPgp(PgpKey::Aut)))
    );
    assert_eq!(
        address_texts(first.record.slots[1].role, &first.record.slots[1].public).unwrap(),
        ["bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"]
    );
    let shared = KeyRole::Evm {
        index: AccountIndex::ZERO,
        btc: Some(BtcUse {
            network: BtcNetwork::Mainnet,
            script: ScriptType::P2wpkh,
        }),
    };
    assert_eq!(
        address_texts(shared, &first.record.slots[0].public)
            .unwrap()
            .len(),
        2
    );
}

/// spec/10 §9.3 on the emulator: `OpenPGP` PW1/PW3, PIV PIN/PUK and the management key change.
#[test]
fn defaults_change_on_the_emulator() {
    use super::openpgp::OpenPgp;
    use super::piv::{MgmtAlgorithm, MgmtKey, Piv};
    let mut card = MockCard::new(31_000_004);
    {
        let mut session = OpenPgp::open(&mut card, ApduMode::Short).unwrap();
        session.change_pin(false, b"123456", b"246810").unwrap();
        session.change_pin(true, b"12345678", b"13579111").unwrap();
    }
    assert_eq!(card.pw1, b"246810");
    assert_eq!(card.pw3, b"13579111");
    {
        let mut session = Piv::open(&mut card, ApduMode::Short).unwrap();
        session
            .change_reference(false, b"123456", b"654321")
            .unwrap();
        session
            .change_reference(true, b"12345678", b"87654321")
            .unwrap();
        assert!(
            session
                .change_reference(true, b"12345678", b"11112222")
                .is_err()
        );
        let old = MgmtKey::default_for(MgmtAlgorithm::Aes192).unwrap();
        session.authenticate(&old, &ToyCipher, &[0x11; 16]).unwrap();
        session
            .set_management_key(&MgmtKey::new(MgmtAlgorithm::Aes192, &[0x42; 24]).unwrap())
            .unwrap();
    }
    assert_eq!(card.piv_pin, b"654321");
    assert_eq!(card.piv_puk, b"87654321");
    assert_eq!(card.mgmt_key, [0x42; 24]);
}

/// spec/10 §5.3.3 on the emulator: the PIN-protected management key (ykman `--generate
/// --protect`): the object layouts, enrolment with the PIV PIN only, and the wallet's own
/// "generate and protect" from the factory key.
#[test]
fn pin_protected_management_key() {
    use super::piv::{
        ADMIN_FLAG_MGM_PROTECTED, AdminData, ManagementCredential, OBJECT_ADMIN_DATA,
        OBJECT_PRINTED, Piv, get_data, parse_protected_key, put_data,
    };
    let frame = |command: &super::apdu::Command| {
        super::apdu::encode(command, ApduMode::Short).unwrap()[0].to_vec()
    };
    assert_eq!(
        frame(&get_data(OBJECT_ADMIN_DATA)),
        [
            0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xFF, 0x00, 0x00
        ]
    );
    assert_eq!(
        frame(&put_data(OBJECT_PRINTED, &[]).unwrap()),
        [
            0x00, 0xDB, 0x3F, 0xFF, 0x07, 0x5C, 0x03, 0x5F, 0xC1, 0x09, 0x53, 0x00
        ]
    );
    let admin = AdminData::parse(&[0x80, 0x09, 0x81, 0x01, 0x03, 0x83, 0x04, 1, 2, 3, 4]).unwrap();
    assert!(admin.mgm_key_protected());
    assert_eq!(admin.pin_timestamp, Some([1, 2, 3, 4]));
    assert_eq!(
        admin.encode().unwrap(),
        [0x80, 0x09, 0x81, 0x01, 0x03, 0x83, 0x04, 1, 2, 3, 4]
    );
    assert!(AdminData::default().encode().unwrap().is_empty());
    assert!(AdminData::parse(&[0x81, 0x01, 0x02]).is_err());
    assert_eq!(parse_protected_key(&[]).unwrap(), None);

    // A card set up by ykman: enrolment needs only the PIV PIN.
    let plan = vec![piv(0x82, sol(0))];
    let mut card = MockCard::new(31_000_010);
    card.protect_management([0x37; 24]);
    // The factory key is not tried on a protected card: only the PIN opens it.
    let mut auth = default_auth();
    let seed = seed_of(ABOUT);
    assert_eq!(
        enrol_card(&mut card, ApduMode::Short, &seed, &plan, &[], &auth),
        Err(EnrolError::Card(CardError::ManagementKeyProtected))
    );
    auth.piv_pin = b"999999";
    assert_eq!(
        enrol_card(&mut card, ApduMode::Short, &seed, &plan, &[], &auth),
        Err(EnrolError::Card(CardError::WrongPin { retries: 2 }))
    );
    auth.piv_pin = b"123456";
    let enrolled = enrol_card(&mut card, ApduMode::Short, &seed, &plan, &[], &auth).unwrap();
    assert!(enrolled.defaults.piv_management_protected);
    assert!(!enrolled.defaults.piv_management);

    // The wallet's own --generate --protect from the factory key.
    let mut fresh = MockCard::new(31_000_011);
    {
        let mut session = Piv::open(&mut fresh, ApduMode::Short).unwrap();
        assert!(!session.management_state().unwrap().protected);
        assert_eq!(
            session.protect_management_key(b"000000", &ToyCipher, &[0x21; 16]),
            Err(CardError::WrongPin { retries: 2 })
        );
        session
            .protect_management_key(b"123456", &ToyCipher, &[0x21; 16])
            .unwrap();
    }
    assert_ne!(fresh.mgmt_key, super::piv::DEFAULT_MANAGEMENT_KEY);
    let printed = parse_protected_key(fresh.piv_object(OBJECT_PRINTED).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(printed.as_slice(), fresh.mgmt_key.as_slice());
    let admin = AdminData::parse(fresh.piv_object(OBJECT_ADMIN_DATA).unwrap()).unwrap();
    assert_eq!(admin.flags, ADMIN_FLAG_MGM_PROTECTED);
    // Again (now protected): a new key, still readable with the PIN only.
    let first = fresh.mgmt_key.clone();
    let mut session = Piv::open(&mut fresh, ApduMode::Short).unwrap();
    session
        .protect_management_key(b"123456", &ToyCipher, &[0x22; 16])
        .unwrap();
    let state = session
        .authenticate_management(
            ManagementCredential {
                key: b"",
                pin: b"123456",
            },
            &ToyCipher,
            &[0x23; 16],
        )
        .unwrap();
    assert!(state.protected && !state.default);
    assert_ne!(fresh.mgmt_key, first);
    // A custom key that is not protected is not guessed.
    let mut custom = MockCard::new(31_000_012);
    custom.mgmt_key = vec![0x42; 24];
    let mut session = Piv::open(&mut custom, ApduMode::Short).unwrap();
    assert_eq!(
        session.protect_management_key(b"123456", &ToyCipher, &[0x24; 16]),
        Err(CardError::ManagementKeyUnknown)
    );
}

/// spec/10 §9.1: a `YubiKey`'s `OpenPGP` applet answers a wrong PIN with `6982`; the session
/// reads the counters again (`6E`/`C4`) and reports `WrongPin` with the tries left (PW1 and
/// PW3 separately, `0` = blocked and final), also for CHANGE REFERENCE DATA.
#[test]
fn openpgp_wrong_pin_6982_reads_the_counter_again() {
    use super::openpgp::{OpenPgp, Pw, select, verify};
    let mut card = MockCard::new(41_000_001);
    {
        let mut session = OpenPgp::open(&mut card, ApduMode::Short).unwrap();
        assert_eq!(session.app.retries, [3, 0, 3]);
        assert_eq!(
            session.verify(Pw::Admin, b"87654321"),
            Err(CardError::WrongPin { retries: 2 })
        );
        assert_eq!(session.app.retries, [3, 0, 2]);
        assert_eq!(
            session.change_pin(false, b"654321", b"135791"),
            Err(CardError::WrongPin { retries: 2 })
        );
        assert_eq!(
            session.verify(Pw::UserOther, b"000000"),
            Err(CardError::WrongPin { retries: 1 })
        );
        assert_eq!(
            session.verify(Pw::UserOther, b"000000"),
            Err(CardError::WrongPin { retries: 0 })
        );
    }
    assert!(!CardError::WrongPin { retries: 0 }.pin_retryable());
    assert!(CardError::WrongPin { retries: 1 }.pin_retryable());
    // The emulator answers like a YubiKey: 6982 for a wrong PIN, 6983 once blocked.
    let status = |card: &mut MockCard, pin: &[u8]| {
        super::apdu::exchange(card, &verify(Pw::Admin, pin), ApduMode::Short)
            .unwrap()
            .sw
    };
    assert_eq!(
        super::apdu::exchange(&mut card, &select(), ApduMode::Short)
            .unwrap()
            .sw,
        0x9000
    );
    assert_eq!(status(&mut card, b"87654321"), 0x6982);
    assert_eq!(status(&mut card, b"87654321"), 0x6982);
    assert_eq!(status(&mut card, b"87654321"), 0x6983);
    let mut session = OpenPgp::open(&mut card, ApduMode::Short).unwrap();
    assert_eq!(session.app.retries, [0, 0, 0]);
    assert_eq!(
        session.verify(Pw::Admin, b"12345678"),
        Err(CardError::PinBlocked)
    );
}

/// spec/10 §5.3.3 recovery: a "PIV 관리 키 자동 보호" that stopped after SET MANAGEMENT KEY and
/// before the ADMIN DATA flag ("neither default nor protected", key in PRINTED) is finished by
/// running it again with the PIN, and an enrolment with the PIN authenticates with PRINTED; a
/// re-protect that stopped after PRINTED and before SET MANAGEMENT KEY still authenticates with
/// the previous key when it is in memory.
#[test]
fn protected_management_key_recovers_from_a_partial_protect() {
    use super::piv::{ManagementCredential, OBJECT_ADMIN_DATA, OBJECT_PRINTED, Piv};
    let mut card = MockCard::new(41_000_002);
    Piv::open(&mut card, ApduMode::Short)
        .unwrap()
        .protect_management_key(b"123456", &ToyCipher, &[0x31; 16])
        .unwrap();
    card.piv_objects.retain(|(id, _)| *id != OBJECT_ADMIN_DATA);
    let credential = |key| ManagementCredential {
        key,
        pin: b"123456",
    };
    {
        let mut session = Piv::open(&mut card, ApduMode::Short).unwrap();
        let state = session.management_state().unwrap();
        assert!(!state.default && !state.protected);
        session
            .authenticate_management(credential(b""), &ToyCipher, &[0x32; 16])
            .unwrap();
        session
            .protect_management_key(b"123456", &ToyCipher, &[0x33; 16])
            .unwrap();
        assert!(session.management_state().unwrap().protected);
    }
    // PRINTED holds a key the card never got: the previous key in memory still opens it.
    let previous = card.mgmt_key.clone();
    let mut printed = vec![0x88, 0x1A, 0x89, 0x18];
    printed.extend_from_slice(&[0x5C; 24]);
    card.piv_objects.retain(|(id, _)| *id != OBJECT_PRINTED);
    card.piv_objects.push((OBJECT_PRINTED, printed));
    let mut session = Piv::open(&mut card, ApduMode::Short).unwrap();
    assert!(
        session
            .authenticate_management(credential(b""), &ToyCipher, &[0x34; 16])
            .is_err()
    );
    session
        .authenticate_management(credential(&previous), &ToyCipher, &[0x35; 16])
        .unwrap();
}

/// "YubiKey 연결하기 (복구 단어 없이)" (spec/10 §7.6): a card holding keys from words the PC never
/// sees is scanned read-only, connected with unknown paths, round-trips as a record that earlier
/// builds refuse, and signs for EVM, Bitcoin, Solana and Zcash through the slot map like an
/// enrolled card.
#[test]
#[allow(clippy::too_many_lines, reason = "one end-to-end scenario")]
fn connect_without_words_and_sign_every_chain() {
    use super::connect::{KeyUse, connect_card, connect_record, scan_card, verify_pin};
    use super::plan::{Curve, T_UNKNOWN_PATH, address_texts};
    use super::record::{BODY_FIXED_LEN, SLOT_ENTRY_LEN};
    use crate::zec::ZecNetwork;

    let sig_slot = CardSlot::OpenPgp(PgpKey::Sig);
    let aut_slot = CardSlot::OpenPgp(PgpKey::Aut);
    let piv_slot = CardSlot::Piv(PivSlot::new(0x9A).unwrap());
    // Keys put on the card earlier from OTHER (not known to this wallet).
    let mut card = MockCard::new(31);
    let original = enrol(
        &mut card,
        OTHER,
        &[sig(evm(5)), aut(btc(3)), piv(0x9A, sol(2))],
        &[],
    )
    .unwrap()
    .record;
    card.log.clear();
    let scan = scan_card(&mut card, ApduMode::Short).unwrap();
    assert!(!card.saw_write(), "the scan only reads");
    assert_eq!((scan.serial, scan.keys.len()), (31, 3));
    assert_eq!(
        (scan.pgp_pin_retries, scan.piv_pin_retries),
        (Some(3), Some(3))
    );
    assert!(scan.defaults.piv_pin && scan.unsupported.is_empty());
    let choices = [
        (sig_slot, KeyUse::Evm),
        (
            aut_slot,
            KeyUse::Btc {
                network: BtcNetwork::Mainnet,
                script: ScriptType::P2wpkh,
            },
        ),
        (piv_slot, KeyUse::Sol),
    ];
    let record = connect_record(&scan, &choices, &[]).unwrap();
    assert_eq!(record.fingerprint, [0; 4]);
    for (slot, before) in record.slots.iter().zip(&original.slots) {
        assert!(!slot.path_known);
        assert_eq!(slot.role.index(), 900);
        assert_eq!(
            (slot.public, slot.touch, slot.pin),
            (before.public, before.touch, before.pin)
        );
        // The addresses are those of the keys at their real (unknown here) paths.
        assert_eq!(
            address_texts(slot.role, &slot.public),
            address_texts(before.role, &before.public)
        );
        assert_eq!(slot.path_text_in(crate::lang::Lang::Ko), T_UNKNOWN_PATH);
        assert_eq!(
            slot.role.path_text_in(crate::lang::Lang::Ko),
            T_UNKNOWN_PATH
        );
    }
    // A use of the other curve, or a slot the scan did not find, is refused.
    assert_eq!(
        connect_record(&scan, &[(piv_slot, KeyUse::Evm)], &[]),
        Err(EnrolError::Plan(PlanError::WrongApplet(piv_slot)))
    );
    // A re-slot never plans an index of the unknown-path band (spec/10 §15.1).
    assert_eq!(
        super::manage::validate_reslot(
            &original,
            original.fingerprint,
            &[sig(evm(950)), aut(btc(3))],
            &[]
        ),
        Err(PlanError::UnsupportedRole(sig_slot))
    );
    // The connected card names no mnemonic: a re-slot takes the entered words (its PIV key
    // stays as it is), unless another card with a known path has other words.
    let words = [9, 8, 7, 6];
    let new_slots = [sig(evm(0)), aut(btc(1))];
    assert_eq!(
        super::manage::validate_reslot(&record, words, &new_slots, &[]),
        Ok(())
    );
    let mut other_card = original.clone();
    other_card.serial = 32;
    assert_eq!(
        super::manage::validate_reslot(
            &record,
            words,
            &new_slots,
            std::slice::from_ref(&other_card)
        ),
        Err(PlanError::DifferentMnemonic)
    );
    assert_eq!(
        super::manage::validate_reslot(
            &record,
            other_card.fingerprint,
            &new_slots,
            std::slice::from_ref(&other_card)
        ),
        Ok(())
    );
    assert_eq!(
        super::manage::validate_reslot(&original, words, &new_slots, &[]),
        Err(PlanError::DifferentMnemonic)
    );

    // Record: round trip; the flag sits in the bytes earlier builds require to be zero, so
    // they refuse the payload (UnsupportedPayload) instead of misreading it.
    let mut body = Vec::new();
    record.encode_into(&mut body).unwrap();
    let (decoded, rest) = HwKeyRecord::decode(&body).unwrap();
    assert_eq!((decoded, rest.len()), (record.clone(), 0));
    let flag_at = |slot: usize| BODY_FIXED_LEN + slot * SLOT_ENTRY_LEN + 45;
    for slot in 0..3 {
        assert_eq!(body[flag_at(slot)..flag_at(slot) + 3], [1, 0, 0]);
    }
    // An enrolled record is byte-identical to before: the flag byte stays zero.
    let mut known = Vec::new();
    original.encode_into(&mut known).unwrap();
    assert!((0..3).all(|slot| known[flag_at(slot)..flag_at(slot) + 3] == [0, 0, 0]));
    // An unknown-path flag outside the band, or a fingerprint on an all-unknown record, is refused.
    let mut forged = original.clone();
    forged.slots[0].path_known = false;
    assert!(!forged.is_valid());
    let mut forged = record.clone();
    forged.fingerprint = [1, 2, 3, 4];
    assert!(!forged.is_valid());

    // "저장": a fresh read-only scan of the same card must still hold the confirmed keys.
    let connected = connect_card(&mut card, ApduMode::Short, 31, &choices, &record, &[]).unwrap();
    assert_eq!(connected.record, record);
    assert!(connected.defaults.piv_pin);
    assert_eq!(
        connect_card(&mut card, ApduMode::Short, 32, &choices, &record, &[]).err(),
        Some(EnrolError::Card(CardError::WrongCard))
    );
    assert!(!card.saw_write());

    // Optional PIN check: the factory PIN is never sent; a wrong one shows the tries left.
    assert_eq!(
        verify_pin(&mut card, ApduMode::Short, 31, Curve::Secp256k1, b"123456"),
        Err(CardError::PinFormat)
    );
    assert_eq!(
        verify_pin(&mut card, ApduMode::Short, 31, Curve::Secp256k1, b"999999"),
        Err(CardError::WrongPin { retries: 2 })
    );
    card.piv_pin = b"24681357".to_vec();
    verify_pin(&mut card, ApduMode::Short, 31, Curve::Ed25519, b"24681357").unwrap();
    card.pgp_retries = [3, 3];

    // A second card: Zcash testnet in SIG, and a backup copy of the EVM key in AUT keeps the
    // first card's account (same role, two holders).
    let mut second = MockCard::new(32);
    let zec_role = KeyRole::Zec {
        network: ZecNetwork::Testnet,
        index: 4,
    };
    enrol(&mut second, OTHER, &[sig(zec_role), aut(evm(5))], &[]).unwrap();
    second.log.clear();
    let second_scan = scan_card(&mut second, ApduMode::Short).unwrap();
    let second_record = connect_record(
        &second_scan,
        &[
            (
                sig_slot,
                KeyUse::Zec {
                    network: ZecNetwork::Testnet,
                },
            ),
            (aut_slot, KeyUse::Evm),
        ],
        std::slice::from_ref(&record),
    )
    .unwrap();
    assert_eq!(
        second_record.slots[0].role,
        KeyRole::Zec {
            network: ZecNetwork::Testnet,
            index: 900
        }
    );
    assert_eq!(second_record.slots[1].role, record.slots[0].role);
    let records = vec![record.clone(), second_record.clone()];
    assert!(records_consistent(&records));
    assert_eq!(accounts(&records).len(), 4);
    // A mnemonic enrolment cannot use the band.
    assert_eq!(
        super::plan::validate_before_card(&records, [9; 4], &[sig(evm(900))]),
        Err(PlanError::UnsupportedRole(sig_slot))
    );

    // Signing goes through the slot map exactly like an enrolled card.
    let ctx = Secp256k1::new();
    let key_for = |records: &[HwKeyRecord], role: KeyRole, serial: u32| {
        let holder = slot_on_card(records, role, serial).unwrap();
        let public = records
            .iter()
            .find(|record| record.serial == serial)
            .and_then(|record| record.slots.iter().find(|slot| slot.slot == holder.slot))
            .unwrap()
            .public;
        CardKey {
            serial,
            slot: holder.slot,
            public,
        }
    };
    let verify_der = |key: &CardKey, digest: [u8; 32], der: &[u8]| {
        let HwPublicKey::Secp256k1(public) = key.public else {
            unreachable!("secp key");
        };
        ctx.verify_ecdsa(
            Message::from_digest(digest),
            &secp256k1::ecdsa::Signature::from_der(der).unwrap(),
            &PublicKey::from_slice(&public).unwrap(),
        )
        .unwrap();
    };
    // EVM (SIG of card 31): the recovered address is the account's.
    let evm_key = key_for(&records, record.slots[0].role, 31);
    let digest = [0x42; 32];
    let (parity, compact) = sign_evm(
        &ctx,
        &mut card,
        ApduMode::Short,
        &evm_key,
        b"123456",
        digest,
    )
    .unwrap();
    assert_eq!(
        crate::evm::sign::recover_address(digest, parity, &compact),
        super::plan::evm_address(&evm_key.public).ok()
    );
    // The backup holder (AUT of card 32) signs for the same account.
    let backup = key_for(&records, record.slots[0].role, 32);
    assert_eq!(backup.slot, aut_slot);
    let (parity, compact) = sign_evm(
        &ctx,
        &mut second,
        ApduMode::Short,
        &backup,
        b"123456",
        digest,
    )
    .unwrap();
    assert_eq!(
        crate::evm::sign::recover_address(digest, parity, &compact),
        super::plan::evm_address(&evm_key.public).ok()
    );
    // Bitcoin (AUT of card 31) and Zcash (SIG of card 32): a sighash signed and verified.
    let btc_key = key_for(&records, record.slots[1].role, 31);
    let der = sign_btc(
        &ctx,
        &mut card,
        ApduMode::Short,
        &btc_key,
        b"123456",
        [7; 32],
    )
    .unwrap();
    verify_der(&btc_key, [7; 32], &der);
    let zec_key = key_for(&records, second_record.slots[0].role, 32);
    let der =
        super::sign::sign_btc_checked(&mut second, ApduMode::Short, &zec_key, b"123456", [9; 32])
            .unwrap();
    verify_der(&zec_key, [9; 32], &der);
    assert_eq!(
        address_texts(second_record.slots[0].role, &zec_key.public).unwrap(),
        vec![super::plan::zec_address(&zec_key.public, ZecNetwork::Testnet).unwrap()]
    );
    // Solana (PIV 9A of card 31).
    let sol_key = key_for(&records, record.slots[2].role, 31);
    card.piv_pin = super::piv::DEFAULT_PIN.to_vec();
    let signature = sign_sol(&mut card, ApduMode::Short, &sol_key, b"123456", b"connect").unwrap();
    let HwPublicKey::Ed25519(public) = sol_key.public else {
        unreachable!("ed key");
    };
    ed25519_dalek::VerifyingKey::from_bytes(&public)
        .unwrap()
        .verify_strict(
            b"connect",
            &ed25519_dalek::Signature::from_bytes(&signature),
        )
        .unwrap();
    assert!(!card.saw_write() && !second.saw_write());
}

/// spec/10 §15: "이 지갑의 슬롯만 지우기" and "슬롯 구성 바꾸기" read every slot they would empty or
/// overwrite before any PIN or write. A key the record does not list (another program's key)
/// stops that applet with nothing deleted or written; an empty slot, the recorded key, and for a
/// re-slot the new key itself (a retry after a partial write) go ahead.
#[test]
fn clear_and_reslot_keep_a_key_the_record_does_not_list() {
    use super::manage::{ClearAuth, ClearMethod, ClearPlan, clear_card, reslot_card};
    use super::openpgp::{SlotKey, parse_slot_key};
    use super::tlv;

    // READ PUBLIC KEY answers: empty (6A88 or no key value), an RSA key, a status error.
    let rsa = {
        let mut inner = tlv::encode(0x81, &[0xC5; 256]).unwrap();
        inner.extend(tlv::encode(0x82, &[1, 0, 1]).unwrap());
        tlv::encode(0x7F49, &inner).unwrap()
    };
    let no_point = tlv::encode(0x7F49, &tlv::encode(0x86, &[]).unwrap()).unwrap();
    assert_eq!(parse_slot_key(0x6A88, &[]), Ok(SlotKey::Empty));
    assert_eq!(parse_slot_key(0x9000, &no_point), Ok(SlotKey::Empty));
    assert_eq!(parse_slot_key(0x9000, &rsa), Ok(SlotKey::Other));
    assert_eq!(parse_slot_key(0x6982, &[]), Err(CardError::SecurityStatus));

    let seed = seed_of(ABOUT);
    let mut card = MockCard::new(41);
    let record = enrol(&mut card, ABOUT, &recommended_plan(), &[])
        .unwrap()
        .record;
    let foreign = [0x11; 32];
    let (our_sig, our_aut) = (card.pgp_keys[0], card.pgp_keys[2]);
    let auth = ClearAuth {
        admin_pin: b"12345678",
        piv_pin: super::piv::DEFAULT_PIN,
        cipher: Some(&ToyCipher),
        challenge: [0x5C; 16],
    };
    let pin_sent = |card: &MockCard| card.log.iter().any(|[_, ins, _, _]| *ins == 0x20);
    let both = ClearPlan {
        openpgp: Some(ClearMethod::OurSlots),
        piv: Some(ClearMethod::OurSlots),
    };

    // Another secp256k1 key in AUT: OpenPGP refused before the admin PIN, SIG kept, PIV not tried.
    card.pgp_keys[2] = Some(foreign);
    card.log.clear();
    let report = clear_card(&mut card, ApduMode::Short, &record, both, &auth).unwrap();
    assert_eq!(report.openpgp, Some(Err(CardError::ForeignKey)));
    assert_eq!(report.piv, None);
    assert!(!card.saw_write() && !pin_sent(&card));
    assert_eq!(
        (card.pgp_keys[0], card.pgp_keys[2]),
        (our_sig, Some(foreign))
    );
    assert_eq!(card.piv_keys.len(), 2);

    // Another Ed25519 key in one recorded PIV slot: refused before the PIV PIN, both slots kept.
    card.pgp_keys[2] = our_aut;
    let our_piv = card.piv_keys[1].1.seed;
    card.piv_keys[1].1.seed = [0x22; 32];
    card.log.clear();
    let piv_only = ClearPlan {
        openpgp: None,
        piv: Some(ClearMethod::OurSlots),
    };
    let report = clear_card(&mut card, ApduMode::Short, &record, piv_only, &auth).unwrap();
    assert_eq!(report.piv, Some(Err(CardError::ForeignKey)));
    assert!(!card.saw_write() && !pin_sent(&card));
    assert_eq!(card.piv_keys.len(), 2);
    card.piv_keys[1].1.seed = our_piv;

    // Re-slot to EVM 0 + EVM 1: another key in AUT (recorded: Bitcoin 0) is refused before the
    // admin PIN, nothing written.
    let plan = [sig(evm(0)), aut(evm(1))];
    let reslot = |card: &mut MockCard, record: &HwKeyRecord| {
        reslot_card(
            card,
            ApduMode::Short,
            &seed,
            record,
            &plan,
            &[],
            b"12345678",
        )
    };
    card.pgp_keys[2] = Some(foreign);
    card.log.clear();
    assert_eq!(
        reslot(&mut card, &record),
        Err(EnrolError::Card(CardError::ForeignKey))
    );
    assert!(!card.saw_write() && !pin_sent(&card));
    assert_eq!(card.pgp_keys[2], Some(foreign));
    // An empty AUT is written; SIG keeps its key. The factory admin PIN worked: the card is
    // reported as on its defaults again (spec/10 §9.3).
    card.pgp_keys[2] = None;
    let updated = reslot(&mut card, &record).unwrap();
    assert!(updated.defaults.openpgp_admin);
    let updated = updated.record;
    assert_eq!(updated.slots[0], record.slots[0]);
    assert_eq!(updated.slots[1].role, evm(1));
    assert_eq!(card.pgp_keys[0], our_sig);
    // A retry with the old record (the vault was not updated): AUT already holds the new key.
    assert_eq!(
        reslot(&mut card, &record).map(|enrolled| enrolled.record),
        Ok(updated.clone())
    );
    // The record of the card again: an empty SIG and the recorded keys elsewhere are cleared.
    card.pgp_keys[0] = None;
    let report = clear_card(&mut card, ApduMode::Short, &updated, both, &auth).unwrap();
    assert_eq!((report.openpgp, report.piv), (Some(Ok(())), Some(Ok(()))));
    assert_eq!(card.pgp_keys, [None, None, None]);
    assert!(card.piv_keys.is_empty());
}

/// spec/10 §7.4: an enrolment never writes over a key it does not derive unless the user saw it
/// and agreed (`EnrolAuth::overwrite`): another key in AUT and another Ed25519 key in PIV 82 are
/// listed (read-only) and refused before any PIN or write; the empty SIG and the planned keys
/// themselves (a retry after a partial write, the same words again) are not listed. spec/10
/// §15.5: an applet reset blocks counters above 15 within the tries the card reports.
#[test]
fn enrolment_keeps_a_key_it_does_not_derive_and_resets_high_counters() {
    use super::manage::{ClearAuth, ClearMethod, ClearPlan, clear_card};

    let seed = seed_of(ABOUT);
    let mut card = MockCard::new(42);
    let foreign = [0x11; 32];
    card.pgp_attributes[2] = super::openpgp::secp256k1_attributes();
    let auth = ClearAuth {
        admin_pin: b"12345678",
        piv_pin: super::piv::DEFAULT_PIN,
        cipher: Some(&ToyCipher),
        challenge: [0x5C; 16],
    };
    let pin_sent = |card: &MockCard| card.log.iter().any(|[_, ins, _, _]| *ins == 0x20);

    let ed_foreign = [0x33; 32];
    card.pgp_keys[2] = Some(foreign);
    card.piv_keys.push((
        0x82,
        super::mock::PivKey {
            seed: ed_foreign,
            pin_policy: 3,
            touch_policy: 2,
        },
    ));
    card.log.clear();
    let occupied =
        super::enrol::occupied_slots(&mut card, ApduMode::Short, &seed, &recommended_plan(), &[])
            .unwrap();
    let ed_public = ed25519_dalek::SigningKey::from_bytes(&ed_foreign)
        .verifying_key()
        .to_bytes();
    let foreign_public = secp256k1::SecretKey::from_byte_array(foreign)
        .unwrap()
        .public_key(&Secp256k1::new())
        .serialize();
    assert_eq!(
        occupied,
        [
            super::enrol::Occupant {
                slot: CardSlot::OpenPgp(PgpKey::Aut),
                public: Some(HwPublicKey::Secp256k1(foreign_public)),
            },
            super::enrol::Occupant {
                slot: CardSlot::Piv(PivSlot::new(0x82).unwrap()),
                public: Some(HwPublicKey::Ed25519(ed_public)),
            },
        ]
    );
    assert_eq!(
        enrol(&mut card, ABOUT, &recommended_plan(), &[]).err(),
        Some(EnrolError::Card(CardError::ForeignKey))
    );
    assert!(!card.saw_write() && !pin_sent(&card));
    assert_eq!(card.pgp_keys[2], Some(foreign));
    let overwrite = EnrolAuth {
        overwrite: true,
        ..default_auth()
    };
    let enrolled = enrol_card(
        &mut card,
        ApduMode::Short,
        &seed,
        &recommended_plan(),
        &[],
        &overwrite,
    )
    .unwrap();
    assert_eq!(enrolled.record.slots.len(), 4);
    let occupied = |card: &mut MockCard| {
        super::enrol::occupied_slots(card, ApduMode::Short, &seed, &recommended_plan(), &[])
            .unwrap()
    };
    assert!(occupied(&mut card).is_empty());
    // Keys the plan moves to another slot stay on the card: not listed either.
    card.pgp_keys.swap(0, 2);
    assert!(occupied(&mut card).is_empty());
    enrol(&mut card, ABOUT, &recommended_plan(), &[]).unwrap();

    // A reset of an applet whose counters allow more than 15 tries (ykman `set-retries`) blocks
    // them all within the tries the card reports.
    card.pgp_retries = [20, 20];
    card.piv_retries = 20;
    card.piv_puk_retries = 20;
    let reset = ClearPlan {
        openpgp: Some(ClearMethod::Reset),
        piv: Some(ClearMethod::Reset),
    };
    let report = clear_card(&mut card, ApduMode::Short, &enrolled.record, reset, &auth).unwrap();
    assert_eq!((report.openpgp, report.piv), (Some(Ok(())), Some(Ok(()))));
    assert_eq!(card.pgp_keys, [None, None, None]);
    assert!(card.piv_keys.is_empty());
}

/// A card answering READ PUBLIC KEY of an empty slot with a status other than 6A88 (a YubiKey
/// 5.8.0, 2026-11-12): the key information `DE` decides, so the pre-import check and the
/// enrolment go on; without `DE` the status stays an error, now with its code in the text.
#[test]
fn empty_slot_answered_without_6a88_follows_the_key_information() {
    let seed = seed_of(ABOUT);
    for status in [0x6A80_u16, 0x6B00] {
        let mut card = MockCard::new(41_000_001);
        card.pgp_empty_sw = status;
        let occupied = super::enrol::occupied_slots(
            &mut card,
            ApduMode::Short,
            &seed,
            &[sig(evm(0)), aut(btc(0))],
            &[],
        )
        .unwrap();
        assert!(occupied.is_empty(), "{status:04X}");
        let mut card = MockCard::new(41_000_002);
        card.pgp_empty_sw = status;
        assert!(enrol(&mut card, ABOUT, &[sig(evm(0)), aut(btc(0))], &[]).is_ok());
    }
    let mut card = MockCard::new(41_000_003);
    card.pgp_empty_sw = 0x6B00;
    card.pgp_key_info = false;
    let error =
        super::enrol::occupied_slots(&mut card, ApduMode::Short, &seed, &[sig(evm(0))], &[])
            .unwrap_err();
    assert_eq!(error, EnrolError::Card(CardError::Status(0x6B00)));
    assert_eq!(
        CardError::Status(0x6B00).to_string(),
        "YubiKey 작업 중 오류가 발생했습니다 (SW 6B00)."
    );
    assert_eq!(CardError::Status(0x6B00).status_word(), Some(0x6B00));
}

/// Every `YubiKey` catalogue entry keeps its placeholders, has no Hangul in English and passes the
/// display-text rule (spec/14 §4).
#[test]
fn yubikey_catalogue_is_complete() {
    use crate::approval::{MAX_DISPLAY_VALUE_BYTES, is_valid_display_text};
    use crate::lang::{has_hangul, placeholders};
    for entry in super::text::ALL {
        let expected: Vec<usize> = (0..entry.args).collect();
        for template in [entry.ko, entry.en] {
            let mut found = placeholders(template);
            found.sort_unstable();
            found.dedup();
            assert_eq!(found, expected, "{}: {template}", entry.name);
        }
        assert!(!has_hangul(entry.en), "{}", entry.name);
        assert!(
            is_valid_display_text(entry.en, MAX_DISPLAY_VALUE_BYTES, true),
            "{}",
            entry.name
        );
    }
}

/// Korean texts stay those of `Display`; English card, plan, slot, role and scan texts have no
/// Hangul (spec/14).
#[test]
fn english_yubikey_texts_have_no_korean() {
    use super::TransportFault;
    use super::connect::ScanNote;
    use crate::lang::{Lang, has_hangul};
    let errors = [
        CardError::Transport(TransportFault::NoService),
        CardError::Transport(TransportFault::NoCard),
        CardError::Transport(TransportFault::Busy),
        CardError::Transport(TransportFault::Io),
        CardError::CardRemoved,
        CardError::AppletMissing,
        CardError::WrongPin { retries: 0 },
        CardError::WrongPin { retries: 1 },
        CardError::WrongPin { retries: 2 },
        CardError::PinBlocked,
        CardError::SecurityStatus,
        CardError::Conditions,
        CardError::WrongData,
        CardError::NotSupported,
        CardError::NotFound,
        CardError::Status(0x6B00),
        CardError::Malformed,
        CardError::TooLarge,
        CardError::ManagementKeyMismatch,
        CardError::ManagementKeyProtected,
        CardError::ManagementKeyUnknown,
        CardError::FirmwareTooOld,
        CardError::KdfEnabled,
        CardError::KeyMismatch,
        CardError::ForeignKey,
        CardError::WrongCard,
        CardError::BadSignature,
        CardError::PinFormat,
        CardError::Ed25519ImportRefused,
        CardError::AdminLastTry,
        CardError::MultipleCards,
        CardError::DefaultPin,
        CardError::NotBlocked,
        CardError::PukLastTry,
        CardError::Internal,
    ];
    for error in errors {
        assert_eq!(error.text_in(Lang::Ko), error.to_string());
        assert!(!has_hangul(&error.text_in(Lang::En)), "{error:?}");
    }
    assert_eq!(
        CardError::Status(0x6B00).text_in(Lang::En),
        "A YubiKey operation failed (SW 6B00)."
    );
    let retired = CardSlot::Piv(PivSlot::retired(0).unwrap());
    let plans = [
        PlanError::SlotCount,
        PlanError::DuplicateSlot(retired),
        PlanError::DuplicatePath(CardSlot::OpenPgp(PgpKey::Sig)),
        PlanError::WrongApplet(CardSlot::OpenPgp(PgpKey::Aut)),
        PlanError::UnsupportedRole(retired),
        PlanError::Policy(retired),
        PlanError::CardAlreadyEnrolled,
        PlanError::TooManyCards,
        PlanError::NotACopy(retired),
        PlanError::DifferentMnemonic,
    ];
    for error in plans {
        assert_eq!(error.text_in(Lang::Ko), error.to_string());
        assert!(!has_hangul(&error.text_in(Lang::En)), "{error:?}");
        let enrol = EnrolError::Plan(error);
        assert_eq!(enrol.text_in(Lang::Ko), enrol.to_string());
    }
    assert!(!has_hangul(&EnrolError::SerialMismatch.text_in(Lang::En)));
    assert_eq!(retired.label_in(Lang::En), "PIV 82 (retired 1)");
    let shared = KeyRole::Evm {
        index: AccountIndex::new(2).unwrap(),
        btc: Some(BtcUse {
            network: BtcNetwork::Mainnet,
            script: ScriptType::P2wpkh,
        }),
    };
    let unknown = btc(0).with_index(super::plan::UNKNOWN_PATH_FIRST).unwrap();
    for role in [evm(3), btc(0), sol(1), shared, unknown] {
        assert!(!has_hangul(&role.title_in(Lang::En)), "{role:?}");
        assert!(!has_hangul(&role.path_text_in(Lang::En)), "{role:?}");
    }
    assert_eq!(evm(3).title_in(Lang::En), "EVM account 3");
    assert_eq!(unknown.path_text_in(Lang::En), "Path unknown");
    for touch in [
        TouchPolicy::Never,
        TouchPolicy::Always,
        TouchPolicy::Cached,
        TouchPolicy::AlwaysFixed,
        TouchPolicy::CachedFixed,
    ] {
        assert!(!has_hangul(touch.label_in(Lang::En)));
    }
    let note = ScanNote {
        piv: true,
        reason: super::text::NOTE_APPLET_MISSING,
    };
    assert_eq!(note.text(Lang::Ko), "PIV(Solana 키): 애플릿이 없습니다");
    assert_eq!(note.text(Lang::En), "PIV (Solana keys): No applet");
}
