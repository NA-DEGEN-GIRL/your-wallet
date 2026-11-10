//! spec/10 §15 at the App level, emulator cards only: "슬롯 구성 바꾸기" (with the Zcash role of
//! the wizard, the backup-card loop and a wrong card) and "`YubiKey` 비우기" (our slots, the applet
//! resets, the record dropped when no slot is left).

use yw_core::yubikey::mock::MockCard;
use yw_core::yubikey::plan::{CardSlot, KeyRole, PgpKey};

use super::{
    ABOUT, EvmAccountPref, Harness, Purpose, YkSeen, about_wallet, all_text, card_harness, ctl,
    finish_result, has_text, unique_ids, yk_pump,
};
use crate::app_yubikey::YkPurpose;
use crate::app_yubikey::manage::{CLEAR_WORD, ClearStep, Preset, ReslotStep, YkManage};
use crate::ui::screens_yubikey::ids as yk;
use crate::ui::screens_yubikey::ids::{PgpAction, pgp_id};

const ADMIN: &[u8] = b"12345678";
const BIP84_0: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";

/// The wizard's plan screen is open: `다음` → W05 (unless the words are held) → confirmation →
/// admin PIN → the inserted card.
fn wizard_import(h: &mut Harness, seen: &mut YkSeen, words: bool) {
    h.app.on_command(yk::PLAN_NEXT);
    if words {
        h.submit(Purpose::YubiKey(YkPurpose::Mnemonic), &[ABOUT.as_bytes()]);
    }
    yk_pump(h, seen);
    h.app.on_command(yk::SAME_ACK);
    h.app.on_command(yk::CONFIRM_NEXT);
    yk_pump(h, seen);
    h.app.on_command(yk::IMPORT);
    h.submit(Purpose::YubiKey(YkPurpose::AdminPin), &[ADMIN]);
    yk_pump(h, seen);
}

fn reslot_step(h: &Harness) -> Option<ReslotStep> {
    match h.app.card.manage.as_ref() {
        Some(YkManage::Reslot(flow)) => Some(flow.step),
        _ => None,
    }
}

fn record(h: &Harness, serial: u32) -> yw_core::yubikey::record::HwKeyRecord {
    h.app
        .card
        .records
        .iter()
        .find(|record| record.serial == serial)
        .cloned()
        .unwrap()
}

/// spec/10 §3.1 (Zcash role), §15.1: card A enrolled with SIG = EVM 0, AUT = Zcash mainnet 0
/// (the confirmation shows `m/44'/133'/0'/0/0` and its `t1…` address) and one Solana slot, card B
/// its backup copy. "슬롯 구성 바꾸기" of A to EVM + Bitcoin: the current map, the preset, the words
/// once (W05), every new path and address, the Zcash account A stops holding (B still holds it;
/// the import waits for the acknowledgement), a wrong card refused before any write, then A's
/// AUT holds BIP84 0 (read back), its PIV slot unchanged, the Bitcoin account appears. "백업
/// `YubiKey`에도 같은 구성 적용" repeats it on B without asking for the words; `완료` wipes them.
#[test]
#[expect(clippy::too_many_lines, reason = "one re-slot walk-through")]
fn yubikey_reslot_switches_chains_and_applies_it_to_the_backup() {
    let (mut h, cards) = card_harness("yk-reslot", 8_900_001);
    let mut seen = YkSeen::default();
    about_wallet(&mut h);
    h.app.on_command(yk::SECTION_YUBIKEY);
    h.pump();
    // Card A: SIG = EVM 0 (default), AUT = Zcash mainnet 0, one Solana account (default).
    h.app.on_command(yk::ENROL_START);
    h.app.on_command(pgp_id(
        PgpKey::Aut,
        PgpAction::Kind(crate::app_yubikey::PgpKind::Zec),
    ));
    h.app.yk_set_text(yk::AUT_INDEX_EDIT, "0".to_owned());
    h.app.on_command(yk::PLAN_NEXT);
    h.submit(Purpose::YubiKey(YkPurpose::Mnemonic), &[ABOUT.as_bytes()]);
    yk_pump(&mut h, &mut seen);
    let about_seed = yw_core::bip39::Mnemonic::parse(ABOUT)
        .unwrap()
        .to_seed(&yw_core::password::Bip39Passphrase::empty())
        .unwrap();
    let zec_role = KeyRole::Zec {
        network: yw_core::zec::ZecNetwork::Mainnet,
        index: 0,
    };
    let zec_line = yw_core::yubikey::enrol::preview_seed(
        about_seed.expose(),
        &[yw_core::yubikey::plan::PlannedSlot::recommended(
            CardSlot::OpenPgp(PgpKey::Aut),
            zec_role,
        )],
    )
    .unwrap()
    .remove(0);
    let zec_address = zec_line.addresses[0].clone();
    assert!(zec_address.starts_with("t1"), "{zec_address}");
    let shown = all_text(&h.app.items());
    assert!(shown.iter().any(|text| text == "m/44'/133'/0'/0/0"));
    assert!(shown.contains(&zec_address));
    h.app.on_command(yk::SAME_ACK);
    h.app.on_command(yk::CONFIRM_NEXT);
    yk_pump(&mut h, &mut seen);
    h.app.on_command(yk::IMPORT);
    h.submit(Purpose::YubiKey(YkPurpose::AdminPin), &[ADMIN]);
    yk_pump(&mut h, &mut seen);
    let before_a = record(&h, 8_900_001);
    assert_eq!(before_a.slots.len(), 3);
    assert_eq!(before_a.slots[1].role, zec_role);
    // Card B: the backup copy of A (the words are still held); A is set aside meanwhile.
    h.app.on_command(yk::ANOTHER);
    let card_a = {
        let mut inserted = cards.lock().unwrap();
        let card_a = inserted.remove(0);
        inserted.push(MockCard::new(8_900_002));
        card_a
    };
    wizard_import(&mut h, &mut seen, false);
    assert_eq!(h.app.card.records.len(), 2);
    finish_result(&mut h, yk::FINISH);
    yk_pump(&mut h, &mut seen);

    // "슬롯 구성 바꾸기" of A (row 0): the current map is shown; EVM + Bitcoin.
    cards.lock().unwrap()[0].log.clear();
    h.app.on_command(yk::RESLOT_BASE);
    assert_eq!(reslot_step(&h), Some(ReslotStep::Choose));
    let items = h.app.items();
    unique_ids(&items);
    assert!(all_text(&items).contains(&zec_address), "current map");
    assert!(has_text(
        &items,
        crate::app_yubikey::manage::T_YK_RESLOT_WORDS
    ));
    h.app.on_command(yk::preset_id(Preset::EvmBtc));
    h.app.on_command(yk::RESLOT_NEXT);
    h.submit(
        Purpose::YubiKey(YkPurpose::ReslotMnemonic),
        &[ABOUT.as_bytes()],
    );
    yk_pump(&mut h, &mut seen);
    assert_eq!(reslot_step(&h), Some(ReslotStep::Confirm));
    assert!(
        cards.lock().unwrap().iter().all(|card| card.log.is_empty()),
        "the preview talks to no card"
    );
    let items = h.app.items();
    unique_ids(&items);
    let shown = all_text(&items);
    for expected in ["m/44'/60'/0'/0/0", "m/84'/0'/0'/0/0", BIP84_0] {
        assert!(shown.iter().any(|text| text == expected), "{expected}");
    }
    // The "지워지는 계정" block (2026-11-10): the account, its address, what still signs.
    assert!(
        shown.iter().any(|text| text.starts_with("Zcash"))
            && shown.contains(&zec_address)
            && shown
                .iter()
                .any(|text| text.starts_with("#8900002에 남아 있음")),
        "the dropped Zcash account and its other holder: {shown:?}"
    );
    // The import waits for the acknowledgement of the removed chain.
    assert!(!ctl(&items, yk::RESLOT_IMPORT).unwrap().enabled);
    h.app.on_command(yk::RESLOT_REMOVED_ACK);
    assert!(ctl(&h.app.items(), yk::RESLOT_IMPORT).unwrap().enabled);
    // Only B inserted: refused as another card, nothing written.
    h.app.on_command(yk::RESLOT_IMPORT);
    h.submit(Purpose::YubiKey(YkPurpose::ReslotAdminPin), &[ADMIN]);
    yk_pump(&mut h, &mut seen);
    assert_eq!(reslot_step(&h), Some(ReslotStep::Result));
    let Some(YkManage::Reslot(flow)) = h.app.card.manage.as_ref() else {
        unreachable!("re-slot flow")
    };
    assert!(flow.failure.is_some());
    assert!(!cards.lock().unwrap()[0].saw_write());
    assert_eq!(record(&h, 8_900_001), before_a);
    // A inserted: `다시 시도` → admin PIN → A re-slotted and read back.
    let card_b = core::mem::replace(&mut cards.lock().unwrap()[0], card_a);
    h.app.on_command(yk::RESLOT_RETRY);
    h.submit(Purpose::YubiKey(YkPurpose::ReslotAdminPin), &[ADMIN]);
    yk_pump(&mut h, &mut seen);
    let after_a = record(&h, 8_900_001);
    assert_eq!(after_a.slots.len(), 3);
    assert_eq!(after_a.slots[0], before_a.slots[0], "SIG kept (EVM 0)");
    assert!(matches!(
        after_a.slots[1].role,
        KeyRole::Btc { index: 0, .. }
    ));
    assert_eq!(after_a.slots[2], before_a.slots[2], "PIV unchanged");
    let bip84 = yw_core::yubikey::enrol::preview_seed(
        about_seed.expose(),
        &[yw_core::yubikey::plan::PlannedSlot::recommended(
            CardSlot::OpenPgp(PgpKey::Aut),
            after_a.slots[1].role,
        )],
    )
    .unwrap()
    .remove(0);
    assert_eq!(after_a.slots[1].public, bip84.public);
    assert_eq!(bip84.addresses, [BIP84_0]);
    // The card answers with that key (read-only check of every recorded slot).
    let checked = crate::yubikey::check_record(
        &mut crate::yubikey::MockSource {
            cards: std::sync::Arc::clone(&cards),
        },
        &after_a,
    )
    .unwrap();
    assert!(checked.iter().all(Result::is_ok), "{checked:?}");
    assert!(
        h.app
            .btc_dapp_rows()
            .iter()
            .any(|row| row.entry.address == BIP84_0)
    );
    assert!(
        h.app
            .account_rows()
            .iter()
            .any(|(pref, ..)| *pref == EvmAccountPref::Hardware(0))
    );
    // "백업 YubiKey에도 같은 구성 적용": B (row 1), the words still held (no W05).
    let items = h.app.items();
    unique_ids(&items);
    let backup = yk::RESLOT_BACKUP_BASE + 1;
    assert!(ctl(&items, backup).is_some());
    let _card_a = core::mem::replace(&mut cards.lock().unwrap()[0], card_b);
    h.app.on_command(backup);
    yk_pump(&mut h, &mut seen);
    assert_eq!(reslot_step(&h), Some(ReslotStep::Confirm));
    h.app.on_command(yk::RESLOT_REMOVED_ACK);
    h.app.on_command(yk::RESLOT_IMPORT);
    h.submit(Purpose::YubiKey(YkPurpose::ReslotAdminPin), &[ADMIN]);
    yk_pump(&mut h, &mut seen);
    let after_b = record(&h, 8_900_002);
    assert_eq!(after_b.slots[1], after_a.slots[1], "same key on the backup");
    assert!(ctl(&h.app.items(), yk::RESLOT_BACKUP_BASE + 1).is_none());
    // `완료`: the flow ends and the key worker forgets the words.
    finish_result(&mut h, yk::MANAGE_DONE);
    yk_pump(&mut h, &mut seen);
    assert!(h.app.card.manage.is_none());
    let outcome = h
        .worker
        .handle(crate::events::KeyJob::YubiKey(
            crate::workers::key::yubikey::YkJob::Preview {
                mnemonic: None,
                slots: Vec::new(),
            },
        ))
        .pop();
    assert!(matches!(
        outcome,
        Some(crate::events::KeyOutcome::YubiKey(
            crate::workers::key::yubikey::YkOutcome::Preview(Err(_))
        ))
    ));
    let items = h.app.items();
    assert!(has_text(
        &items,
        "Bitcoin 네이티브 세그윗(P2WPKH) 주소 0 (m/84'/0'/0'/0/0) — #8900001 AUT, #8900002 AUT(백업)"
    ));
}

fn clear_step(h: &Harness) -> Option<ClearStep> {
    match h.app.card.manage.as_ref() {
        Some(YkManage::Clear(flow)) => Some(flow.step),
        _ => None,
    }
}

/// spec/10 §15.2–§15.3: "`YubiKey` 비우기" of a card with SIG = EVM 0, AUT = BIP84 0 and one
/// Solana slot. Both applets, our slots only: the typed word is required, the admin PIN and the
/// PIV PIN are asked, the emulator's SIG/AUT keys are gone (attributes back to RSA 2048) and its
/// PIV slot deleted (`F6`), no applet reset was sent, and the record with no slot left leaves the
/// list (the accounts go). Enrolled again with changed PINs: the PIV reset (PIN and PUK blocked,
/// `FB`) leaves `OpenPGP` alone and keeps the record with its `OpenPGP` slots; the `OpenPGP` reset
/// (`E6`, `44`) restores the factory PINs and drops the record.
#[test]
#[expect(clippy::too_many_lines, reason = "one clear walk-through")]
fn yubikey_clear_our_slots_and_applet_resets() {
    let (mut h, cards) = card_harness("yk-clear", 8_900_011);
    let mut seen = YkSeen::default();
    about_wallet(&mut h);
    h.app.on_command(yk::SECTION_YUBIKEY);
    h.pump();
    h.app.on_command(yk::ENROL_START);
    wizard_import(&mut h, &mut seen, true);
    finish_result(&mut h, yk::FINISH);
    yk_pump(&mut h, &mut seen);
    assert_eq!(record(&h, 8_900_011).slots.len(), 3);
    // Both applets, our slots only.
    h.app.on_command(yk::CLEAR_BASE);
    assert_eq!(clear_step(&h), Some(ClearStep::Choose));
    h.app.on_command(yk::CLEAR_PGP_TOGGLE);
    h.app.on_command(yk::CLEAR_PIV_TOGGLE);
    let items = h.app.items();
    unique_ids(&items);
    let shown = all_text(&items);
    assert!(
        shown.iter().any(|text| text == BIP84_0),
        "the account to lose: {shown:?}"
    );
    assert!(has_text(
        &items,
        crate::app_yubikey::manage::T_YK_CLEAR_FUNDS
    ));
    // The word must be typed exactly.
    h.app
        .yk_manage_set_text(yk::CLEAR_CONFIRM_EDIT, "비움".to_owned());
    h.app.on_command(yk::CLEAR_RUN);
    assert_eq!(clear_step(&h), Some(ClearStep::Choose));
    assert!(h.app.key_queue.is_empty());
    h.app
        .yk_manage_set_text(yk::CLEAR_CONFIRM_EDIT, CLEAR_WORD.to_owned());
    cards.lock().unwrap()[0].log.clear();
    h.app.on_command(yk::CLEAR_RUN);
    h.submit(Purpose::YubiKey(YkPurpose::ClearAdminPin), &[ADMIN]);
    h.submit(Purpose::YubiKey(YkPurpose::ClearPivPin), &[b"123456"]);
    yk_pump(&mut h, &mut seen);
    assert_eq!(clear_step(&h), Some(ClearStep::Result));
    {
        let card = &cards.lock().unwrap()[0];
        assert_eq!(card.pgp_keys, [None, None, None]);
        assert_eq!(
            card.pgp_attributes[0],
            yw_core::yubikey::openpgp::RSA2048_ATTRIBUTES
        );
        assert!(card.piv_keys.is_empty());
        assert!(card.log.iter().any(|header| header[1] == 0xF6));
        assert!(
            !card
                .log
                .iter()
                .any(|header| matches!(header[1], 0xE6 | 0x44 | 0xFB)),
            "no applet reset"
        );
        assert_eq!(card.pw3, ADMIN, "PINs kept");
    }
    assert!(h.app.card.records.is_empty(), "no slot left: record gone");
    assert!(
        !h.app
            .account_rows()
            .iter()
            .any(|(pref, ..)| matches!(pref, EvmAccountPref::Hardware(_)))
    );
    finish_result(&mut h, yk::MANAGE_DONE);
    yk_pump(&mut h, &mut seen);
    assert!(h.app.card.manage.is_none());

    // Enrol again, then change the card's PINs (as a user would; "PIN 설정" clears the
    // factory-PIN note).
    h.app.on_command(yk::ENROL_START);
    wizard_import(&mut h, &mut seen, true);
    finish_result(&mut h, yk::FINISH);
    yk_pump(&mut h, &mut seen);
    assert_eq!(record(&h, 8_900_011).slots.len(), 3);
    {
        let card = &mut cards.lock().unwrap()[0];
        card.piv_pin = b"24682468".to_vec();
        card.piv_puk = b"13571357".to_vec();
        card.pw1 = b"24682468".to_vec();
        card.pw3 = b"13571357".to_vec();
        card.log.clear();
    }
    h.app.meta.as_mut().unwrap().hw_accounts.defaults.clear();
    h.app.save_meta();
    yk_pump(&mut h, &mut seen);
    // PIV reset only: no PIN asked.
    h.app.on_command(yk::CLEAR_BASE);
    h.app.on_command(yk::CLEAR_PIV_TOGGLE);
    h.app.on_command(yk::CLEAR_PIV_RESET);
    h.app
        .yk_manage_set_text(yk::CLEAR_CONFIRM_EDIT, CLEAR_WORD.to_owned());
    h.app.on_command(yk::CLEAR_RUN);
    yk_pump(&mut h, &mut seen);
    assert_eq!(clear_step(&h), Some(ClearStep::Result));
    {
        let card = &cards.lock().unwrap()[0];
        assert!(card.log.iter().any(|header| header[1] == 0xFB));
        assert!(card.piv_keys.is_empty());
        assert_eq!(card.piv_pin, yw_core::yubikey::piv::DEFAULT_PIN);
        assert_eq!(card.piv_puk, yw_core::yubikey::piv::DEFAULT_PUK);
        assert_eq!(card.mgmt_key, yw_core::yubikey::piv::DEFAULT_MANAGEMENT_KEY);
        assert!(card.pgp_keys[0].is_some(), "OpenPGP untouched");
        assert_eq!(card.pw3, b"13571357");
    }
    let left = record(&h, 8_900_011);
    assert_eq!(left.slots.len(), 2);
    assert!(
        left.slots
            .iter()
            .all(|slot| matches!(slot.slot, CardSlot::OpenPgp(_)))
    );
    // The reset PIV applet keeps no wallet key (its factory PINs protect nothing of the
    // record) and OpenPGP keeps its PINs: the card still signs (spec/10 §15.4).
    assert!(
        !h.app
            .meta
            .as_ref()
            .unwrap()
            .hw_accounts
            .defaults
            .contains(&8_900_011),
        "no factory-PIN flag for an applet without wallet keys"
    );
    finish_result(&mut h, yk::MANAGE_DONE);
    yk_pump(&mut h, &mut seen);
    // OpenPGP reset: the factory PINs, no key, the record gone.
    h.app.on_command(yk::CLEAR_BASE);
    let items = h.app.items();
    assert!(
        ctl(&items, yk::CLEAR_PIV_TOGGLE).is_none(),
        "no PIV slot left"
    );
    h.app.on_command(yk::CLEAR_PGP_TOGGLE);
    h.app.on_command(yk::CLEAR_PGP_RESET);
    h.app
        .yk_manage_set_text(yk::CLEAR_CONFIRM_EDIT, CLEAR_WORD.to_owned());
    h.app.on_command(yk::CLEAR_RUN);
    yk_pump(&mut h, &mut seen);
    {
        let card = &cards.lock().unwrap()[0];
        assert!(card.log.iter().any(|header| header[1] == 0xE6));
        assert!(card.log.iter().any(|header| header[1] == 0x44));
        assert_eq!(card.pgp_keys, [None, None, None]);
        assert_eq!(card.pw1, yw_core::yubikey::openpgp::DEFAULT_PW1);
        assert_eq!(card.pw3, yw_core::yubikey::openpgp::DEFAULT_PW3);
        assert_eq!(card.pgp_retries, [3, 3]);
    }
    assert!(h.app.card.records.is_empty());
}
