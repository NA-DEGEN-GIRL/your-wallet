//! spec/04 §2.6 (2026-11-15): the EVM and Solana account cards share one layout — title
//! `내 EVM 계정` / `내 Solana 계정`, drop-down items `label · source` — and a `YubiKey` account's
//! source names the cards holding its key.

use yw_core::bip32::path::AccountIndex;
use yw_core::btc::{BtcNetwork, ScriptType};
use yw_core::lang::Lang;
use yw_core::yubikey::Firmware;
use yw_core::yubikey::plan::{CardSlot, KeyRole, PgpKey, PinPolicy, PivSlot, TouchPolicy};
use yw_core::yubikey::record::{HwKeyRecord, HwPublicKey, RecordedSlot};
use yw_core::zec::ZecNetwork;

use super::{has_text, unlocked_app};
use crate::app::App;
use crate::meta::{Account, RawAccount, Tab};
use crate::ui::main_window::Item;
use crate::ui::screens_links::ids::{PICKER_EVM, PICKER_SOL};

const SERIAL_A: u32 = 7_700_021;
const SERIAL_B: u32 = 7_700_022;
const SERIAL_C: u32 = 7_700_023;
/// The `abandon …` vector's EVM account 1 (public test data).
const EVM_CARD: &str = "0x6fac4d18c912343bf86fa7049364dd4e424ab9c0";

fn slot(slot: CardSlot, role: KeyRole) -> RecordedSlot {
    let public = match role {
        KeyRole::Sol { .. } => HwPublicKey::Ed25519([3; 32]),
        _ => HwPublicKey::Secp256k1([2; 33]),
    };
    RecordedSlot {
        slot,
        role,
        touch: TouchPolicy::Always,
        pin: if matches!(slot, CardSlot::Piv(_)) {
            PinPolicy::Once
        } else {
            PinPolicy::NotApplicable
        },
        public,
        path_known: true,
    }
}

fn evm0() -> KeyRole {
    KeyRole::Evm {
        index: AccountIndex::ZERO,
        btc: None,
    }
}

fn sol0() -> KeyRole {
    KeyRole::Sol {
        index: AccountIndex::ZERO,
    }
}

fn piv() -> CardSlot {
    CardSlot::Piv(PivSlot::new(0x9A).unwrap())
}

/// The owner's two cards from one mnemonic: A holds EVM 0, Solana 0 and Bitcoin address 0, B
/// holds EVM 0, Solana 0 and Zcash address 0.
fn owner_cards() -> Vec<HwKeyRecord> {
    let record = |serial: u32, slots: Vec<RecordedSlot>| HwKeyRecord {
        serial,
        firmware: Firmware {
            major: 5,
            minor: 7,
            patch: 1,
        },
        fingerprint: [1, 2, 3, 4],
        slots,
    };
    vec![
        record(
            SERIAL_A,
            vec![
                slot(CardSlot::OpenPgp(PgpKey::Sig), evm0()),
                slot(
                    CardSlot::OpenPgp(PgpKey::Aut),
                    KeyRole::Btc {
                        network: BtcNetwork::Mainnet,
                        script: ScriptType::P2wpkh,
                        index: 0,
                    },
                ),
                slot(piv(), sol0()),
            ],
        ),
        record(
            SERIAL_B,
            vec![
                slot(CardSlot::OpenPgp(PgpKey::Sig), evm0()),
                slot(
                    CardSlot::OpenPgp(PgpKey::Aut),
                    KeyRole::Zec {
                        network: ZecNetwork::Mainnet,
                        index: 0,
                    },
                ),
                slot(piv(), sol0()),
            ],
        ),
    ]
}

/// A wallet of recovery words (`계정 1`, `Solana 1`) with the owner's two cards: one `YubiKey`
/// account per chain (the same key on both cards), named by the reconcile's new default.
fn owner_app(tag: &str) -> (App, std::path::PathBuf) {
    let (mut app, dir) = unlocked_app(tag, false);
    app.card.records = owner_cards();
    let meta = app.meta.as_mut().unwrap();
    meta.hw_accounts.evm = vec![Account {
        index: 0,
        label: "계정 2".to_owned(),
        address: EVM_CARD.to_owned(),
        hidden: false,
    }];
    meta.hw_accounts.sol = vec![Account {
        index: 0,
        label: "Solana 2".to_owned(),
        address: yw_core::sol::SolAddress::from_bytes([3; 32]).to_base58(),
        hidden: false,
    }];
    meta.set_card_name(SERIAL_A, Some("메인".to_owned()));
    meta.set_card_name(SERIAL_B, Some("백업".to_owned()));
    (app, dir)
}

/// The open drop-down's entries of the tab's card.
fn entries(app: &mut App, tab: Tab) -> Vec<String> {
    app.meta.as_mut().unwrap().prefs.tab = tab;
    let (picker, base) = match tab {
        Tab::Sol => (PICKER_SOL, crate::ui::screens_sol::ids::ACCOUNT_BASE),
        _ => (PICKER_EVM, crate::ui::screens::ids::ACCOUNT_BASE),
    };
    app.account_menu = Some(picker);
    let entries = super::controls(&app.items())
        .into_iter()
        .filter(|ctl| (base..base + 100).contains(&ctl.id))
        .map(|ctl| ctl.text)
        .collect();
    app.account_menu = None;
    entries
}

fn title(app: &App, title: &str) -> bool {
    app.items()
        .iter()
        .any(|item| matches!(item, Item::CardStart(Some(text)) if text == title))
}

/// The owner's case: card A (EVM 0, Solana 0, Bitcoin 0) and card B (EVM 0, Solana 0, Zcash 0)
/// from one mnemonic give one EVM item and one Solana item, each naming both cards; the words'
/// accounts then name their source too (a mixed list). An unnamed card shows `#serial`, a third
/// holder ` +1`; the hidden row says the same source; English sources.
#[test]
fn two_cards_of_one_mnemonic_show_one_account_naming_both() {
    let (mut app, dir) = owner_app("accounts-owner");
    assert!(title(&app, "내 EVM 계정"));
    assert_eq!(
        entries(&mut app, Tab::Evm),
        ["계정 1 · 복구 단어", "계정 2 · YubiKey: 메인·백업"]
    );
    app.meta.as_mut().unwrap().prefs.tab = Tab::Sol;
    assert!(title(&app, "내 Solana 계정"));
    assert_eq!(
        entries(&mut app, Tab::Sol),
        ["Solana 1 · 복구 단어", "Solana 2 · YubiKey: 메인·백업"]
    );
    // The closed drop-down names the selected account with its source.
    assert!(
        super::controls(&app.items())
            .iter()
            .any(|ctl| ctl.id == PICKER_SOL && ctl.text == "Solana 1 · 복구 단어")
    );
    // Card B without a name: its serial alone (the item stays short, no `(#serial)`).
    app.meta.as_mut().unwrap().set_card_name(SERIAL_B, None);
    assert_eq!(
        entries(&mut app, Tab::Evm)[1],
        format!("계정 2 · YubiKey: 메인·#{SERIAL_B}")
    );
    // A third card with the key: the first two and ` +1`.
    let mut third = owner_cards().remove(1);
    third.serial = SERIAL_C;
    app.card.records.push(third);
    assert_eq!(
        entries(&mut app, Tab::Sol)[1],
        format!("Solana 2 · YubiKey: 메인·#{SERIAL_B} +1")
    );
    app.card.records.pop();
    // Hidden, the account's row names the same cards.
    app.meta.as_mut().unwrap().hw_accounts.evm[0].hidden = true;
    app.hidden_open = true;
    app.meta.as_mut().unwrap().prefs.tab = Tab::Evm;
    assert!(has_text(
        &app.items(),
        &format!("계정 2 · YubiKey: 메인·#{SERIAL_B} · 숨김")
    ));
    app.meta.as_mut().unwrap().hw_accounts.evm[0].hidden = false;
    // English.
    app.settings.language = Lang::En;
    app.meta
        .as_mut()
        .unwrap()
        .set_card_name(SERIAL_B, Some("Backup".to_owned()));
    assert!(title(&app, "My EVM accounts"));
    assert_eq!(
        entries(&mut app, Tab::Evm),
        ["계정 1 · Recovery words", "계정 2 · YubiKey: 메인·Backup"]
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Every item of a list that mixes kinds names its source (words, imported key, `YubiKey`); a
/// list of one set of recovery words only names none, as before.
#[test]
fn mixed_lists_give_every_item_a_source() {
    let (mut app, dir) = unlocked_app("accounts-mixed", false);
    let meta = app.meta.as_mut().unwrap();
    meta.evm_accounts.push(Account {
        index: 1,
        label: "계정 2".to_owned(),
        address: "0x2222222222222222222222222222222222222222".to_owned(),
        hidden: false,
    });
    assert_eq!(entries(&mut app, Tab::Evm), ["계정 1", "계정 2"]);
    app.meta
        .as_mut()
        .unwrap()
        .evm_raw_accounts
        .push(RawAccount {
            record_id: [9; 16],
            label: "가져온 계정 1".to_owned(),
            address: "0x3333333333333333333333333333333333333333".to_owned(),
        });
    assert_eq!(
        entries(&mut app, Tab::Evm),
        [
            "계정 1 · 복구 단어",
            "계정 2 · 복구 단어",
            "가져온 계정 1 · 가져온 키"
        ]
    );
    // A YubiKey account whose card record is not loaded: `YubiKey` alone.
    app.meta.as_mut().unwrap().hw_accounts.evm.push(Account {
        index: 0,
        label: "계정 3".to_owned(),
        address: EVM_CARD.to_owned(),
        hidden: false,
    });
    let items = entries(&mut app, Tab::Evm);
    assert_eq!(items.len(), 4);
    assert!(items.iter().all(|item| item.contains(" · ")), "{items:?}");
    assert_eq!(items[3], "계정 3 · YubiKey");
    // Solana: the words' account alone has no source; with an imported key both have one.
    assert_eq!(entries(&mut app, Tab::Sol), ["Solana 1"]);
    app.meta
        .as_mut()
        .unwrap()
        .sol_raw_accounts
        .push(crate::meta::SolRawAccount {
            record_id: [8; 16],
            label: "가져온 Solana 1".to_owned(),
            address: yw_core::sol::SolAddress::from_bytes([4; 32]).to_base58(),
        });
    app.settings.language = Lang::En;
    assert_eq!(
        entries(&mut app, Tab::Sol),
        [
            "Solana 1 · Recovery words",
            "가져온 Solana 1 · Imported key"
        ]
    );
    let _ = std::fs::remove_dir_all(dir);
}
