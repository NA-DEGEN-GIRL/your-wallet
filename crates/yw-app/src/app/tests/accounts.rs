//! spec/04 §2.6 (2026-11-15): the EVM, Solana, Bitcoin and Zcash account cards share one
//! layout — title `내 EVM 계정` / `내 Solana 계정` / `내 Bitcoin 계정` / `내 Zcash 계정`,
//! drop-down items `label · source` (Zcash: its key sources) — and a `YubiKey` account's source
//! names the cards holding its key.

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
pub(super) fn owner_cards() -> Vec<HwKeyRecord> {
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
        Tab::Btc => (
            crate::ui::screens_links::ids::PICKER_BTC,
            crate::ui::screens_btc::ids::ACCOUNT_BASE,
        ),
        _ => (PICKER_EVM, crate::ui::screens::ids::ACCOUNT_BASE),
    };
    app.account_menu = crate::ui::cmd_table::press_of(picker, &app.controls);
    assert!(app.account_menu.is_some());
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

/// The generator point (public test data): a valid compressed key for the Bitcoin accounts.
const G: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/// The owner's wallet with Bitcoin on (mainnet): the words' BIP84 account 0, card A's Bitcoin
/// address key 0, an account on EVM account 1's key and an imported key. Returns card A's
/// account identity.
fn owner_btc_app(tag: &str) -> (App, std::path::PathBuf, yw_core::btc::BtcAccountId) {
    use yw_core::btc::account::HwBtcKey;
    use yw_core::btc::{BtcAccountKey, BtcMeta, BtcPubKey};
    let (mut app, dir) = owner_app(tag);
    app.settings.bitcoin.enabled = true;
    app.settings.bitcoin.network = crate::network::BtcNet::Mainnet;
    // A usable tab (an endpoint, the journal read): the selected card shows its address.
    app.apikeys.set_rpc(
        crate::network::NetworkId::Bitcoin(crate::network::BtcNet::Mainnet),
        &yw_platform::http::HttpsUrl::parse("https://btc.example.test/").unwrap(),
    );
    app.evm.journal = Some(crate::events::JournalView {
        room: true,
        sol_room: true,
        btc_room: true,
        ..crate::events::JournalView::default()
    });
    let pubkey = yw_core::hex::decode_array::<33>(G).unwrap();
    let node = yw_core::bip32::AccountXpub {
        pubkey,
        chain_code: [7; 32],
    };
    let card = BtcAccountKey::hardware(HwBtcKey::Address(0), ScriptType::P2wpkh, pubkey).unwrap();
    let meta = app.meta.as_mut().unwrap();
    meta.prefs.tab = Tab::Btc;
    meta.btc = Some(Box::new(BtcMeta::new(BtcNetwork::Mainnet, node)));
    for key in [
        card,
        BtcAccountKey::evm_shared(1, ScriptType::P2tr, pubkey).unwrap(),
        BtcAccountKey::single([5; 16], ScriptType::P2pkh, BtcPubKey::Compressed(pubkey)).unwrap(),
    ] {
        meta.btc_accounts
            .upsert(BtcMeta::with_key(BtcNetwork::Mainnet, key))
            .unwrap();
    }
    (app, dir, card.id())
}

/// The key jobs queued since the last call.
fn key_jobs(app: &App) -> Vec<crate::events::KeyJob> {
    std::iter::from_fn(|| {
        (!app.key_queue.is_empty())
            .then(|| app.key_queue.pop())
            .flatten()
    })
    .map(|(_, job)| job)
    .collect()
}

/// The receive address 0 of the selected Bitcoin account.
fn selected_btc_address(app: &App) -> String {
    app.btc_ctx()
        .btc_meta()
        .unwrap()
        .address(yw_core::bip32::path::BtcChain::Receive, 0)
        .unwrap()
        .as_str()
        .to_owned()
}

/// spec/04 §2.6, spec/08 §3.6 (2026-11-15): the Bitcoin card `내 Bitcoin 계정` uses the shared
/// layout — items `label · source` with the default names `Bitcoin N`, card A's address key 0 as
/// `· YubiKey: 메인` (only card A holds it), the EVM-key account as `· EVM 계정 1 키`, the
/// imported key as `· 가져온 키` — and no address, type or balance in the item: the selected
/// account's whole address and type are the card above. English sources.
#[test]
fn bitcoin_card_names_sources_and_card_a() {
    use crate::ui::screens_btc::ids as btc_ids;
    let (mut app, dir, card) = owner_btc_app("accounts-btc");
    assert!(title(&app, "내 Bitcoin 계정"));
    assert_eq!(
        entries(&mut app, Tab::Btc),
        [
            "Bitcoin 1 · 복구 단어",
            "Bitcoin 2 · YubiKey: 메인",
            "Bitcoin 3 · EVM 계정 1 키",
            "Bitcoin 4 · 가져온 키"
        ]
    );
    // The default account: its name on the drop-down button and the card above, the type and
    // the whole address there; `이름 바꾸기` without `숨기기`.
    let items = app.items();
    let ctls = super::controls(&items);
    assert!(ctls.iter().any(|ctl| {
        ctl.id == crate::ui::screens_links::ids::PICKER_BTC && ctl.text == "Bitcoin 1 · 복구 단어"
    }));
    assert!(
        items
            .iter()
            .any(|item| matches!(item, Item::Subtitle(text) if text == "Bitcoin 1"))
    );
    assert!(has_text(&items, "네이티브 세그윗 (bc1q…)"));
    assert!(ctls.iter().any(|ctl| ctl.id == btc_ids::RENAME));
    assert!(!ctls.iter().any(|ctl| ctl.id == btc_ids::HIDE));
    // Card A's account selected: its name on the card, `숨기기` offered.
    app.meta.as_mut().unwrap().btc_accounts.selected = Some(card);
    let items = app.items();
    assert!(
        items
            .iter()
            .any(|item| matches!(item, Item::Subtitle(text) if text == "Bitcoin 2"))
    );
    assert!(
        super::controls(&items)
            .iter()
            .any(|ctl| ctl.id == btc_ids::HIDE)
    );
    // Its whole address is the card's copy line (never in the drop-down item).
    let address = selected_btc_address(&app);
    assert_eq!(
        super::controls(&items)
            .iter()
            .find(|ctl| ctl.id == btc_ids::CARD_COPY)
            .and_then(crate::ui::main_window::Ctl::value_text),
        Some(address.clone())
    );
    assert!(
        entries(&mut app, Tab::Btc)
            .iter()
            .all(|entry| !entry.contains(&address))
    );
    // The imported key: `개인키 보기`·`삭제`, no `숨기기`.
    let imported = yw_core::btc::BtcAccountId::Imported { id: [5; 16] };
    app.meta.as_mut().unwrap().btc_accounts.selected = Some(imported);
    let ids_now: Vec<u16> = super::controls(&app.items())
        .iter()
        .map(|ctl| ctl.id)
        .collect();
    assert!(!ids_now.contains(&btc_ids::HIDE));
    assert!(ids_now.contains(&crate::ui::screens_keys::ids::BTC_REVEAL));
    assert!(ids_now.contains(&crate::ui::screens_keys::ids::BTC_REMOVE));
    // English.
    app.settings.language = Lang::En;
    assert!(title(&app, "My Bitcoin accounts"));
    assert_eq!(
        entries(&mut app, Tab::Btc),
        [
            "Bitcoin 1 · Recovery words",
            "Bitcoin 2 · YubiKey: 메인",
            "Bitcoin 3 · EVM account 1 key",
            "Bitcoin 4 · Imported key"
        ]
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// spec/04 §2.6, spec/08 §12.3d (2026-11-15): `이름 바꾸기` stores the name in
/// `btc_account_view` (a bad label is refused), `숨기기` takes the account out of the drop-down
/// and the dApp rows, selects the default account through the key worker and lists it under
/// `숨긴 계정`, and `다시 보이기` brings it back.
#[test]
fn bitcoin_rename_hide_and_unhide() {
    use crate::ui::screens_btc::ids as btc_ids;
    use crate::workers::journal::btc::BtcMetaOp;
    let (mut app, dir, card) = owner_btc_app("accounts-btc-hide");
    app.meta.as_mut().unwrap().btc_accounts.selected = Some(card);
    let network = BtcNetwork::Mainnet;
    // Rename: the field opens on the selected account; a bad label is refused.
    assert!(app.on_btc_command(btc_ids::RENAME));
    assert_eq!(app.btc.rename, Some(card));
    assert!(
        super::controls(&app.items())
            .iter()
            .any(|ctl| ctl.id == btc_ids::RENAME_EDIT && ctl.text == "Bitcoin 2")
    );
    app.btc_save_rename(" ");
    assert_eq!(app.btc.rename, Some(card));
    app.btc_save_rename(" 카드 A 계정 ");
    assert_eq!(app.btc.rename, None);
    assert_eq!(
        app.meta
            .as_ref()
            .unwrap()
            .btc_view_of(network, card)
            .and_then(|view| view.label.as_deref()),
        Some("카드 A 계정")
    );
    assert_eq!(
        entries(&mut app, Tab::Btc)[1],
        "카드 A 계정 · YubiKey: 메인"
    );
    let card_address = selected_btc_address(&app);
    assert!(
        app.btc_dapp_rows()
            .iter()
            .any(|row| row.entry.address == card_address)
    );
    let _ = key_jobs(&app);
    // Hide: gone from the drop-down and the dApp rows, the default account selected.
    assert!(app.on_btc_command(btc_ids::HIDE));
    assert!(app.meta.as_ref().unwrap().btc_hidden(network, card));
    assert_eq!(
        entries(&mut app, Tab::Btc),
        [
            "Bitcoin 1 · 복구 단어",
            "Bitcoin 3 · EVM 계정 1 키",
            "Bitcoin 4 · 가져온 키"
        ]
    );
    assert!(
        !app.btc_dapp_rows()
            .iter()
            .any(|row| row.entry.address == card_address)
    );
    let selects: Vec<_> = key_jobs(&app)
        .into_iter()
        .filter_map(|job| match job {
            crate::events::KeyJob::BtcMeta {
                op: BtcMetaOp::Select { network, account },
            } => Some((network, account)),
            _ => None,
        })
        .collect();
    assert_eq!(selects, [(network, yw_core::btc::BtcAccountId::PRIMARY)]);
    assert!(has_text(
        &app.items(),
        &crate::app_hidden::hidden_note(Lang::Ko, "카드 A 계정")
    ));
    // The hidden list names it with its cards and its whole address; `다시 보이기` brings it
    // back.
    app.hidden_open = true;
    let items = app.items();
    assert!(has_text(&items, "카드 A 계정 · YubiKey: 메인 · 숨김"));
    let grouped = yw_engine::text::grouped(&card_address);
    assert!(
        items
            .iter()
            .any(|item| matches!(item, Item::Mono(text) if *text == grouped))
    );
    assert!(app.on_hidden_command(crate::app_hidden::ids::BTC_ROW_BASE));
    assert!(!app.meta.as_ref().unwrap().btc_hidden(network, card));
    assert_eq!(entries(&mut app, Tab::Btc).len(), 4);
    // Read back: the name stays, nothing hidden.
    let text = app.meta.as_ref().unwrap().to_json();
    let reread = crate::meta::parse(&text).unwrap().meta;
    assert_eq!(reread.btc_view, app.meta.as_ref().unwrap().btc_view);
    let _ = std::fs::remove_dir_all(dir);
}

/// The owner's wallet with Zcash on (mainnet): the account on the standard path, a second set of
/// recovery words, card B's Zcash address key 0 and an imported key (the generator point's
/// address, public test data). Returns the imported key's address.
fn owner_zec_app(tag: &str) -> (App, std::path::PathBuf, String) {
    use yw_core::vault::{MnemonicInfo, RecordId};
    use yw_core::zec::{ZecAccount, ZecKeySource};
    let (mut app, dir) = owner_app(tag);
    app.settings.zcash.enabled = true;
    app.settings.zcash.network = ZecNetwork::Mainnet;
    let info = |id: RecordId, primary: bool| MnemonicInfo {
        id,
        created_unix: 0,
        words: 24,
        passphrase_used: false,
        backup_confirmed: true,
        primary,
    };
    app.mn.infos = vec![
        info(RecordId::from_bytes([1; 16]), true),
        info(RecordId::from_bytes([4; 16]), false),
    ];
    let pubkey = yw_core::hex::decode_array::<33>(G).unwrap();
    let imported = ZecAccount {
        network: ZecNetwork::Mainnet,
        source: ZecKeySource::Imported,
        pubkey,
    };
    let address = imported.address();
    app.keys.zec_keys.push((
        RecordId::from_bytes([6; 16]),
        yw_core::keyimport::ZecKeyInfo {
            network: ZecNetwork::Mainnet,
            pubkey,
            address: address.clone(),
        },
    ));
    let meta = app.meta.as_mut().unwrap();
    meta.prefs.tab = Tab::Zec;
    meta.zcash.set(ZecAccount {
        network: ZecNetwork::Mainnet,
        source: ZecKeySource::DEFAULT,
        pubkey,
    });
    (app, dir, address)
}

/// The open Zcash drop-down's entries: `(id, text, enabled)`; empty while it cannot open.
fn zec_entries(app: &mut App) -> Vec<(u16, String, bool)> {
    app.account_menu = Some(yw_engine::cmd::Press::Links(
        yw_engine::cmd::LinksPress::PickerZec,
    ));
    let entries = app
        .items()
        .into_iter()
        .filter_map(|item| match item {
            Item::Menu(ctls) => Some(ctls),
            _ => None,
        })
        .flatten()
        .map(|ctl| (ctl.id, ctl.text, ctl.enabled))
        .collect();
    app.account_menu = None;
    entries
}

fn zec_texts(app: &mut App) -> Vec<String> {
    zec_entries(app)
        .into_iter()
        .map(|(_, text, _)| text)
        .collect()
}

/// The Zcash public-key jobs queued since the last call (their sources).
fn zec_key_sources(app: &App) -> Vec<yw_core::zec::ZecKeySource> {
    key_jobs(app)
        .into_iter()
        .filter_map(|job| match job {
            crate::events::KeyJob::Zec(job) => match *job {
                crate::workers::journal::zec::ZecKeyJob::PublicKey { source, .. } => Some(source),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// spec/12 §11, spec/04 §2.6 (2026-11-15): the Zcash card `내 Zcash 계정` lists every key source
/// of the network as `label · source` — the standard path (`권장, 기본값`) of each set of
/// recovery words, the EVM key, card B's Zcash key as `· YubiKey: 백업` and the imported key —
/// with the account's source selected; the old `키 출처` card and `이 키 출처 사용` are gone, and
/// there is no `이름 바꾸기` / `숨기기` (one account per network). English sources.
#[test]
fn zcash_card_lists_every_key_source_and_card_b() {
    use crate::ui::screens_zec::ids as zec;
    let (mut app, dir, address) = owner_zec_app("accounts-zec");
    assert!(title(&app, "내 Zcash 계정"));
    assert!(!title(&app, "키 출처"));
    let mn = crate::ui::screens_mnemonics::ids::ZEC_PICK_BASE;
    assert_eq!(
        zec_entries(&mut app),
        [
            (
                zec::SOURCE_STANDARD,
                "Zcash 표준 경로 (권장, 기본값) · 복구 단어 1".to_owned(),
                true
            ),
            (mn + 1, "Zcash 표준 경로 · 복구 단어 2".to_owned(), true),
            (
                zec::SOURCE_EVM_BASE,
                "EVM 경로 (비표준) · EVM 계정 0 키".to_owned(),
                true
            ),
            (
                zec::HW_BASE,
                "Zcash 표준 경로 · YubiKey: 백업".to_owned(),
                true
            ),
            (zec::IMPORTED_BASE, format!("{address} · 가져온 키"), true),
        ]
    );
    let items = app.items();
    let ctls = super::controls(&items);
    assert!(ctls.iter().any(|ctl| {
        ctl.id == crate::ui::screens_links::ids::PICKER_ZEC
            && ctl.text == "Zcash 표준 경로 (권장, 기본값) · 복구 단어 1"
            && ctl.enabled
    }));
    for gone in [zec::SOURCE_APPLY, zec::SOURCE_CANCEL] {
        assert!(!ctls.iter().any(|ctl| ctl.id == gone), "{gone}");
    }
    assert!(!has_text(&items, "이 키 출처 사용"));
    // Kept: `개인키 가져오기` with its hint, the recovery-words link.
    assert!(ctls.iter().any(|ctl| ctl.id == zec::IMPORT));
    assert!(has_text(
        &items,
        crate::ui::screens_zec::text::IMPORT_HELP.ko
    ));
    assert!(
        ctls.iter()
            .any(|ctl| ctl.id == crate::ui::screens_mnemonics::ids::MAIN_LINK)
    );
    // Card B unnamed: its serial.
    app.meta.as_mut().unwrap().set_card_name(SERIAL_B, None);
    assert_eq!(
        zec_texts(&mut app)[3],
        format!("Zcash 표준 경로 · YubiKey: #{SERIAL_B}")
    );
    app.meta
        .as_mut()
        .unwrap()
        .set_card_name(SERIAL_B, Some("Backup".to_owned()));
    app.settings.language = Lang::En;
    assert!(title(&app, "My Zcash accounts"));
    assert_eq!(
        zec_texts(&mut app),
        [
            "Zcash standard path (recommended, default) · Recovery words 1".to_owned(),
            "Zcash standard path · Recovery words 2".to_owned(),
            "EVM path (non-standard) · EVM account 0 key".to_owned(),
            "Zcash standard path · YubiKey: Backup".to_owned(),
            format!("{address} · Imported key"),
        ]
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Picking an item applies its source (2026-11-15; a radio and `이 키 출처 사용` before): card B's
/// key becomes the account and the balance card names it (`YubiKey: 백업`), the standard path and
/// an added set of words ask the key worker, the imported key becomes the account, and the item
/// in use changes nothing.
#[test]
fn zcash_pick_applies_the_source() {
    use crate::ui::screens_zec::ids as zec;
    use yw_core::zec::ZecKeySource;
    let (mut app, dir, _) = owner_zec_app("accounts-zec-pick");
    let _ = key_jobs(&app);
    app.on_command(zec::HW_BASE);
    let account = app.zec_account().unwrap();
    assert_eq!(account.source, ZecKeySource::Hardware { index: 0 });
    assert_eq!(account.pubkey, [2; 33]);
    let items = app.items();
    assert!(has_text(
        &items,
        "키 출처: Zcash 표준 경로 · YubiKey: 백업 · m/44'/133'/0'/0/0"
    ));
    assert!(super::controls(&items).iter().any(|ctl| {
        ctl.id == crate::ui::screens_links::ids::PICKER_ZEC
            && ctl.text == "Zcash 표준 경로 · YubiKey: 백업"
    }));
    let _ = key_jobs(&app);
    // The item in use: nothing.
    app.on_command(zec::HW_BASE);
    assert!(zec_key_sources(&app).is_empty());
    // The standard path and the added words: the key worker derives the key.
    app.on_command(zec::SOURCE_STANDARD);
    assert_eq!(zec_key_sources(&app), [ZecKeySource::DEFAULT]);
    app.on_command(crate::ui::screens_mnemonics::ids::ZEC_PICK_BASE + 1);
    assert_eq!(
        zec_key_sources(&app),
        [ZecKeySource::Mnemonic {
            mnemonic: yw_core::vault::RecordId::from_bytes([4; 16]),
            account: 0,
            index: 0,
        }]
    );
    // The imported key: the account at once, with `개인키 보기`·`삭제`.
    app.on_command(zec::IMPORTED_BASE);
    assert_eq!(app.zec_account().unwrap().source, ZecKeySource::Imported);
    let ctls = super::controls(&app.items());
    assert!(ctls.iter().any(|ctl| ctl.id == zec::REVEAL));
    assert!(ctls.iter().any(|ctl| ctl.id == zec::REMOVE));
    let _ = std::fs::remove_dir_all(dir);
}

/// The EVM key keeps its warning and confirmation (T-ZEC-EVM-SHARED): picking it changes nothing
/// until `정말 EVM 키 사용`; `취소` drops it.
#[test]
fn zcash_evm_key_still_needs_the_confirmation() {
    use crate::ui::screens_zec::ids as zec;
    use yw_core::zec::ZecKeySource;
    let (mut app, dir, _) = owner_zec_app("accounts-zec-evm");
    let _ = key_jobs(&app);
    app.on_command(zec::SOURCE_EVM_BASE);
    assert!(zec_key_sources(&app).is_empty());
    assert!(app.zec.confirm_shared);
    assert_eq!(app.zec_account().unwrap().source, ZecKeySource::DEFAULT);
    let items = app.items();
    assert!(has_text(
        &items,
        crate::ui::screens_zec::text::EVM_SHARED.ko
    ));
    assert!(
        super::controls(&items)
            .iter()
            .any(|ctl| ctl.id == zec::SOURCE_APPLY && ctl.text == "정말 EVM 키 사용")
    );
    // `취소`: nothing applied.
    app.on_command(zec::SOURCE_CANCEL);
    assert!(!app.zec.confirm_shared);
    assert!(zec_key_sources(&app).is_empty());
    assert!(
        !super::controls(&app.items())
            .iter()
            .any(|ctl| ctl.id == zec::SOURCE_APPLY)
    );
    // Picked again and confirmed: the key worker derives the EVM key.
    app.on_command(zec::SOURCE_EVM_BASE);
    app.on_command(zec::SOURCE_APPLY);
    assert_eq!(
        zec_key_sources(&app),
        [ZecKeySource::EvmShared { evm_index: 0 }]
    );
    assert!(!app.zec.confirm_shared);
    let _ = std::fs::remove_dir_all(dir);
}

/// While a Zcash transaction is unfinished the drop-down is disabled and says why
/// (`SOURCE_BUSY`), it does not open, and a pick that still arrives is refused.
#[test]
fn zcash_dropdown_is_disabled_while_a_transaction_is_unfinished() {
    use crate::ui::screens_zec::ids as zec;
    use yw_core::zec::ZecKeySource;
    let (mut app, dir, _) = owner_zec_app("accounts-zec-busy");
    app.zec.busy = true;
    let items = app.items();
    assert!(
        super::controls(&items)
            .iter()
            .any(|ctl| { ctl.id == crate::ui::screens_links::ids::PICKER_ZEC && !ctl.enabled })
    );
    let busy = crate::app_zec::text::SOURCE_BUSY.ko;
    assert!(
        items
            .iter()
            .any(|item| matches!(item, Item::Help(text) if text == busy))
    );
    assert!(zec_entries(&mut app).is_empty());
    app.on_command(zec::HW_BASE);
    assert_eq!(app.zec_account().unwrap().source, ZecKeySource::DEFAULT);
    assert_eq!(app.zec.error.as_deref(), Some(busy));
    app.zec.busy = false;
    app.zec.error = None;
    assert!(zec_entries(&mut app).iter().all(|(_, _, enabled)| *enabled));
    let _ = std::fs::remove_dir_all(dir);
}
