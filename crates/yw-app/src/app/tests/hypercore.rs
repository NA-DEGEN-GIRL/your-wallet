//! The tests of `app_hypercore.rs` that build an `App` (2026-11-21, S4 W0, spec/09 §2.1),
//! moved unchanged from its inline `mod tests` (where every test builds an `App`).
//! It was a `#[cfg(test)] #[path]` child of `crate::app_hypercore`, not of `app::tests`, to keep
//! the access of the inline module, so no production item of that file was widened. 2026-11-22 (S4d
//! E0c, spec/09 §2.1): a child of `app::tests` (that file moves to yw-engine at S4d E1 and these
//! tests need `App`); it reaches nothing private there, so nothing was widened.

use yw_core::evm::address::{Address, parse_address};
use yw_core::hypercore::{HcEvmLink, HcKind, HcNetwork, HcPerpState, HcSpotBalance, HcToken};

use crate::apikeys::ApiKeys;
use crate::app::{App, AppMode, Paths, Screen};
use crate::app_hypercore::{HcActivity, HcAsset, HcForm, HcFormKind, HcStatus, text};
use crate::flow::evm::form::AddressNote;
use crate::hypercore::HcBalances;
use crate::meta::{Account, EvmAccountPref, Meta};
use crate::settings::Settings;
use crate::ui::main_window::{Ctl, Item};
use crate::ui::screens_hypercore::ids;
use yw_engine::screen::Tone;

const OWN: &str = "0x9858effd232b4033e47d90003d41ec34ecaeda94";
const OTHER: &str = "0x00000000000000000000000000000000000000b2";
/// Look-alikes of `OWN` (the first and the last six hex digits).
const LOOK_A: &str = "0x9858ef1111111111111111111111111111aeda94";
const LOOK_B: &str = "0x9858ef2222222222222222222222222222aeda94";

fn address(text: &str) -> Address {
    parse_address(text).unwrap()
}

/// An unlocked wallet with EVM accounts `OWN` (selected) and `OTHER`, the mainnet `HyperCore`
/// balances of `OWN` (100 USDC perp; 1.23456789 of a token whose `HyperEVM` side has two
/// decimals fewer) and S-HC open.
fn app() -> App {
    let dir = std::env::temp_dir().join(format!("yw-app-hc-ui-{}", std::process::id()));
    let mut app = App::new(
        Paths {
            data: dir.clone(),
            logs: dir.join("logs"),
        },
        true,
        Settings::default(),
        ApiKeys::default(),
    );
    app.mode = AppMode::Unlocked {
        alt_passphrase: false,
    };
    let mut meta = Meta::default();
    meta.evm_accounts[0].address = OWN.to_owned();
    meta.evm_accounts.push(Account {
        index: 1,
        label: "계정 2".to_owned(),
        address: OTHER.to_owned(),
        hidden: false,
    });
    app.meta = Some(meta);
    let token = HcToken {
        name: "TKN".to_owned(),
        index: 1,
        token_id: "0x0000000000000000000000000000000a".to_owned(),
        sz_decimals: 2,
        wei_decimals: 8,
        evm: Some(HcEvmLink {
            address: address("0x00000000000000000000000000000000000000c3"),
            extra_wei_decimals: -2,
        }),
        full_name: None,
    };
    app.hypercore.tokens = Some((HcNetwork::Mainnet, vec![token]));
    app.hypercore.balances = Some((
        HcNetwork::Mainnet,
        address(OWN),
        HcBalances {
            spot: vec![HcSpotBalance {
                coin: "TKN".to_owned(),
                token: 1,
                total: "1.23456789".to_owned(),
                hold: "0.0".to_owned(),
            }],
            perp: HcPerpState {
                account_value: "100.0".to_owned(),
                withdrawable: "100.0".to_owned(),
                positions: 0,
            },
        },
    ));
    app.screen = Screen::HyperCore;
    app
}

fn form(app: &mut App, kind: HcFormKind, to: &str, amount: &str) {
    app.hypercore.form = HcForm {
        kind,
        to_text: to.to_owned(),
        amount_text: amount.to_owned(),
        to_perp: true,
        asset: if kind == HcFormKind::ToEvm {
            HcAsset::Spot(1)
        } else {
            HcAsset::PerpUsdc
        },
        ..HcForm::default()
    };
    app.hc_validate();
}

fn shown(app: &App, card: bool) -> Vec<Item> {
    let mut items = Vec::new();
    if card {
        app.hc_card(&mut items);
    } else {
        app.hc_screen(&mut items);
    }
    items
}

fn banners(items: &[Item]) -> Vec<(String, Tone)> {
    items
        .iter()
        .filter_map(|item| match item {
            Item::Banner(text, tone) => Some((text.clone(), *tone)),
            _ => None,
        })
        .collect()
}

fn control(items: &[Item], id: u16) -> Option<Ctl> {
    items
        .iter()
        .flat_map(|item| match item {
            Item::Row(row) | Item::LabeledRow(_, row) => row.clone(),
            _ => Vec::new(),
        })
        .find(|ctl| ctl.id == id)
}

/// The look-alike acknowledgement covers one recipient: a change to another look-alike drops
/// it (S11 and the Bitcoin form do the same).
#[test]
fn look_alike_acknowledgement_follows_the_recipient() {
    let mut app = app();
    form(&mut app, HcFormKind::Send, LOOK_A, "1");
    assert!(app.hypercore.form.error.is_none());
    assert!(app.hypercore.form.notes.iter().any(AddressNote::needs_ack));
    assert!(!app.hc_can_review());
    app.hc_toggle_ack();
    assert!(app.hc_can_review());
    // Another look-alike in the field: not acknowledged.
    app.hypercore.form.to_text = LOOK_B.to_owned();
    app.hc_validate();
    assert!(app.hypercore.form.notes.iter().any(AddressNote::needs_ack));
    assert!(!app.hypercore.form.ack && !app.hc_can_review());
    app.hc_toggle_ack();
    assert!(app.hc_can_review());
    // An acknowledgement recorded for another address does not count.
    app.hypercore.form.ack_for = Some(address(LOOK_A));
    assert!(!app.hc_can_review());
}

/// The card lists the selected account's transfers only.
#[test]
fn card_activity_is_the_selected_accounts() {
    let mut app = app();
    app.screen = Screen::Main;
    // Whole next to HyperEVM (the card folds to one line next to other chains, 2026-11-10).
    app.settings.evm_chain_id = 999;
    for (account, amount) in [(OWN, "10 USDC"), (OTHER, "20 USDC")] {
        app.hypercore.activity.push(HcActivity {
            network: HcNetwork::Mainnet,
            nonce: 1_790_000_000_000,
            account: address(account),
            kind: HcKind::UsdSend,
            amount: amount.to_owned(),
            to: Some(address(LOOK_A)),
            status: HcStatus::Ok,
        });
    }
    let texts = |app: &App| -> Vec<String> {
        shown(app, true)
            .into_iter()
            .filter_map(|item| match item {
                Item::Text(text) => Some(text),
                _ => None,
            })
            .collect()
    };
    let own = texts(&app);
    assert!(own.iter().any(|text| text.contains("10 USDC")), "{own:?}");
    assert!(!own.iter().any(|text| text.contains("20 USDC")), "{own:?}");
    app.meta.as_mut().unwrap().prefs.evm_account = EvmAccountPref::Index(1);
    let other = texts(&app);
    assert!(
        other.iter().any(|text| text.contains("20 USDC")),
        "{other:?}"
    );
    assert!(
        !other.iter().any(|text| text.contains("10 USDC")),
        "{other:?}"
    );
}

/// S-HC shows what can be sent and `최대` fills it at the form's decimals (a `HyperEVM` move
/// cuts the digits the EVM side lacks); a withdrawal to the signing account is information;
/// a failed load says so with `새로고침` instead of "loading" forever.
#[test]
fn forms_show_the_available_amount_and_the_load_state() {
    let mut app = app();
    form(&mut app, HcFormKind::Withdraw, OWN, "");
    assert!(control(&shown(&app, false), ids::MAX).is_some_and(|ctl| ctl.enabled));
    app.hc_fill_max();
    assert_eq!(app.hypercore.form.amount_text, "100");
    assert!(app.hypercore.form.error.is_none() && app.hc_can_review());
    let items = shown(&app, false);
    assert!(
        banners(&items).contains(&(text::WITHDRAW_OWN.ko.to_owned(), Tone::Info)),
        "{:?}",
        banners(&items)
    );

    form(&mut app, HcFormKind::ToEvm, "", "");
    assert_eq!(
        app.hc_form_available(),
        Some(("1.234567".to_owned(), "TKN".to_owned()))
    );
    app.hc_fill_max();
    assert_eq!(app.hypercore.form.amount_text, "1.234567");
    assert!(
        app.hypercore.form.error.is_none(),
        "{:?}",
        app.hypercore.form.error
    );

    // The load failed: the reason and `새로고침`, not an endless "불러오는 중".
    app.hypercore.balances = None;
    app.hypercore.loading = false;
    app.hypercore.error = Some("Hyperliquid API에 연결할 수 없습니다".to_owned());
    app.hc_validate();
    let error = app.hypercore.form.error.clone().unwrap();
    assert!(error.contains("불러오지 못했습니다"), "{error}");
    let items = shown(&app, false);
    assert!(control(&items, ids::REFRESH).is_some());
    assert!(
        banners(&items)
            .iter()
            .any(|(text, _)| text == "Hyperliquid API에 연결할 수 없습니다")
    );
    assert!(control(&items, ids::MAX).is_some_and(|ctl| !ctl.enabled));
}
