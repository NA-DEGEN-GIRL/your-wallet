//! The tests of `app_sol_commands.rs` that build an `App` (2026-11-21, S4 W0, spec/09 §2.1),
//! moved unchanged from its inline `mod tests` (where every test builds an `App`).
//! It was a `#[cfg(test)] #[path]` child of `crate::app_sol_commands`, not of `app::tests`, to keep
//! the access of the inline module, so no production item of that file was widened. 2026-11-22 (S4d
//! E0c, spec/09 §2.1): a child of `app::tests` (that file moves to yw-engine at S4d E1 and these
//! tests need `App`); it reaches nothing private there, so nothing was widened.

use yw_core::bip32::path::AccountIndex;
use yw_core::slip10::SolKeySource;
use yw_core::sol::SolAddress;

use crate::apikeys::ApiKeys;
use crate::app::{App, AppMode, Paths, Screen};
use crate::app_sol::ScanStage;
use crate::meta::{Account, Meta, Tab};
use crate::settings::Settings;
use crate::sol::scan::ScanRow;
use crate::ui::main_window::{Ctl, Item};
use crate::ui::screens_sol::ids::{self, ScanAction, scan_row_id};

fn address(seed: u8) -> SolAddress {
    SolAddress::from_bytes([seed; 32])
}

/// A Solana wallet with two accounts and a finished scan of 60 funded rows: rows 0–49 are
/// BIP44 accounts (move only), rows 50–59 standard accounts 50.. (add only).
fn scanned_app() -> App {
    let dir = std::env::temp_dir().join(format!("yw-app-sol-scan-{}", std::process::id()));
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
    let mut meta = Meta {
        sol_accounts: (0..2)
            .map(|index| Account {
                index,
                label: format!("Solana {}", index + 1),
                address: address(200 + u8::try_from(index).unwrap()).to_base58(),
                hidden: false,
            })
            .collect(),
        ..Meta::default()
    };
    meta.prefs.tab = Tab::Sol;
    meta.prefs.sol_account = 0;
    app.meta = Some(meta);
    let mut rows = Vec::new();
    for index in 0..50_u32 {
        rows.push(ScanRow {
            source: SolKeySource::Bip44Account(AccountIndex::new(index).unwrap()),
            address: address(u8::try_from(index).unwrap() + 1),
            balance: 1_000_000,
            tokens: Vec::new(),
        });
    }
    for index in 50..60_u32 {
        rows.push(ScanRow {
            source: SolKeySource::Standard(AccountIndex::new(index).unwrap()),
            address: address(u8::try_from(index).unwrap() + 1),
            balance: 2_000_000,
            tokens: Vec::new(),
        });
    }
    app.sol.scan.stage = ScanStage::Done;
    app.sol.scan.cluster = Some(app.sol_cluster());
    app.sol.scan.rows = rows;
    app.screen = Screen::SolScan;
    app
}

/// `scanned_app` with a `YubiKey` Solana account selected (`address(250)`).
fn hardware_selected(app: &mut App) -> SolAddress {
    let hardware = address(250);
    let meta = app.meta.as_mut().unwrap();
    meta.hw_accounts.sol.push(Account {
        index: 0,
        label: "YubiKey Solana".to_owned(),
        address: hardware.to_base58(),
        hidden: false,
    });
    meta.hw_accounts.sol_selected = Some(0);
    assert_eq!(
        app.sol_selected().map(|(.., address)| address),
        Some(hardware)
    );
    hardware
}

fn controls(items: &[Item]) -> Vec<Ctl> {
    items
        .iter()
        .flat_map(|item| match item {
            Item::Row(row) | Item::LabeledRow(_, row) => row.clone(),
            _ => Vec::new(),
        })
        .collect()
}

#[test]
fn scan_rows_past_the_fortieth_keep_their_own_action() {
    let mut app = scanned_app();
    // Every rendered scan button maps back to its own row, never to an account radio.
    let mut items = Vec::new();
    app.sol_scan_screen(&mut items);
    let buttons: Vec<Ctl> = controls(&items)
        .into_iter()
        .filter(|ctl| ids::scan_action(ctl.id).is_some())
        .collect();
    assert_eq!(buttons.len(), 60);
    for (row, ctl) in buttons.iter().enumerate() {
        let expected = if row < 50 {
            ScanAction::Move(row)
        } else {
            ScanAction::Add(row)
        };
        assert_eq!(ids::scan_action(ctl.id), Some(expected), "row {row}");
        assert!(
            !(ids::ACCOUNT_BASE..ids::ACCOUNT_BASE + ids::ACCOUNT_SPAN).contains(&ctl.id),
            "row {row}"
        );
    }
    // Row 40 (the 41st) used to be 7,200 = account radio 0: now it moves that row's funds.
    let id = scan_row_id(ScanAction::Move(40)).unwrap();
    assert!(app.on_sol_command(id));
    assert_eq!(app.screen, Screen::SolSend);
    assert_eq!(
        app.sol.send.moving.map(|(source, _)| source),
        Some(SolKeySource::Bip44Account(AccountIndex::new(40).unwrap()))
    );
    assert_eq!(app.meta.as_ref().unwrap().prefs.sol_account, 0);
    // Row 55 (standard account 55): `계정 추가` adds that account, not a selection.
    app.screen = Screen::SolScan;
    let id = scan_row_id(ScanAction::Add(55)).unwrap();
    assert!(app.on_sol_command(id));
    let meta = app.meta.as_ref().unwrap();
    assert!(meta.sol_accounts.iter().any(|account| account.index == 55));
    assert_eq!(meta.prefs.sol_account, 0);
    // The account radios still select accounts.
    assert!(app.on_sol_command(ids::ACCOUNT_BASE + 1));
    assert_eq!(app.meta.as_ref().unwrap().prefs.sol_account, 1);
}

/// Signing moves non-standard funds only to a standard account of the primary phrase
/// (spec/07 §3.3, §13.1-6): with a `YubiKey` account selected the move goes to `Solana 1`,
/// named on the scan screen; a form whose recipient is another account cannot be reviewed;
/// without such an account the move is refused before the form. The results stay when the
/// scan is reopened (one move per asset) until `다시 스캔`.
#[test]
fn scan_moves_go_to_a_primary_standard_account() {
    let mut app = scanned_app();
    app.evm.journal = Some(crate::events::JournalView::default());
    let hardware = hardware_selected(&mut app);
    let mut items = Vec::new();
    app.sol_scan_screen(&mut items);
    assert!(items.iter().any(|item| matches!(
        item,
        Item::Field(label, value) if label == "옮겨 받을 계정" && value.starts_with("Solana 1 ·")
    )));
    assert!(app.on_sol_command(scan_row_id(ScanAction::Move(3)).unwrap()));
    assert_eq!(app.screen, Screen::SolSend);
    assert_eq!(app.sol.send.to_text, address(200).to_base58());
    assert!(app.sol_move_target_ok() && app.sol_can_review());
    // A kept form whose recipient is not a primary standard account (here the YubiKey one).
    app.sol.send.to_text = hardware.to_base58();
    app.sol_validate_send();
    assert!(app.sol.send.check.is_some());
    assert!(!app.sol_move_target_ok() && !app.sol_can_review());
    // Reopening keeps this cluster's results and the moved row; `다시 스캔` clears them.
    app.sol_open_scan();
    assert_eq!(app.sol.scan.stage, ScanStage::Done);
    assert_eq!(app.sol.scan.rows.len(), 60);
    assert_eq!(app.sol.scan.moved, vec![address(4)]);
    assert!(app.on_sol_command(ids::SCAN_AGAIN));
    assert_eq!(app.sol.scan.stage, ScanStage::Notice);
    assert!(app.sol.scan.rows.is_empty() && app.sol.scan.moved.is_empty());

    // No visible standard account of the primary phrase: named, disabled, refused.
    let mut app = scanned_app();
    hardware_selected(&mut app);
    app.meta.as_mut().unwrap().sol_accounts.clear();
    let mut items = Vec::new();
    app.sol_scan_screen(&mut items);
    let text = crate::app_sol::SOL_SCAN_NO_TARGET_TEXT;
    assert!(
        items
            .iter()
            .any(|item| matches!(item, Item::Banner(shown, _) if shown == text))
    );
    let id = scan_row_id(ScanAction::Move(0)).unwrap();
    assert!(
        controls(&items)
            .iter()
            .any(|ctl| ctl.id == id && !ctl.enabled)
    );
    assert!(app.on_sol_command(id));
    assert_eq!(app.screen, Screen::SolScan);
    assert_eq!(app.sol.scan.message.as_deref(), Some(text));
    assert!(app.sol.send.moving.is_none());
}

/// spec/14 (Step 3): the Solana screens (main, send, result, receive, settings, scan) and the
/// Zcash tab (off and on) in English carry no Hangul (the labels here are ASCII data), and the
/// same screens in Korean still do.
#[test]
fn english_sol_and_zec_screens_have_no_korean() {
    use yw_core::lang::{Lang, has_hangul};
    let render = |app: &App| {
        let mut items = Vec::new();
        app.sol_main_screen(&mut items);
        app.sol_send_screen(&mut items);
        app.sol_send_result_screen(&mut items);
        app.sol_receive_screen(&mut items);
        app.sol_settings_section(&mut items);
        app.sol_scan_screen(&mut items);
        app.zec_main_screen(&mut items);
        items
    };
    let mut app = scanned_app();
    app.show_advanced = true;
    app.sol.send.send_max = true;
    let korean = render(&app);
    assert!(korean.iter().any(|item| has_hangul(&format!("{item:?}"))));
    app.settings.language = Lang::En;
    for zcash in [false, true] {
        app.settings.zcash.enabled = zcash;
        for item in render(&app) {
            let shown = format!("{item:?}");
            assert!(!has_hangul(&shown), "{shown}");
        }
    }
}
