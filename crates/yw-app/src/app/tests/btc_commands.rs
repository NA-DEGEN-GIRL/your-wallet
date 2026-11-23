//! The tests of `app_btc_commands.rs` that build an `App` (2026-11-21, S4 W0, spec/09 §2.1),
//! moved unchanged from its inline `mod tests` (which keeps the tests that build no `App`).
//! It was a `#[cfg(test)] #[path]` child of `crate::app_btc_commands`, not of `app::tests`, to keep
//! the access of the inline module, so no production item of that file was widened. 2026-11-22 (S4d
//! E0c, spec/09 §2.1): a child of `app::tests` (that file moves to yw-engine at S4d E1 and these
//! tests need `App`); it reaches nothing private there, so nothing was widened.

use std::path::PathBuf;
use std::sync::mpsc;

use yw_core::btc::{BtcMeta, BtcNetwork, Sats};
use yw_engine::form::EditField;
use yw_platform::http::HttpsUrl;

use crate::app::{App, Paths};
use crate::ui::screens_btc::ids;
use yw_engine::apikeys::ApiKeys;
use yw_engine::btc::work::BtcRpcJob;
use yw_engine::errors::ErrorCode;
use yw_engine::events::{JournalView, KeyJob};
use yw_engine::meta::{Meta, Tab};
use yw_engine::network::{BtcNet, NetworkId};
use yw_engine::screen::SettingsSection;
use yw_engine::settings::{BtcIndexer, Settings};
use yw_engine::testkit::WalletTestExt;
use yw_engine::wallet::app_btc::{BtcAmountUnit, BtcConfirm, BtcFeeChoice, BtcSendForm};
use yw_engine::wallet::{AppMode, Confirm, Screen};
use yw_engine::workers::journal::btc::BtcMetaOp;
use yw_engine::workers::rpc::RpcJob;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("yw-app-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn app(dir: &std::path::Path, settings: Settings, meta: Meta) -> (App, mpsc::Receiver<RpcJob>) {
    let mut app = App::new(
        Paths {
            data: dir.to_path_buf(),
            logs: dir.join("logs"),
        },
        true,
        settings,
        ApiKeys::default(),
    );
    app.mode = AppMode::Unlocked {
        alt_passphrase: false,
    };
    app.meta = Some(meta);
    app.evm.journal = Some(JournalView {
        room: true,
        sol_room: true,
        btc_room: true,
        ..JournalView::default()
    });
    let (tx, rx) = mpsc::channel();
    app.rpc_tx = Some(tx);
    app.screen = Screen::Main;
    (app, rx)
}

fn testnet_url(app: &mut App) {
    app.apikeys.set_rpc(
        NetworkId::Bitcoin(BtcNet::Testnet4),
        &HttpsUrl::parse("https://btc.example.test/").unwrap(),
    );
}

fn key_jobs(app: &App) -> Vec<KeyJob> {
    app.key_queue
        .cancel_pending(u64::MAX)
        .into_iter()
        .map(|(_, job)| job)
        .collect()
}

#[test]
fn settings_commands_go_through_the_controller() {
    let dir = temp_dir("btc-settings-commands");
    let (mut app, rpc) = app(&dir, Settings::default(), Meta::default());
    assert!(app.on_btc_command(ids::SECTION_BTC));
    assert_eq!(app.screen, Screen::Settings(SettingsSection::Bitcoin));
    // Disabled: the network radio only records the network `켜기` uses.
    assert!(app.on_btc_command(ids::SET_TESTNET4));
    assert_eq!(app.settings.bitcoin.network, BtcNet::Testnet4);
    let written = std::fs::read_to_string(dir.join("settings.json")).unwrap();
    assert!(written.contains("testnet4"));
    assert_eq!(app.screen, Screen::Settings(SettingsSection::Bitcoin));
    // No `rpc:bitcoin:testnet4`: E-KEY-005, nothing written or queued.
    assert!(app.on_btc_command(ids::ENABLE));
    assert!(!app.settings.bitcoin.enabled);
    assert_eq!(
        app.btc.settings_message,
        Some(ErrorCode::Key005.text_in(yw_core::lang::Lang::Ko))
    );
    assert!(key_jobs(&app).is_empty());
    // With the URL: enabled, sessions reset, BtcMeta created for testnet4.
    testnet_url(&mut app);
    assert!(app.on_btc_command(ids::ENABLE));
    assert!(app.settings.bitcoin.enabled);
    assert!(key_jobs(&app).iter().any(|job| matches!(
        job,
        KeyJob::BtcMeta {
            op: BtcMetaOp::Create {
                network: BtcNetwork::Testnet4
            }
        }
    )));
    assert!(
        rpc.try_iter()
            .any(|job| matches!(job, RpcJob::Btc(job) if matches!(*job, BtcRpcJob::Reset)))
    );
    // Blockbook asks T-BTC-BB-OPTIN first.
    assert!(app.on_btc_command(ids::IDX_BB_REST));
    assert_eq!(app.screen, Screen::Confirm(Confirm::Btc));
    assert_eq!(
        app.btc.confirm,
        Some(BtcConfirm::IndexerOptIn {
            indexer: BtcIndexer::BbRest
        })
    );
    assert_eq!(app.settings.bitcoin.indexer, BtcIndexer::Esplora);
    app.btc_confirm_yes();
    assert_eq!(app.settings.bitcoin.indexer, BtcIndexer::BbRest);
    assert_eq!(app.screen, Screen::Settings(SettingsSection::Bitcoin));
    assert!(app.on_btc_command(ids::IDX_ESPLORA));
    assert_eq!(app.settings.bitcoin.indexer, BtcIndexer::Esplora);
    // Esplora `저장` with an empty edit: E-BTC-006, the value stays.
    assert!(app.on_btc_command(ids::ESPLORA_TESTNET4_SAVE));
    assert_eq!(
        app.btc.settings_message,
        Some(ErrorCode::Btc006.text_in(yw_core::lang::Lang::Ko))
    );
    assert_eq!(
        app.settings.bitcoin.esplora_testnet4,
        "https://mempool.space/testnet4/api"
    );
    // The tab is remembered in meta prefs.
    assert!(app.on_btc_command(ids::TAB_BTC));
    assert_eq!(app.meta.as_ref().map(|meta| meta.prefs.tab), Some(Tab::Btc));
    // 끄기 (no in-flight record).
    assert!(app.on_btc_command(ids::ENABLE));
    assert!(!app.settings.bitcoin.enabled);
    assert!(!app.on_btc_command(crate::ui::screens::ids::LOCK));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn form_fields_and_buttons_reach_the_controller() {
    let dir = temp_dir("btc-form-commands");
    let mut settings = Settings::default();
    settings.bitcoin.enabled = true;
    settings.bitcoin.network = BtcNet::Testnet4;
    let account = yw_core::bip32::AccountXpub {
        pubkey: yw_core::hex::decode_array::<33>(
            "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4",
        )
        .unwrap(),
        chain_code: [7; 32],
    };
    let meta = Meta {
        btc: Some(Box::new(BtcMeta::new(BtcNetwork::Testnet4, account))),
        ..Meta::default()
    };
    let (mut app, _rpc) = app(&dir, settings, meta);
    testnet_url(&mut app);
    assert!(app.on_btc_command(ids::SEND_OPEN));
    assert_eq!(app.screen, Screen::BtcSend);
    app.btc_apply_field(EditField::BtcSendAmount, "0.0012");
    assert_eq!(app.btc.send.amount, Sats::new(120_000));
    assert!(app.on_btc_command(ids::UNIT_SATS));
    assert_eq!(app.btc.send.unit, BtcAmountUnit::Sats);
    assert_eq!(app.btc.send.amount_text, "120000");
    // A typed fee survives its own edits and is dropped when the cap request goes away.
    app.btc.send.fee.needs_typed = Sats::new(600_000);
    app.btc_apply_field(EditField::BtcTypedFee, "600000");
    assert_eq!(app.btc.send.fee.typed, Sats::new(600_000));
    app.btc_apply_field(EditField::BtcSendAmount, "130000");
    assert_eq!(app.btc.send.fee.needs_typed, None);
    assert!(app.btc.send.fee.typed_text.is_empty());
    assert_eq!(app.btc.send.fee.typed, None);
    assert!(app.on_btc_command(ids::FEE_MANUAL));
    assert_eq!(app.btc.send.fee.choice, BtcFeeChoice::Manual);
    app.btc_apply_field(EditField::BtcFeeManual, "2.5");
    assert!(app.btc.send.fee.manual.is_some());
    assert!(app.on_btc_command(ids::SEND_MAX));
    assert!(app.btc.send.send_max);
    assert!(app.btc.send.amount_text.is_empty());
    assert!(app.on_btc_command(ids::SEND_CANCEL));
    assert_eq!(app.btc.send, BtcSendForm::default());
    assert_eq!(app.screen, Screen::Main);
    assert!(app.on_btc_command(ids::BUMP_FEE_SLOW));
    assert_eq!(app.btc.bump.fee.choice, BtcFeeChoice::Slow);
    assert_eq!(app.btc.send.fee.choice, BtcFeeChoice::Normal);
    // 받기 shows S12 at once; the address follows the key worker's stored index.
    assert!(app.on_btc_command(ids::RECEIVE_OPEN));
    assert_eq!(app.screen, Screen::BtcReceive);
    assert!(key_jobs(&app).iter().any(|job| matches!(
        job,
        KeyJob::BtcMeta {
            op: BtcMetaOp::ReceiveAddress {
                network: BtcNetwork::Testnet4,
                ..
            }
        }
    )));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The fee radios dispatch to the choice they are drawn for (2026-11-18, S3 C7-C9 review):
/// `fee_choice` of each radio's press equals `fee_choice_of` of its id, which pairs `fee_ids`
/// with the drawing order `FEE_CHOICES`. 2026-11-23 (spec/15 §11.4 S4d E1): moved here unchanged
/// from the inline tests of `app_btc_commands` (it maps control ids, which stay in the shell;
/// `fee_choice` is `#[doc(hidden)] pub` for it).
#[test]
fn fee_presses_match_the_drawn_radio_order() {
    use crate::ui::screens_btc::{fee_choice_of, fee_ids, ids};
    use yw_engine::wallet::app_btc_commands::fee_choice;
    for bump in [false, true] {
        for id in fee_ids(bump) {
            let press = ids::press_of(id).unwrap();
            assert_eq!(fee_choice(press), fee_choice_of(id), "id {id}");
            assert_eq!(fee_choice_of(id).map(|(_, b)| b), Some(bump), "id {id}");
        }
    }
}
