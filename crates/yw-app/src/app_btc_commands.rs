//! Command and edit-change handling of the Bitcoin screens (ids in `ui::screens_btc::ids`): every
//! action goes through the `App::btc_*` wrappers of [`crate::app_btc`] (controller + actions).
//! Buttons, checks and radios act on the controller state, not on the control's own check
//! state, so a `WM_COMMAND` without a click behaves the same.

use yw_core::btc::{BtcNetwork, ScriptType, Txid};

use crate::app::{App, Screen, SettingsSection};
use crate::app_btc::{BtcAction, BtcAmountUnit, BtcBumpForm, BtcSendForm};
use crate::btc::{app_network, core_network};
use crate::settings::BtcIndexer;
use crate::ui::screens_btc::{esplora_ids, fee_choice_of, ids};

/// Longest text read from a Bitcoin edit (addresses ≤ 128, Esplora URL ≤ 256).
const TEXT_MAX: usize = 512;

fn offset(id: u16, base: u16, span: u16) -> Option<u16> {
    id.checked_sub(base).filter(|offset| *offset < span)
}

/// The form edits whose text the controller keeps (re-created controls show it again).
const SEND_FIELDS: [u16; 4] = [
    ids::SEND_TO_EDIT,
    ids::SEND_AMOUNT_EDIT,
    ids::FEE_MANUAL_EDIT,
    ids::TYPED_FEE_EDIT,
];
const BUMP_FIELDS: [u16; 2] = [ids::BUMP_MANUAL_EDIT, ids::BUMP_TYPED_EDIT];

impl App {
    fn btc_edit_text(&self, id: u16) -> Option<String> {
        self.controls.text(id, TEXT_MAX)
    }

    /// The controller's copy of a form edit.
    fn btc_field_text(&self, id: u16) -> &str {
        match id {
            ids::SEND_TO_EDIT => &self.btc.send.to_text,
            ids::SEND_AMOUNT_EDIT => &self.btc.send.amount_text,
            ids::FEE_MANUAL_EDIT => &self.btc.send.fee.manual_text,
            ids::TYPED_FEE_EDIT => &self.btc.send.fee.typed_text,
            ids::BUMP_MANUAL_EDIT => &self.btc.bump.fee.manual_text,
            ids::BUMP_TYPED_EDIT => &self.btc.bump.fee.typed_text,
            _ => "",
        }
    }

    /// Hands a form edit's text to the controller (no repaint).
    fn btc_apply_field(&mut self, id: u16, text: &str) {
        self.btc_call(|ui, ctx| {
            match id {
                ids::SEND_TO_EDIT => ui.set_recipient(ctx, text),
                ids::SEND_AMOUNT_EDIT => ui.set_amount(ctx, text),
                ids::FEE_MANUAL_EDIT => ui.set_manual_rate(text, false),
                ids::TYPED_FEE_EDIT => ui.set_typed_fee(text, false),
                ids::BUMP_MANUAL_EDIT => ui.set_manual_rate(text, true),
                ids::BUMP_TYPED_EDIT => ui.set_typed_fee(text, true),
                _ => {}
            }
            Vec::new()
        });
        match id {
            ids::SEND_TO_EDIT | ids::SEND_AMOUNT_EDIT | ids::FEE_MANUAL_EDIT => {
                self.btc_drop_stale_typed(false);
            }
            ids::BUMP_MANUAL_EDIT => self.btc_drop_stale_typed(true),
            _ => {}
        }
    }

    /// The typed-fee field is shown only while the cap asks for it (spec/08 §8.3): once an input
    /// change withdraws the request, its text is cleared so no hidden override reaches a plan.
    fn btc_drop_stale_typed(&mut self, bump: bool) {
        let fee = if bump {
            &self.btc.bump.fee
        } else {
            &self.btc.send.fee
        };
        if fee.needs_typed.is_none() && !fee.typed_text.is_empty() {
            self.btc.set_typed_fee("", bump);
        }
    }

    /// Reads the form edits once more before `검토` (the controller copy wins only when equal).
    fn btc_sync_form(&mut self, bump: bool) {
        let fields: &[u16] = if bump { &BUMP_FIELDS } else { &SEND_FIELDS };
        for id in fields {
            if let Some(text) = self.btc_edit_text(*id)
                && text != self.btc_field_text(*id)
            {
                self.btc_apply_field(*id, &text);
            }
        }
    }

    /// `EN_CHANGE` of a Bitcoin edit; `false` when `id` is not one of them.
    pub fn on_btc_edit_change(&mut self, id: u16) -> bool {
        match id {
            ids::SEND_TO_EDIT
            | ids::SEND_AMOUNT_EDIT
            | ids::FEE_MANUAL_EDIT
            | ids::TYPED_FEE_EDIT
            | ids::BUMP_MANUAL_EDIT
            | ids::BUMP_TYPED_EDIT => {
                let text = self.btc_edit_text(id).unwrap_or_default();
                if text != self.btc_field_text(id) {
                    self.btc_apply_field(id, &text);
                    self.refresh();
                }
            }
            // Read when `저장` / `테스트` is pressed.
            ids::ESPLORA_MAINNET_EDIT | ids::ESPLORA_TESTNET4_EDIT => {}
            _ => return false,
        }
        true
    }

    fn btc_set_unit(&mut self, unit: BtcAmountUnit) {
        self.btc_call(|ui, ctx| {
            ui.set_unit(ctx, unit);
            Vec::new()
        });
        let text = self.btc.send.amount_text.clone();
        self.controls.set_text(ids::SEND_AMOUNT_EDIT, &text);
    }

    fn btc_toggle_max(&mut self) {
        self.btc_call(|ui, ctx| {
            ui.toggle_send_max(ctx);
            Vec::new()
        });
        self.btc_drop_stale_typed(false);
        if self.btc.send.send_max {
            self.controls.set_text(ids::SEND_AMOUNT_EDIT, "");
        }
    }

    /// Settings network radio: the network change procedure while enabled (confirmation,
    /// spec/08 §2); while disabled only the network `켜기` will use is written.
    fn btc_settings_network(&mut self, net: BtcNetwork) {
        if self.settings.bitcoin.enabled {
            self.btc_choose_network(net);
            return;
        }
        self.btc.settings_message = None;
        if core_network(self.settings.bitcoin.network) == net {
            return;
        }
        let mut bitcoin = self.settings.bitcoin.clone();
        bitcoin.network = app_network(net);
        self.btc_apply(vec![BtcAction::SaveSettings(
            Box::new(bitcoin),
            "bitcoin.network",
        )]);
    }

    /// `Bitcoin 사용`: 켜기 with the selected network (E-KEY-005 without its URL) / 끄기.
    fn btc_toggle_enabled(&mut self) {
        if self.settings.bitcoin.enabled {
            self.btc_disable();
        } else {
            self.btc_enable(core_network(self.settings.bitcoin.network));
        }
    }

    /// Esplora URL rows: `저장`, `기본값으로`, `테스트`; `false` when `id` is not one of them.
    fn on_btc_esplora(&mut self, id: u16) -> bool {
        for net in BtcNetwork::ALL {
            let (edit_id, save_id, default_id, test_id) = esplora_ids(net);
            if id == save_id {
                let typed = self.btc_edit_text(edit_id).unwrap_or_default();
                self.btc_save_esplora_url(net, &typed);
                if self.btc.settings_message.is_none() {
                    let saved = self.btc_ctx().esplora_text(net).to_owned();
                    self.controls.set_text(edit_id, &saved);
                }
                return true;
            }
            if id == default_id {
                self.btc_default_esplora_url(net);
                let saved = self.btc_ctx().esplora_text(net).to_owned();
                self.controls.set_text(edit_id, &saved);
                return true;
            }
            if id == test_id {
                let typed = self.btc_edit_text(edit_id).unwrap_or_default();
                self.btc_test_esplora_url(net, &typed);
                return true;
            }
        }
        false
    }

    /// Bitcoin commands; `false` when `id` is not one of them.
    pub fn on_btc_command(&mut self, id: u16) -> bool {
        match id {
            ids::TAB_BTC => self.btc_select_tab(),
            ids::SECTION_BTC => {
                self.btc.settings_message = None;
                self.set_screen(Screen::Settings(SettingsSection::Bitcoin));
            }
            ids::REFRESH => self.btc_refresh(),
            ids::SEND_OPEN => self.btc_open_send(),
            ids::RECEIVE_OPEN => {
                self.btc_open_receive();
                if !matches!(self.screen, Screen::BtcReceive | Screen::Confirm(_)) {
                    self.set_screen(Screen::BtcReceive);
                }
            }
            ids::BUMP_OPEN => self.btc_open_bump(),
            ids::DISCOVER_RETRY => self.btc_discover(false),
            ids::DISCOVER_MORE => self.btc_discover(true),
            ids::DISCOVER_CANCEL => self.btc_cancel_discovery(),
            ids::MISMATCH_KEEP_META => self.btc_mismatch_keep_meta(),
            ids::MISMATCH_USE_SETTINGS => self.btc_mismatch_use_settings(),
            ids::RESET_TIP => self.btc_reset_tip(),
            ids::ACCOUNT_ADD => self.btc_call(|ui, ctx| {
                ui.open_add_account(ctx);
                Vec::new()
            }),
            ids::ACCOUNT_ADD_CANCEL => self.btc_call(|ui, _| {
                ui.close_add_account();
                Vec::new()
            }),
            ids::SEND_ADDR_ACK => self.btc_toggle_address_ack(),
            ids::UNIT_BTC => self.btc_set_unit(BtcAmountUnit::Btc),
            ids::UNIT_SATS => self.btc_set_unit(BtcAmountUnit::Sats),
            ids::SEND_MAX => self.btc_toggle_max(),
            ids::SEND_REVIEW => {
                self.btc_sync_form(false);
                self.btc_review();
            }
            ids::SEND_CANCEL => {
                self.btc.send = BtcSendForm::default();
                self.set_screen(Screen::Main);
            }
            ids::RESULT_COPY => {
                if let Some(txid) = self.btc.result {
                    self.copy_text(&txid.to_display_hex());
                }
            }
            ids::RESULT_RETRY => {
                if let Some(txid) = self.btc.result {
                    self.btc_continue(txid);
                }
            }
            ids::RESULT_TO_SEND => self.set_screen(Screen::BtcSend),
            ids::BUMP_REVIEW => {
                self.btc_sync_form(true);
                self.btc_review_bump();
            }
            ids::BUMP_CANCEL => {
                self.btc.bump = BtcBumpForm::default();
                self.set_screen(Screen::Main);
            }
            ids::COPY_ADDRESS => {
                self.btc_copy_address();
                if self.info.as_deref() == Some("복사했습니다.") {
                    self.info = Some(
                        "주소를 복사했습니다. 붙여넣은 곳에서 주소 전체를 확인하세요.".to_owned(),
                    );
                }
            }
            ids::NEW_ADDRESS => self.btc_new_receive_address(),
            ids::ENABLE => self.btc_toggle_enabled(),
            ids::SET_MAINNET => self.btc_settings_network(BtcNetwork::Mainnet),
            ids::SET_TESTNET4 => self.btc_settings_network(BtcNetwork::Testnet4),
            ids::IDX_ESPLORA => self.btc_set_indexer(BtcIndexer::Esplora),
            ids::IDX_BB_RPC => self.btc_set_indexer(BtcIndexer::BbRpc),
            ids::IDX_BB_REST => self.btc_set_indexer(BtcIndexer::BbRest),
            other => {
                if !self.on_btc_esplora(other) && !self.on_btc_indexed(other) {
                    return false;
                }
            }
        }
        // The wrappers repaint only when the controller acted; radios and checks must show the
        // controller state again either way.
        self.refresh();
        true
    }

    fn on_btc_indexed(&mut self, id: u16) -> bool {
        if let Some((choice, bump)) = fee_choice_of(id) {
            self.btc_call(|ui, ctx| {
                ui.set_fee_choice(ctx, choice, bump);
                Vec::new()
            });
            self.btc_drop_stale_typed(bump);
            return true;
        }
        if let Some(choice) = offset(id, ids::ACCOUNT_ADD_TYPE, 4) {
            if let Some(script_type) = ScriptType::CHOICES.get(usize::from(choice)).copied() {
                self.btc_call(|ui, ctx| ui.add_account(ctx, script_type));
            }
            return true;
        }
        if let Some(row) = offset(id, ids::ACCOUNT_BASE, ids::ACCOUNT_SPAN) {
            let account = {
                let ctx = self.btc_ctx();
                self.btc
                    .account_rows(&ctx)
                    .get(usize::from(row))
                    .map(|row| row.id)
            };
            if let Some(account) = account {
                self.btc_call(|ui, ctx| ui.select_account(ctx, account));
            }
            return true;
        }
        if let Some(row) = offset(id, ids::UTXO_BASE, ids::UTXO_SPAN) {
            let utxo = {
                let ctx = self.btc_ctx();
                self.btc.utxos(&ctx).get(usize::from(row)).copied()
            };
            if let Some(utxo) = utxo
                && !utxo.in_flight
            {
                self.btc_freeze(utxo.outpoint, utxo.frozen.is_none());
            }
            return true;
        }
        if let Some(position) = offset(id, ids::ACTIVITY_BASE, ids::ACTIVITY_SPAN) {
            let rows = {
                let ctx = self.btc_ctx();
                self.btc.activity_rows(&ctx)
            };
            let Some(view) = rows.get(usize::from(position / ids::ACTIVITY_STRIDE)) else {
                return true;
            };
            let action = position % ids::ACTIVITY_STRIDE;
            if action == ids::ACT_COPY {
                let text = view.txid.clone();
                self.copy_text(&text);
                return true;
            }
            let Ok(txid) = Txid::from_display_hex(&view.txid) else {
                return true;
            };
            match action {
                ids::ACT_BUMP if view.can_bump => self.btc_open_bump(),
                ids::ACT_REBROADCAST if view.can_rebroadcast => self.btc_rebroadcast(txid),
                ids::ACT_ABANDON if view.can_abandon => self.btc_abandon(txid),
                ids::ACT_ESPLORA if view.can_esplora => self.btc_esplora_broadcast(txid),
                ids::ACT_CONTINUE if view.can_continue => self.btc_continue(txid),
                ids::ACT_CANCEL if view.can_continue => self.btc_cancel_signed(txid),
                _ => {}
            }
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::mpsc;

    use yw_core::btc::{BtcMeta, BtcNetwork, Sats};
    use yw_win::http::HttpsUrl;

    use crate::apikeys::ApiKeys;
    use crate::app::{App, AppMode, Confirm, Paths, Screen, SettingsSection};
    use crate::app_btc::{BtcAmountUnit, BtcConfirm, BtcFeeChoice, BtcSendForm};
    use crate::btc::work::BtcRpcJob;
    use crate::errors::ErrorCode;
    use crate::events::{JournalView, KeyJob};
    use crate::meta::{Meta, Tab};
    use crate::network::{BtcNet, NetworkId};
    use crate::settings::{BtcIndexer, Settings};
    use crate::ui::screens_btc::ids;
    use crate::workers::journal::btc::BtcMetaOp;
    use crate::workers::rpc::RpcJob;

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
            .cancel_pending()
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
        assert_eq!(app.btc.settings_message, Some(ErrorCode::Key005.text()));
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
        assert_eq!(app.btc.settings_message, Some(ErrorCode::Btc006.text()));
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
        app.btc_apply_field(ids::SEND_AMOUNT_EDIT, "0.0012");
        assert_eq!(app.btc.send.amount, Sats::new(120_000));
        assert!(app.on_btc_command(ids::UNIT_SATS));
        assert_eq!(app.btc.send.unit, BtcAmountUnit::Sats);
        assert_eq!(app.btc.send.amount_text, "120000");
        // A typed fee survives its own edits and is dropped when the cap request goes away.
        app.btc.send.fee.needs_typed = Sats::new(600_000);
        app.btc_apply_field(ids::TYPED_FEE_EDIT, "600000");
        assert_eq!(app.btc.send.fee.typed, Sats::new(600_000));
        app.btc_apply_field(ids::SEND_AMOUNT_EDIT, "130000");
        assert_eq!(app.btc.send.fee.needs_typed, None);
        assert!(app.btc.send.fee.typed_text.is_empty());
        assert_eq!(app.btc.send.fee.typed, None);
        assert!(app.on_btc_command(ids::FEE_MANUAL));
        assert_eq!(app.btc.send.fee.choice, BtcFeeChoice::Manual);
        app.btc_apply_field(ids::FEE_MANUAL_EDIT, "2.5");
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
}
