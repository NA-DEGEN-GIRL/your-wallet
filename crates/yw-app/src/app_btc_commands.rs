//! Command and edit-change handling of the Bitcoin screens (ids in `ui::screens_btc::ids`): every
//! action goes through the `App::btc_*` wrappers of [`crate::app_btc`] (controller + actions).
//! Buttons, checks and radios act on the controller state, not on the control's own check
//! state, so a `WM_COMMAND` without a click behaves the same.

use yw_core::btc::{BtcNetwork, Txid};
use yw_engine::cmd::{BtcActivityAction, BtcPress, Row};
use yw_engine::effect::Effect;
use yw_engine::form::EditField;

use crate::app::{App, Screen, SettingsSection};
use crate::app_btc::{BtcAction, BtcAmountUnit, BtcBumpForm, BtcFeeChoice, BtcSendForm};
use crate::btc::{app_network, core_network};
use crate::settings::BtcIndexer;

/// The form edits whose text the controller keeps (re-created controls show it again).
/// 2026-11-18 (S3 C9): `EditField`s (before, their control ids).
const SEND_FIELDS: [EditField; 4] = [
    EditField::BtcSendTo,
    EditField::BtcSendAmount,
    EditField::BtcFeeManual,
    EditField::BtcTypedFee,
];
const BUMP_FIELDS: [EditField; 2] = [EditField::BtcBumpManual, EditField::BtcBumpTyped];

/// The Esplora URL edit of `net` (S3 C9; `ui::screens_btc::esplora_ids` names its control).
const fn esplora_field(net: BtcNetwork) -> EditField {
    match net {
        BtcNetwork::Mainnet => EditField::BtcEsploraMainnet,
        BtcNetwork::Testnet4 => EditField::BtcEsploraTestnet4,
    }
}

/// The fee choice of a fee radio press, with whether it belongs to the fee-bump form (S3 C9:
/// was `ui::screens_btc::fee_choice_of` of the control id, which keeps the radio order).
const fn fee_choice(press: BtcPress) -> Option<(BtcFeeChoice, bool)> {
    Some(match press {
        BtcPress::FeeFast => (BtcFeeChoice::Fast, false),
        BtcPress::FeeNormal => (BtcFeeChoice::Normal, false),
        BtcPress::FeeSlow => (BtcFeeChoice::Slow, false),
        BtcPress::FeeManual => (BtcFeeChoice::Manual, false),
        BtcPress::BumpFeeFast => (BtcFeeChoice::Fast, true),
        BtcPress::BumpFeeNormal => (BtcFeeChoice::Normal, true),
        BtcPress::BumpFeeSlow => (BtcFeeChoice::Slow, true),
        BtcPress::BumpFeeManual => (BtcFeeChoice::Manual, true),
        _ => return None,
    })
}

impl App {
    /// The controller's copy of a form edit.
    fn btc_field_text(&self, field: EditField) -> &str {
        match field {
            EditField::BtcSendTo => &self.btc.send.to_text,
            EditField::BtcSendAmount => &self.btc.send.amount_text,
            EditField::BtcFeeManual => &self.btc.send.fee.manual_text,
            EditField::BtcTypedFee => &self.btc.send.fee.typed_text,
            EditField::BtcBumpManual => &self.btc.bump.fee.manual_text,
            EditField::BtcBumpTyped => &self.btc.bump.fee.typed_text,
            _ => "",
        }
    }

    /// Hands a form edit's text to the controller (no repaint). 2026-11-18 (S3 C9): the field
    /// is an `EditField` (before, its control id).
    pub(crate) fn btc_apply_field(&mut self, field: EditField, text: &str) {
        // 2026-11-20 (S4 P10a): `btc_update` (was `btc_call` with an empty batch).
        self.btc_update(|ui, ctx| match field {
            EditField::BtcSendTo => ui.set_recipient(ctx, text),
            EditField::BtcSendAmount => ui.set_amount(ctx, text),
            EditField::BtcFeeManual => ui.set_manual_rate(ctx.lang, text, false),
            EditField::BtcTypedFee => ui.set_typed_fee(ctx.lang, text, false),
            EditField::BtcBumpManual => ui.set_manual_rate(ctx.lang, text, true),
            EditField::BtcBumpTyped => ui.set_typed_fee(ctx.lang, text, true),
            _ => {}
        });
        match field {
            EditField::BtcSendTo | EditField::BtcSendAmount | EditField::BtcFeeManual => {
                self.btc_drop_stale_typed(false);
            }
            EditField::BtcBumpManual => self.btc_drop_stale_typed(true),
            _ => {}
        }
    }

    /// The typed-fee field is shown only while the cap asks for it (spec/08 §8.3): once an input
    /// change withdraws the request, its text is cleared so no hidden override reaches a plan.
    pub(crate) fn btc_drop_stale_typed(&mut self, bump: bool) {
        let fee = if bump {
            &self.btc.bump.fee
        } else {
            &self.btc.send.fee
        };
        if fee.needs_typed.is_none() && !fee.typed_text.is_empty() {
            self.btc.set_typed_fee(self.settings.language, "", bump);
        }
    }

    /// Reads the form edits once more before `검토` (the controller copy wins only when equal).
    /// 2026-11-18 (S3 C9): from the form state (`App::form_text`); before, reads of the edits.
    fn btc_sync_form(&mut self, bump: bool) {
        let fields: &[EditField] = if bump { &BUMP_FIELDS } else { &SEND_FIELDS };
        for field in fields {
            if let Some(text) = self.form_text(*field)
                && text != self.btc_field_text(*field)
            {
                self.btc_apply_field(*field, &text);
            }
        }
    }

    /// `EN_CHANGE` of a Bitcoin edit (2026-11-18, S3 C9: the field and its text from
    /// `Cmd::Edit`; before, the control id and a read of the edit here); `false` when `field` is
    /// not one of them (the name edit has no change handler, as before).
    pub(crate) fn on_btc_edit(&mut self, field: EditField, text: &str) -> bool {
        match field {
            EditField::BtcSendTo
            | EditField::BtcSendAmount
            | EditField::BtcFeeManual
            | EditField::BtcTypedFee
            | EditField::BtcBumpManual
            | EditField::BtcBumpTyped => {
                if text != self.btc_field_text(field) {
                    self.btc_apply_field(field, text);
                    self.refresh();
                }
            }
            // Read when `저장` / `테스트` is pressed.
            EditField::BtcEsploraMainnet | EditField::BtcEsploraTestnet4 => {}
            _ => return false,
        }
        true
    }

    fn btc_set_unit(&mut self, unit: BtcAmountUnit) {
        // 2026-11-20 (S4 P10a): `btc_update` (was `btc_call` with an empty batch).
        self.btc_update(|ui, ctx| ui.set_unit(ctx, unit));
        let text = self.btc.send.amount_text.clone();
        // 2026-11-18 (S3 C9): the writes of the amount and Esplora edits are `Effect::SetField`,
        // applied at once inside this borrow (before, `controls.set_text`), so the edit's
        // `EN_CHANGE` is still not seen; the form state reads the edit back.
        self.emit(Effect::SetField {
            field: EditField::BtcSendAmount,
            text,
        });
    }

    fn btc_toggle_max(&mut self) {
        // 2026-11-20 (S4 P10a): `btc_update` (was `btc_call` with an empty batch).
        self.btc_update(crate::app_btc::BtcUi::toggle_send_max);
        self.btc_drop_stale_typed(false);
        if self.btc.send.send_max {
            self.emit(Effect::SetField {
                field: EditField::BtcSendAmount,
                text: String::new(),
            });
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

    /// Bitcoin presses (2026-11-18, S3 C9: a `BtcPress`; before, the control id, and `false` for
    /// an id that was not one of them). Every press repaints at the end, as every claimed id
    /// did.
    pub(crate) fn on_btc(&mut self, press: BtcPress) {
        match press {
            BtcPress::TabBtc => self.btc_select_tab(),
            BtcPress::SectionBtc => {
                self.btc.settings_message = None;
                self.set_screen(Screen::Settings(SettingsSection::Bitcoin));
            }
            BtcPress::Refresh => self.btc_refresh(),
            BtcPress::SendOpen => self.btc_open_send(),
            BtcPress::ReceiveOpen => {
                self.btc_open_receive();
                // 2026-11-20 (S4 P10a): after the answer of an open the receive batch asked for
                // (`AfterOpen::BtcReceiveScreen`; before, here directly).
                self.after_pending_open(crate::app_approval::AfterOpen::BtcReceiveScreen);
            }
            BtcPress::BumpOpen => self.btc_open_bump(),
            BtcPress::DiscoverRetry => self.btc_discover(false),
            BtcPress::DiscoverMore => self.btc_discover(true),
            BtcPress::DiscoverCancel => self.btc_cancel_discovery(),
            BtcPress::MismatchKeepMeta => self.btc_mismatch_keep_meta(),
            BtcPress::MismatchUseSettings => self.btc_mismatch_use_settings(),
            BtcPress::ResetTip => self.btc_reset_tip(),
            // Names and hiding (2026-11-15, `app_btc_view`).
            BtcPress::Rename => self.btc_rename_start(),
            BtcPress::RenameSave => {
                // 2026-11-18 (S3 C9): the form state (`App::form_text`, cap 64 as before).
                let label = self.form_text(EditField::BtcRename).unwrap_or_default();
                self.btc_save_rename(&label);
            }
            BtcPress::RenameCancel => self.btc_rename_cancel(),
            BtcPress::Hide => self.btc_hide_selected(),
            // 2026-11-20 (S4 P10a): `btc_update` (was `btc_call` with an empty batch).
            BtcPress::AccountAdd => self.btc_update(crate::app_btc::BtcUi::open_add_account),
            BtcPress::AccountAddCancel => self.btc_update(|ui, _| ui.close_add_account()),
            BtcPress::AccountSourceStandard => {
                self.btc_update(|ui, _| ui.set_add_source(crate::app_btc::BtcAddSource::Standard));
            }
            BtcPress::AccountSourceEvm => {
                self.btc_update(|ui, _| ui.set_add_source(crate::app_btc::BtcAddSource::EvmShared));
            }
            BtcPress::AddressModeSingle => self.btc_call(|ui, ctx| ui.set_address_mode(ctx, true)),
            BtcPress::AddressModeHd => self.btc_call(|ui, ctx| ui.set_address_mode(ctx, false)),
            BtcPress::SendAddrAck => self.btc_toggle_address_ack(),
            BtcPress::UnitBtc => self.btc_set_unit(BtcAmountUnit::Btc),
            BtcPress::UnitSats => self.btc_set_unit(BtcAmountUnit::Sats),
            BtcPress::SendMax => self.btc_toggle_max(),
            BtcPress::SendReview => {
                self.btc_sync_form(false);
                self.btc_review();
            }
            BtcPress::SendCancel => {
                self.btc.send = BtcSendForm::default();
                self.return_to(Screen::Main);
            }
            BtcPress::ResultCopy => {
                if let Some(txid) = self.btc.result {
                    self.copy_text(&txid.to_display_hex());
                }
            }
            BtcPress::ResultRetry => {
                if let Some(txid) = self.btc.result {
                    self.btc_continue(txid);
                }
            }
            BtcPress::ResultToSend => self.set_screen(Screen::BtcSend),
            BtcPress::BumpReview => {
                self.btc_sync_form(true);
                self.btc_review_bump();
            }
            BtcPress::BumpCancel => {
                self.btc.bump = BtcBumpForm::default();
                self.return_to(Screen::Main);
            }
            BtcPress::CopyAddress => self.btc_copy_address(),
            BtcPress::CardCopy => self.btc_copy_card_address(),
            BtcPress::NewAddress => self.btc_new_receive_address(),
            BtcPress::Enable => self.btc_toggle_enabled(),
            BtcPress::SetMainnet => self.btc_settings_network(BtcNetwork::Mainnet),
            BtcPress::SetTestnet4 => self.btc_settings_network(BtcNetwork::Testnet4),
            BtcPress::IdxEsplora => self.btc_set_indexer(BtcIndexer::Esplora),
            BtcPress::IdxBbRpc => self.btc_set_indexer(BtcIndexer::BbRpc),
            BtcPress::IdxBbRest => self.btc_set_indexer(BtcIndexer::BbRest),
            BtcPress::EsploraSave(net)
            | BtcPress::EsploraDefault(net)
            | BtcPress::EsploraTest(net) => {
                self.on_btc_esplora(press, net);
            }
            // The fee radios and the rows (the legacy `other` arm). Listed by name, not a
            // catch-all (2026-11-18, S3 C7-C9 review): a new `BtcPress` must be routed on
            // purpose.
            BtcPress::FeeFast
            | BtcPress::FeeNormal
            | BtcPress::FeeSlow
            | BtcPress::FeeManual
            | BtcPress::BumpFeeFast
            | BtcPress::BumpFeeNormal
            | BtcPress::BumpFeeSlow
            | BtcPress::BumpFeeManual
            | BtcPress::AccountAddType(_)
            | BtcPress::EvmAccount(_)
            | BtcPress::Account(_)
            | BtcPress::Utxo(_)
            | BtcPress::Activity(..) => self.on_btc_indexed(press),
        }
        // The wrappers repaint only when the controller acted; radios and checks must show the
        // controller state again either way. 2026-11-20 (S4 P10a): after the answer of an open a
        // press's batch asked for (`AfterOpen::Refresh`; before, here directly).
        self.after_pending_open(crate::app_approval::AfterOpen::Refresh);
    }

    /// Esplora URL rows: `저장`, `기본값으로`, `테스트` of `net` (2026-11-18, S3 C9: a `BtcPress`
    /// with its network; before, the control id matched against each network's row).
    fn on_btc_esplora(&mut self, press: BtcPress, net: BtcNetwork) {
        let field = esplora_field(net);
        match press {
            // 2026-11-20 (S4 P10a): the edit shows the stored URL after the answer of an open the
            // settings batch asked for (`AfterOpen::EsploraField`; before, here directly).
            BtcPress::EsploraSave(_) => {
                let typed = self.form_text(field).unwrap_or_default();
                self.btc_save_esplora_url(net, &typed);
                self.after_pending_open(crate::app_approval::AfterOpen::EsploraField {
                    net,
                    field,
                    saved_only: true,
                });
            }
            BtcPress::EsploraDefault(_) => {
                self.btc_default_esplora_url(net);
                self.after_pending_open(crate::app_approval::AfterOpen::EsploraField {
                    net,
                    field,
                    saved_only: false,
                });
            }
            BtcPress::EsploraTest(_) => {
                let typed = self.form_text(field).unwrap_or_default();
                self.btc_test_esplora_url(net, &typed);
            }
            _ => {}
        }
    }

    /// The Bitcoin radio and row presses (2026-11-18, S3 C9: a `BtcPress`, rows resolved against
    /// the lists rebuilt now as before; an address-type radio carries its `ScriptType`).
    fn on_btc_indexed(&mut self, press: BtcPress) {
        if let Some((choice, bump)) = fee_choice(press) {
            self.btc_call(|ui, ctx| {
                ui.set_fee_choice(ctx, choice, bump);
                // The send form's preview is asked again when older than 60 s (2026-11-10).
                if bump {
                    Vec::new()
                } else {
                    ui.quote_if_stale(ctx)
                }
            });
            // 2026-11-20 (S4 P10a): after the answer of an open the batch asked for
            // (`AfterOpen::BtcDropStaleTyped`; before, here directly).
            self.after_pending_open(crate::app_approval::AfterOpen::BtcDropStaleTyped(bump));
            return;
        }
        match press {
            BtcPress::AccountAddType(script_type) => {
                self.btc_call(|ui, ctx| ui.add_account(ctx, script_type));
            }
            BtcPress::EvmAccount(Row(row)) => {
                let index = self.btc_ctx().evm_indices().get(usize::from(row)).copied();
                if let Some(index) = index {
                    // 2026-11-20 (S4 P10a): `btc_update` (was `btc_call` with an empty batch).
                    self.btc_update(|ui, ctx| ui.set_add_evm_index(ctx, index));
                }
            }
            BtcPress::Account(Row(row)) => {
                // A choice closes the drop-down (2026-11-11).
                self.account_menu = None;
                // The drop-down lists the visible accounts only (2026-11-15).
                let account = self
                    .btc_visible_rows()
                    .get(usize::from(row))
                    .map(|row| row.id);
                if let Some(account) = account {
                    self.btc.rename = None;
                    self.btc_call(|ui, ctx| ui.select_account(ctx, account));
                }
            }
            BtcPress::Utxo(Row(row)) => {
                let utxo = {
                    let ctx = self.btc_ctx();
                    self.btc.utxos(&ctx).get(usize::from(row)).copied()
                };
                if let Some(utxo) = utxo
                    && !utxo.in_flight
                {
                    self.btc_freeze(utxo.outpoint, utxo.frozen.is_none());
                }
            }
            BtcPress::Activity(Row(row), action) => self.on_btc_activity(usize::from(row), action),
            _ => {}
        }
    }

    /// An activity row's button (S3 C9: split out of `on_btc_indexed`, same order).
    fn on_btc_activity(&mut self, row: usize, action: BtcActivityAction) {
        let rows = {
            let ctx = self.btc_ctx();
            self.btc.activity_rows(&ctx)
        };
        let Some(view) = rows.get(row) else {
            return;
        };
        if action == BtcActivityAction::CopyHash {
            let text = view.txid.clone();
            self.copy_text(&text);
            return;
        }
        if action == BtcActivityAction::SaveAddress {
            self.save_activity_address(crate::meta::BookChain::Btc, row);
            return;
        }
        let Ok(txid) = Txid::from_display_hex(&view.txid) else {
            return;
        };
        match action {
            BtcActivityAction::Bump if view.can_bump => self.btc_open_bump(),
            BtcActivityAction::Rebroadcast if view.can_rebroadcast => self.btc_rebroadcast(txid),
            BtcActivityAction::Abandon if view.can_abandon => self.btc_abandon(txid),
            BtcActivityAction::Esplora if view.can_esplora => self.btc_esplora_broadcast(txid),
            BtcActivityAction::Continue if view.can_continue => self.btc_continue(txid),
            BtcActivityAction::Cancel if view.can_continue => self.btc_cancel_signed(txid),
            _ => {}
        }
    }

    /// Test adapter (S3 C9, plan §3.2): presses Bitcoin control `id` directly, as the tests did
    /// before; `false` when `id` is not one.
    #[cfg(test)]
    pub(crate) fn on_btc_command(&mut self, id: u16) -> bool {
        self.press_family(
            id,
            |press| match press {
                yw_engine::cmd::Press::Btc(press) => Some(press),
                _ => None,
            },
            |app, press| {
                app.on_btc(press);
                true
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::mpsc;

    use yw_core::btc::{BtcMeta, BtcNetwork, Sats};
    use yw_engine::form::EditField;
    use yw_platform::http::HttpsUrl;

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
    /// `super::fee_choice` of each radio's press equals `fee_choice_of` of its id, which pairs
    /// `fee_ids` with the drawing order `FEE_CHOICES`.
    #[test]
    fn fee_presses_match_the_drawn_radio_order() {
        use crate::ui::screens_btc::{fee_choice_of, fee_ids};
        for bump in [false, true] {
            for id in fee_ids(bump) {
                let press = ids::press_of(id).unwrap();
                assert_eq!(super::fee_choice(press), fee_choice_of(id), "id {id}");
                assert_eq!(fee_choice_of(id).map(|(_, b)| b), Some(bump), "id {id}");
            }
        }
    }
}
