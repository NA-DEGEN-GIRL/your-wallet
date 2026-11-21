//! Command and edit-change handling of the Bitcoin screens (ids in `ui::screens_btc::ids`): every
//! action goes through the `App::btc_*` wrappers of [`crate::app_btc`] (controller + actions).
//! Buttons, checks and radios act on the controller state, not on the control's own check
//! state, so a `WM_COMMAND` without a click behaves the same.

use yw_core::btc::{BtcNetwork, Txid};
use yw_engine::cmd::{BtcActivityAction, BtcPress, Row};
use yw_engine::effect::Effect;
use yw_engine::form::EditField;

use crate::app::{App, Screen, Wallet};
use crate::app_btc::{BtcAction, BtcAmountUnit, BtcBumpForm, BtcFeeChoice, BtcSendForm};
use crate::btc::{app_network, core_network};
use crate::settings::BtcIndexer;
use yw_engine::screen::SettingsSection;

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

impl Wallet {
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
}

impl App {
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
    use crate::ui::screens_btc::ids;

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

/// The tests that build an `App` (2026-11-21, S4 W0, spec/09 §2.1), in
/// `app/tests/btc_commands.rs`: a child of this module, so that they keep its access.
#[cfg(test)]
#[path = "app/tests/btc_commands.rs"]
mod app_tests;
