//! Command and edit-change handling of the EVM screens (ids in `ui::screens_evm::ids`).

use yw_core::evm::chain::builtin_chain;
use yw_engine::cmd::{ChainRowAction, EvmActivityAction, EvmPress, Row};
use yw_engine::effect::Effect;
use yw_engine::form::{CredField, EditField};

use crate::app::{AppMode, Confirm, Screen, Wallet};
use crate::app_evm::{SendAsset, SendForm, hash_text};
use crate::flow::evm::prepare::ReplaceMode;
use crate::network::NetworkId;
use yw_engine::screen::SettingsSection;

impl Wallet {
    /// The text of an EVM edit for a handler (2026-11-18, S3 C10: the form state,
    /// `Wallet::form_text`; before, a read of the edit with the module's cap 512, now
    /// `EditField::cap`).
    fn evm_edit_text(&self, field: EditField) -> String {
        self.form_text(field).unwrap_or_default()
    }

    /// `EN_CHANGE` of an EVM edit: keep the text (controls may be recreated) and leave the
    /// send-form validation to the send timer (spec/04 §2.7, `Wallet::on_send_timer`: at once for
    /// a whole address or amount, 500 ms after typing stops otherwise). `검토` is off until that
    /// validation runs; the first edit of a burst repaints it so (the picker, whose rows follow
    /// the text, keeps its controls until the validation).
    /// 2026-11-18 (S3 C10): the field and its text from `Cmd::Edit` (or the form state for
    /// `저장`); `false` when `field` is not one of them. Before, `on_edit_change(id)` read the
    /// edit by id, and its `_ => {}` swallowed every other edit's change; nothing handles those
    /// now either.
    pub(crate) fn on_evm_edit(&mut self, field: EditField, text: &str) -> bool {
        let now = self.clock.now_ms();
        match field {
            EditField::EvmSendTo | EditField::EvmSendAmount => {
                let form = &mut self.evm.send;
                if field == EditField::EvmSendTo {
                    text.clone_into(&mut form.to_text);
                } else {
                    text.clone_into(&mut form.amount_text);
                }
                let first = form.dirty_ms.replace(now).is_none();
                if first && !form.picker {
                    self.refresh();
                }
                self.arm_send_timer(self.send_edit_wait_ms(field == EditField::EvmSendTo));
            }
            EditField::EvmTokenAddress => text.clone_into(&mut self.evm.token.address),
            EditField::EvmTokenLabel => text.clone_into(&mut self.evm.token.label),
            EditField::EvmChainId
            | EditField::EvmChainName
            | EditField::EvmChainSymbol
            | EditField::EvmChainDecimals
            | EditField::EvmChainExplorer => {
                if let Some(form) = self.evm.chain_form.as_mut() {
                    let slot = match field {
                        EditField::EvmChainId => &mut form.chain_id,
                        EditField::EvmChainName => &mut form.name,
                        EditField::EvmChainSymbol => &mut form.symbol,
                        EditField::EvmChainDecimals => &mut form.decimals,
                        _ => &mut form.explorer,
                    };
                    text.clone_into(slot);
                }
            }
            EditField::EvmCapFee | EditField::EvmCapTip | EditField::EvmCapTotal => {
                if let Some(caps) = self.evm.caps.as_mut() {
                    match field {
                        EditField::EvmCapFee => text.clone_into(&mut caps.fee),
                        EditField::EvmCapTip => text.clone_into(&mut caps.tip),
                        _ => text.clone_into(&mut caps.total),
                    }
                }
            }
            _ => return false,
        }
        true
    }

    /// The EVM edit handler run again over `fields` with their form-state text (S17 and the
    /// fee caps' `저장`: the drafts are taken again before the save, as before S3).
    fn evm_reread(&mut self, fields: &[EditField]) {
        for &field in fields {
            let text = self.evm_edit_text(field);
            self.on_evm_edit(field, &text);
        }
    }

    /// EVM presses (2026-11-18, S3 C10: an `EvmPress`; before, the control id, and `false` for
    /// an id that was not one of them; a row press past its list still does nothing).
    #[expect(clippy::too_many_lines, reason = "one arm per EVM press")]
    pub(crate) fn on_evm(&mut self, press: EvmPress) {
        match press {
            EvmPress::SendOpen => {
                if matches!(self.mode, AppMode::Unlocked { .. }) {
                    self.open_send();
                }
            }
            EvmPress::ReceiveOpen => self.set_screen(Screen::Receive),
            EvmPress::Refresh => {
                self.refresh_balances();
                self.schedule_tracking(true);
            }
            EvmPress::BookOpen => self.set_screen(Screen::AddressBook),
            EvmPress::ActivityMore => {
                self.activity_all = !self.activity_all;
                self.refresh();
            }
            EvmPress::TokenOpen => {
                self.evm.token = crate::app_evm::TokenForm::default();
                self.set_screen(Screen::TokenAdd);
            }
            EvmPress::RepinSettings | EvmPress::SectionChains => {
                self.set_screen(Screen::Settings(SettingsSection::Chains));
            }
            EvmPress::SendMax => self.fill_max(),
            EvmPress::SendPick => {
                let form = &mut self.evm.send;
                form.picker = !form.picker;
                form.picker_filter.clone_from(&form.to_text);
                self.refresh();
            }
            EvmPress::SendHiddenToggle => {
                self.evm.send_show_hidden = !self.evm.send_show_hidden;
                self.refresh();
            }
            EvmPress::TokenHideZero(checked) => {
                let on = checked.unwrap_or(!self.evm_hide_zero());
                self.set_evm_hide_zero(on);
            }
            EvmPress::TokenHiddenToggle => {
                self.evm.show_hidden_tokens = !self.evm.show_hidden_tokens;
                self.refresh();
            }
            EvmPress::SendAck(checked) => {
                self.evm.send.ack = checked.unwrap_or(false);
                self.refresh();
            }
            EvmPress::SendReview => {
                self.evm.send.to_text = self.evm_edit_text(EditField::EvmSendTo);
                self.evm.send.amount_text = self.evm_edit_text(EditField::EvmSendAmount);
                self.review_send();
            }
            EvmPress::SendCancel => {
                self.evm.send = SendForm::default();
                self.return_to(Screen::Main);
            }
            EvmPress::CopyAddress => {
                // S12 and the S10 account card: the selected account (one path for both).
                if let Some((address, ..)) = self.selected_account() {
                    let text = address.to_checksum();
                    self.copy_address_text(&text);
                }
            }
            EvmPress::NetworkPicker => {
                self.evm.network_picker = !self.evm.network_picker;
                // One drop-down at a time.
                self.account_menu = None;
                self.refresh();
            }
            EvmPress::QrEip681 | EvmPress::QrPlain => {
                self.evm.receive_qr = if press == EvmPress::QrPlain {
                    crate::ui::qr::EvmQrKind::PlainAddress
                } else {
                    crate::ui::qr::EvmQrKind::Eip681
                };
                self.refresh();
            }
            EvmPress::TokenLookup => {
                self.evm.token.address = self.evm_edit_text(EditField::EvmTokenAddress);
                self.lookup_token();
            }
            EvmPress::TokenSave => {
                self.evm.token.label = self.evm_edit_text(EditField::EvmTokenLabel);
                self.save_token();
            }
            EvmPress::ChainAdd => self.open_chain_form(None),
            EvmPress::ChainSimAuto | EvmPress::ChainSimUnsupported => {
                if let Some(form) = self.evm.chain_form.as_mut() {
                    form.unsupported = press == EvmPress::ChainSimUnsupported;
                }
            }
            EvmPress::ChainSave => {
                self.evm_reread(&[
                    EditField::EvmChainId,
                    EditField::EvmChainName,
                    EditField::EvmChainSymbol,
                    EditField::EvmChainDecimals,
                    EditField::EvmChainExplorer,
                ]);
                // 2026-11-18 (S3 C10): the units the shell read with the press (`PressInput`,
                // wiped with it; empty when the edit did not exist, as a read of a missing edit);
                // before, a read of the edit here. Decoded as before (`from_utf16_lossy`); the
                // edit is emptied after the save (`Effect::ClearCred`; before,
                // `controls.clear_text`).
                let units = self.take_cred(CredField::ChainRpc);
                let rpc =
                    yw_core::secret::Zeroizing::new(String::from_utf16_lossy(units.as_slice()));
                drop(units);
                self.save_chain_form(&rpc);
                self.emit(Effect::ClearCred {
                    field: CredField::ChainRpc,
                });
            }
            EvmPress::ChainCancel => {
                self.evm.chain_form = None;
                self.set_screen(Screen::Settings(SettingsSection::Chains));
            }
            EvmPress::CapsSave | EvmPress::CapsDefault => {
                self.evm_reread(&[
                    EditField::EvmCapFee,
                    EditField::EvmCapTip,
                    EditField::EvmCapTotal,
                ]);
                self.save_caps(press == EvmPress::CapsDefault);
            }
            EvmPress::RepinCheck(checked) => {
                let checked = checked.unwrap_or(false);
                if let Some(repin) = self.evm.repin.as_mut() {
                    repin.checked = checked;
                }
                self.refresh();
            }
            EvmPress::SendAsset(_)
            | EvmPress::TokenSend(_)
            | EvmPress::TokenCopy(_)
            | EvmPress::TokenToggleHidden(_)
            | EvmPress::TokenDelete(_)
            | EvmPress::PickRecipient(_)
            | EvmPress::ChainRow(..)
            | EvmPress::CapsChain(_)
            | EvmPress::Activity(..) => self.on_evm_indexed(press),
        }
    }

    /// `{기호} 보내기` of token row `index`: S11 with that token chosen (the form's checks,
    /// review and approval are the usual ones).
    fn send_token_row(&mut self, chain_id: u64, index: usize) {
        if matches!(self.mode, AppMode::Unlocked { .. })
            && let Some((address, ..)) = self.chain_tokens(chain_id).get(index)
        {
            let asset = SendAsset::Token(*address);
            self.open_send();
            self.choose_send_asset(asset);
        }
    }

    /// The asset of send radio `index` (0 = the native asset, then the chain's tokens).
    fn send_asset_at(&self, chain_id: u64, index: usize) -> SendAsset {
        if index == 0 {
            return SendAsset::Native;
        }
        self.chain_tokens(chain_id)
            .get(index.saturating_sub(1))
            .map_or(SendAsset::Native, |(address, ..)| {
                SendAsset::Token(*address)
            })
    }

    /// The send form's asset: set, the quote and contract check dropped, the form checked again.
    fn choose_send_asset(&mut self, asset: SendAsset) {
        self.evm.send.asset = asset;
        self.evm.send.quote = None;
        self.evm.send.contract = None;
        self.validate_send(true);
    }

    /// The row presses (2026-11-18, S3 C10: the press with its row; before, the control id
    /// and its offset in each range, checked in this order).
    fn on_evm_indexed(&mut self, press: EvmPress) {
        let chain_id = self.settings.evm_chain_id;
        match press {
            EvmPress::SendAsset(Row(index)) => {
                let asset = self.send_asset_at(chain_id, usize::from(index));
                self.choose_send_asset(asset);
            }
            EvmPress::TokenSend(Row(index)) => self.send_token_row(chain_id, usize::from(index)),
            EvmPress::TokenCopy(Row(index)) => {
                // The token card's `주소 복사`: the whole contract, checksum case (2026-11-11).
                if let Some((address, ..)) = self.chain_tokens(chain_id).get(usize::from(index)) {
                    let text = address.to_checksum();
                    self.copy_address_text(&text);
                }
            }
            EvmPress::TokenToggleHidden(Row(row)) => {
                self.toggle_evm_token_hidden(usize::from(row));
            }
            EvmPress::TokenDelete(Row(row)) => self.request_delete_token(usize::from(row)),
            EvmPress::PickRecipient(Row(index)) => {
                // The rows on screen (their filter, not text typed since): the clicked row's
                // address.
                if let Some(address) = self.picker_entries().get(usize::from(index)).copied() {
                    self.evm.send.to_text = address.to_checksum();
                    self.evm.send.picker = false;
                    // 2026-11-18 (S3 C10): the write is `Effect::SetField`, applied at once
                    // inside this borrow (before, `controls.set_text`), so the edit's
                    // `EN_CHANGE` is still not seen; the form state reads the edit back.
                    // (2026-11-21, S4 W3: the text is read first, as before the call.)
                    let text = self.evm.send.to_text.clone();
                    self.emit(Effect::SetField {
                        field: EditField::EvmSendTo,
                        text,
                    });
                    self.validate_send(true);
                }
            }
            EvmPress::ChainRow(Row(row), action) => {
                let chains = self.settings.registered_evm();
                if let Some(chain) = chains.get(usize::from(row)).copied() {
                    match action {
                        ChainRowAction::Edit if builtin_chain(chain).is_none() => {
                            self.open_chain_form(Some(chain));
                        }
                        ChainRowAction::Delete if builtin_chain(chain).is_none() => {
                            self.request_delete_chain(chain);
                        }
                        ChainRowAction::Repin => self.start_repin(chain),
                        ChainRowAction::Edit | ChainRowAction::Delete => {}
                    }
                }
            }
            EvmPress::CapsChain(Row(index)) => {
                if let Some(chain) = self
                    .settings
                    .registered_evm()
                    .get(usize::from(index))
                    .copied()
                {
                    self.select_caps_chain(chain);
                }
            }
            EvmPress::Activity(Row(index), action) => {
                let rows = self.activity_rows();
                let Some(row) = rows.get(usize::from(index)).cloned() else {
                    return;
                };
                match action {
                    EvmActivityAction::CopyHash => self.copy_text(&row.hash),
                    EvmActivityAction::SpeedUp => {
                        if let Some(key) = row.open {
                            self.replace_group(key, ReplaceMode::SpeedUp);
                        }
                    }
                    EvmActivityAction::Cancel => {
                        if let Some(key) = row.open {
                            self.replace_group(key, ReplaceMode::Cancel);
                        }
                    }
                    EvmActivityAction::Resend => {
                        if let Some(key) = row.open {
                            self.resend_group(key);
                        }
                    }
                    EvmActivityAction::Discard => {
                        if let Some(key) = row.open {
                            self.evm.discard = Some(key);
                            self.set_screen(Screen::Confirm(Confirm::Discard));
                        }
                    }
                    // `탐색기 링크 복사` / `탐색기에서 열기` (2026-11-11: the S15 "블록 탐색기"
                    // templates, `app_explorer`).
                    EvmActivityAction::CopyExplorerLink => {
                        self.copy_explorer_tx(NetworkId::Eip155(chain_id), &row.hash);
                    }
                    EvmActivityAction::OpenExplorer => {
                        self.open_explorer_tx(NetworkId::Eip155(chain_id), &row.hash);
                    }
                    EvmActivityAction::SaveAddress => {
                        self.save_activity_address(crate::meta::BookChain::Evm, usize::from(index));
                    }
                }
            }
            // The fixed presses are `on_evm`'s.
            _ => {}
        }
    }

    /// The hash text of a record (shared by screens).
    #[must_use]
    pub fn record_hash(record: &yw_core::journal::evm::EvmRecord) -> String {
        hash_text(&record.tx_hash)
    }
}
