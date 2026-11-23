//! Command and edit-change handling of the Solana screens (ids in `ui::screens_sol::ids`).

use crate::cmd::{Row, SolPress, SolScanAction};
use crate::effect::Effect;
use crate::form::EditField;

use crate::meta::Tab;
use crate::network::SolCluster;
use crate::screen::SettingsSection;
use crate::wallet::app_sol::SolSendForm;
use crate::wallet::{Screen, Wallet};

/// Fixed texts of the Solana commands (spec/07, spec/14).
pub mod text {
    yw_core::texts! {
        FEE_RANGE = "Solana 수수료 설정 범위를 벗어났습니다(수수료 상한 10,000–10,000,000, CU 가격 상한 0–100,000,000)."
            / "The Solana fee settings are out of range (fee cap 10,000–10,000,000, CU price cap 0–100,000,000).";
    }
}

impl Wallet {
    /// The text of a Solana edit for a handler (2026-11-18, S3 C8: the form state,
    /// `Wallet::form_text`; before, a read of the edit with the module's cap 256, now
    /// `EditField::cap`).
    fn sol_edit_text(&self, field: EditField) -> String {
        self.form_text(field).unwrap_or_default()
    }

    /// `EN_CHANGE` of a Solana edit (2026-11-18, S3 C8: the field and its text from
    /// `Cmd::Edit`; before, the control id and a read of the edit here); `false` when `field` is
    /// not one of them. A send-form edit is validated by the send timer (`Wallet::on_send_timer`):
    /// at once when the text is a whole address or amount, after the typing pause otherwise.
    pub(crate) fn on_sol_edit(&mut self, field: EditField, text: &str) -> bool {
        let now = self.clock.now_ms();
        match field {
            EditField::SolSendTo => {
                if self.sol.send.moving.is_none() {
                    text.clone_into(&mut self.sol.send.to_text);
                    self.sol.send.dirty_ms = Some(now);
                    self.arm_send_timer(self.sol.send.edit_wait_ms(true));
                }
            }
            EditField::SolSendAmount => {
                text.clone_into(&mut self.sol.send.amount_text);
                self.sol.send.dirty_ms = Some(now);
                self.arm_send_timer(self.sol.send.edit_wait_ms(false));
            }
            _ => return false,
        }
        true
    }

    fn sol_set_cluster(&mut self, cluster: SolCluster) {
        if self.settings.solana.cluster == cluster {
            return;
        }
        let mut settings = self.settings.clone();
        settings.solana.cluster = cluster;
        self.save_settings(settings, "solana");
        self.sol.next_balance_ms = 0;
        self.sol.send = SolSendForm::default();
        self.sol.scan = crate::wallet::app_sol::SolScanState::default();
    }

    fn sol_save_fees(&mut self, defaults: bool) {
        let (fee, price) = if defaults {
            (
                yw_core::sol::fee::DEFAULT_MAX_FEE_LAMPORTS,
                yw_core::sol::fee::DEFAULT_MAX_CU_PRICE_MICRO,
            )
        } else {
            let parse = |text: String| crate::network::parse_decimal_u64(text.trim());
            let fee = parse(self.sol_edit_text(EditField::SolFeeCap));
            let price_text = self.sol_edit_text(EditField::SolCuPrice);
            let price = if price_text.trim() == "0" {
                Some(0)
            } else {
                parse(price_text)
            };
            let (fee_min, fee_max) = yw_core::sol::fee::MAX_FEE_RANGE;
            let (_, price_max) = yw_core::sol::fee::MAX_CU_PRICE_RANGE;
            match (fee, price) {
                (Some(fee), Some(price))
                    if (fee_min..=fee_max).contains(&fee) && price <= price_max =>
                {
                    (fee, price)
                }
                _ => {
                    self.info = Some(text::FEE_RANGE.get(self.settings.language).to_owned());
                    self.refresh();
                    return;
                }
            }
        };
        let mut settings = self.settings.clone();
        settings.solana.max_fee_lamports = fee;
        settings.solana.max_cu_price_micro = price;
        self.save_settings(settings, "solana");
    }

    /// Solana presses (2026-11-18, S3 C8: a `SolPress`; before, the control id, and `false` for
    /// an id that was not one of them).
    pub(crate) fn on_sol(&mut self, press: SolPress) {
        match press {
            SolPress::TabEvm => self.sol_select_tab(Tab::Evm),
            SolPress::TabSol => self.sol_select_tab(Tab::Sol),
            SolPress::ClusterMainnet | SolPress::SetMainnet => {
                self.sol_set_cluster(SolCluster::Mainnet);
            }
            SolPress::ClusterDevnet | SolPress::SetDevnet => {
                self.sol_set_cluster(SolCluster::Devnet);
            }
            SolPress::Refresh => {
                self.sol_refresh_balances();
                self.refresh();
            }
            SolPress::SendOpen => self.sol_open_send(),
            SolPress::ReceiveOpen => self.set_screen(Screen::SolReceive),
            SolPress::Rename => {
                self.sol.rename = self.sol_selected().map(|(id, ..)| id);
                self.refresh();
            }
            SolPress::RenameSave => {
                let text = self.sol_edit_text(EditField::SolRename);
                self.sol_save_rename(&text);
            }
            SolPress::RenameCancel => {
                self.sol.rename = None;
                self.refresh();
            }
            SolPress::Hide => self.sol_hide_selected(),
            SolPress::AddAccount => {
                self.sol_add_account_clicked();
                self.refresh();
            }
            // `스캔 결과로` after a move opens the kept results.
            SolPress::ScanOpen | SolPress::ScanBack => self.sol_open_scan(),
            SolPress::CopyAddress => self.sol_copy_address(),
            SolPress::SendMax => self.sol_fill_max(),
            SolPress::SendReview => self.sol_review(),
            SolPress::SendAgain => self.sol_send_again(),
            SolPress::SendNow => self.sol_send_now(),
            // The signature is the transaction id: public data, for an explorer.
            SolPress::ResultCopy => {
                if let Some((_, signature)) = self.sol.sent {
                    self.copy_text(&yw_core::codec::base58::base58_encode(&signature));
                }
            }
            SolPress::SendCancel => {
                self.sol.send = SolSendForm::default();
                self.return_to(Screen::Main);
            }
            SolPress::SendPick => {
                self.sol.send.picker = !self.sol.send.picker;
                self.refresh();
            }
            SolPress::SectionSol => self.set_screen(Screen::Settings(SettingsSection::Solana)),
            SolPress::FeeSave => self.sol_save_fees(false),
            SolPress::FeeDefault => self.sol_save_fees(true),
            SolPress::ScanStart => self.sol_start_scan(),
            SolPress::ScanAgain => self.sol_scan_again(),
            SolPress::TokenHiddenToggle => {
                self.sol.show_hidden_tokens = !self.sol.show_hidden_tokens;
                self.refresh();
            }
            SolPress::Account(_)
            | SolPress::SendAsset(_)
            | SolPress::TokenHide(_)
            | SolPress::TokenCopy(_)
            | SolPress::ActivityCopy(_)
            | SolPress::TokenSend(_)
            | SolPress::SendPickRow(_)
            | SolPress::ScanRow(..) => self.on_sol_indexed(press),
        }
    }

    /// The Solana row presses (2026-11-18, S3 C8: a `SolPress` row, resolved against the lists
    /// rebuilt now as before; the token card's `숨긴 토큰` toggle, which was checked here between
    /// the rows, is an arm of `on_sol`).
    fn on_sol_indexed(&mut self, press: SolPress) {
        match press {
            SolPress::Account(Row(row)) => {
                // A choice closes the drop-down (2026-11-11).
                self.account_menu = None;
                self.sol_select_account(usize::from(row));
            }
            SolPress::SendAsset(Row(index)) => self.sol_select_asset(usize::from(index)),
            SolPress::TokenHide(Row(index)) => self.toggle_sol_token_hidden(usize::from(index)),
            SolPress::TokenCopy(Row(index)) => {
                // The token card's `주소 복사`: the allowlist row's whole mint (2026-11-11).
                if let Some(entry) =
                    yw_core::sol::template::spl_entries(self.sol_cluster()).nth(usize::from(index))
                {
                    self.copy_address_text(&entry.mint.to_base58());
                }
            }
            SolPress::ActivityCopy(Row(row)) => {
                if let Some(tx_id) = self.sol_activity_tx_ids().get(usize::from(row)) {
                    self.copy_text(tx_id);
                }
            }
            SolPress::TokenSend(Row(index)) => {
                // Token card "보내기": the send form with that token selected (SOL is asset 0).
                self.sol_open_send();
                self.sol_select_asset(usize::from(index).saturating_add(1));
            }
            SolPress::SendPickRow(Row(row)) => {
                if let Some((_, address)) = self.sol_picker_entries().get(usize::from(row)) {
                    self.sol.send.to_text = address.to_base58();
                    self.sol.send.picker = false;
                    // 2026-11-18 (S3 C8): the write is `Effect::SetField`, applied at once inside
                    // this borrow (before, `controls.set_text`), so the edit's `EN_CHANGE` is
                    // still not seen; the form state reads the edit back.
                    // (2026-11-21, S4 W3: the text is read first, as before the call.)
                    let text = self.sol.send.to_text.clone();
                    self.emit(Effect::SetField {
                        field: EditField::SolSendTo,
                        text,
                    });
                    self.sol_validate_send();
                }
            }
            SolPress::ScanRow(Row(row), SolScanAction::Add) => self.sol_scan_add(usize::from(row)),
            SolPress::ScanRow(Row(row), SolScanAction::Move) => {
                self.sol_scan_move(usize::from(row));
            }
            _ => {}
        }
    }
}
