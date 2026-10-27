//! Command and edit-change handling of the Solana screens (ids in `ui::screens_sol::ids`).

use crate::app::{App, Screen, SettingsSection};
use crate::app_sol::SolSendForm;
use crate::meta::Tab;
use crate::network::SolCluster;
use crate::ui::screens_sol::ids;

const TEXT_MAX: usize = 256;

fn offset(id: u16, base: u16, span: u16) -> Option<u16> {
    id.checked_sub(base).filter(|offset| *offset < span)
}

impl App {
    fn sol_edit_text(&self, id: u16) -> String {
        self.controls.text(id, TEXT_MAX).unwrap_or_default()
    }

    /// `EN_CHANGE` of a Solana edit; `false` when `id` is not one of them.
    pub fn on_sol_edit_change(&mut self, id: u16) -> bool {
        let now = yw_win::time::monotonic_ms();
        match id {
            ids::SEND_TO_EDIT => {
                if self.sol.send.moving.is_none() {
                    self.sol.send.to_text = self.sol_edit_text(id);
                    self.sol.send.dirty_ms = Some(now);
                }
            }
            ids::SEND_AMOUNT_EDIT => {
                self.sol.send.amount_text = self.sol_edit_text(id);
                self.sol.send.dirty_ms = Some(now);
            }
            ids::BOOK_ADDR_EDIT => self.sol.book.address = self.sol_edit_text(id),
            ids::BOOK_LABEL_EDIT => self.sol.book.label = self.sol_edit_text(id),
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
        self.sol.scan = crate::app_sol::SolScanState::default();
    }

    fn sol_save_fees(&mut self, defaults: bool) {
        let (fee, price) = if defaults {
            (
                yw_core::sol::fee::DEFAULT_MAX_FEE_LAMPORTS,
                yw_core::sol::fee::DEFAULT_MAX_CU_PRICE_MICRO,
            )
        } else {
            let parse = |text: String| crate::network::parse_decimal_u64(text.trim());
            let fee = parse(self.sol_edit_text(ids::FEE_CAP_EDIT));
            let price_text = self.sol_edit_text(ids::CU_PRICE_EDIT);
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
                    self.info = Some(
                        "Solana 수수료 설정 범위를 벗어났습니다(수수료 상한 10,000–10,000,000, CU 가격 상한 0–100,000,000)."
                            .to_owned(),
                    );
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

    /// Solana commands; `false` when `id` is not one of them.
    pub fn on_sol_command(&mut self, id: u16) -> bool {
        match id {
            ids::TAB_EVM => self.sol_select_tab(Tab::Evm),
            ids::TAB_SOL => self.sol_select_tab(Tab::Sol),
            ids::CLUSTER_MAINNET | ids::SET_MAINNET => self.sol_set_cluster(SolCluster::Mainnet),
            ids::CLUSTER_DEVNET | ids::SET_DEVNET => self.sol_set_cluster(SolCluster::Devnet),
            ids::REFRESH => {
                self.sol_refresh_balances();
                self.refresh();
            }
            ids::SEND_OPEN => self.sol_open_send(),
            ids::RECEIVE_OPEN => self.set_screen(Screen::SolReceive),
            ids::RENAME => {
                self.sol.rename = self.sol_selected().map(|(index, ..)| index);
                self.refresh();
            }
            ids::RENAME_SAVE => {
                let text = self.sol_edit_text(ids::RENAME_EDIT);
                self.sol_save_rename(&text);
            }
            ids::RENAME_CANCEL => {
                self.sol.rename = None;
                self.refresh();
            }
            ids::HIDE => self.sol_hide_selected(),
            ids::ADD_ACCOUNT => {
                self.sol_add_account();
                self.refresh();
            }
            ids::SCAN_OPEN => self.sol_open_scan(),
            ids::COPY_ADDRESS => self.sol_copy_address(),
            ids::SEND_MAX => self.sol_fill_max(),
            ids::SEND_REVIEW => self.sol_review(),
            ids::SEND_AGAIN => self.sol_send_again(),
            ids::SEND_CANCEL => {
                self.sol.send = SolSendForm::default();
                self.set_screen(Screen::Main);
            }
            ids::SEND_PICK => {
                self.sol.send.picker = !self.sol.send.picker;
                self.refresh();
            }
            ids::SECTION_SOL => self.set_screen(Screen::Settings(SettingsSection::Solana)),
            ids::FEE_SAVE => self.sol_save_fees(false),
            ids::FEE_DEFAULT => self.sol_save_fees(true),
            ids::SCAN_START => self.sol_start_scan(),
            ids::BOOK_SAVE => self.sol_save_book(),
            ids::BOOK_VERIFIED => {
                self.sol.book.verified = !self.sol.book.verified;
                self.refresh();
            }
            other => return self.on_sol_indexed(other),
        }
        true
    }

    fn on_sol_indexed(&mut self, id: u16) -> bool {
        if let Some(row) = offset(id, ids::ACCOUNT_BASE, ids::ACCOUNT_SPAN) {
            self.sol_select_account(usize::from(row));
            return true;
        }
        if let Some(row) = offset(id, ids::SEND_PICK_BASE, ids::SEND_PICK_SPAN) {
            if let Some((_, address)) = self.sol_picker_entries().get(usize::from(row)) {
                self.sol.send.to_text = address.to_base58();
                self.sol.send.picker = false;
                self.controls
                    .set_text(ids::SEND_TO_EDIT, &self.sol.send.to_text);
                self.sol_validate_send();
            }
            return true;
        }
        if let Some(position) = offset(id, ids::SCAN_ROW_BASE, ids::SCAN_ROW_SPAN) {
            let row = usize::from(position / 2);
            if position % 2 == 0 {
                self.sol_scan_add(row);
            } else {
                self.sol_scan_move(row);
            }
            return true;
        }
        if let Some(row) = offset(id, ids::BOOK_ROW_BASE, ids::BOOK_ROW_SPAN) {
            self.sol_delete_book(usize::from(row));
            return true;
        }
        false
    }
}
