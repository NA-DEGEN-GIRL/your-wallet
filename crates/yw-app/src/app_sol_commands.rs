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
        if let Some(index) = offset(id, ids::SEND_ASSET_BASE, ids::SEND_ASSET_SPAN) {
            self.sol_select_asset(usize::from(index));
            return true;
        }
        if let Some(index) = offset(id, ids::TOKEN_SEND_BASE, ids::TOKEN_SEND_SPAN) {
            // Token card "보내기": the send form with that token selected (SOL is asset 0).
            self.sol_open_send();
            self.sol_select_asset(usize::from(index).saturating_add(1));
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
        match ids::scan_action(id) {
            Some(ids::ScanAction::Add(row)) => {
                self.sol_scan_add(row);
                return true;
            }
            Some(ids::ScanAction::Move(row)) => {
                self.sol_scan_move(row);
                return true;
            }
            None => {}
        }
        if let Some(row) = offset(id, ids::BOOK_ROW_BASE, ids::BOOK_ROW_SPAN) {
            self.sol_delete_book(usize::from(row));
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
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
        app.sol.scan.rows = rows;
        app.screen = Screen::SolScan;
        app
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
}
