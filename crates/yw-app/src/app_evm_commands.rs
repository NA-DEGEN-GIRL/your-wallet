//! Command and edit-change handling of the EVM screens (ids in `ui::screens_evm::ids`).

use yw_core::evm::chain::builtin_chain;

use crate::app::{App, AppMode, Confirm, Screen, SettingsSection};
use crate::app_evm::{SendAsset, SendForm, hash_text};
use crate::flow::evm::prepare::ReplaceMode;
use crate::meta::BookEntry;
use crate::ui::screens_evm::ids;

const TEXT_MAX: usize = 512;

fn offset(id: u16, base: u16, span: u16) -> Option<u16> {
    id.checked_sub(base).filter(|offset| *offset < span)
}

impl App {
    fn edit_text(&self, id: u16) -> String {
        self.controls.text(id, TEXT_MAX).unwrap_or_default()
    }

    /// `EN_CHANGE` of an EVM edit: keep the text (controls may be recreated) and debounce the
    /// send-form validation (spec/04 §2.7: 500 ms after typing stops).
    pub fn on_edit_change(&mut self, id: u16) {
        let now = yw_win::time::monotonic_ms();
        match id {
            ids::SEND_TO_EDIT => {
                self.evm.send.to_text = self.edit_text(id);
                self.evm.send.dirty_ms = Some(now);
            }
            ids::SEND_AMOUNT_EDIT => {
                self.evm.send.amount_text = self.edit_text(id);
                self.evm.send.dirty_ms = Some(now);
            }
            ids::BOOK_ADDR_EDIT => self.evm.book.address = self.edit_text(id),
            ids::BOOK_LABEL_EDIT => self.evm.book.label = self.edit_text(id),
            ids::TOKEN_ADDR_EDIT => self.evm.token.address = self.edit_text(id),
            ids::TOKEN_LABEL_EDIT => self.evm.token.label = self.edit_text(id),
            ids::CHAIN_ID_EDIT
            | ids::CHAIN_NAME_EDIT
            | ids::CHAIN_SYMBOL_EDIT
            | ids::CHAIN_DECIMALS_EDIT
            | ids::CHAIN_EXPLORER_EDIT => {
                let text = self.edit_text(id);
                if let Some(form) = self.evm.chain_form.as_mut() {
                    let field = match id {
                        ids::CHAIN_ID_EDIT => &mut form.chain_id,
                        ids::CHAIN_NAME_EDIT => &mut form.name,
                        ids::CHAIN_SYMBOL_EDIT => &mut form.symbol,
                        ids::CHAIN_DECIMALS_EDIT => &mut form.decimals,
                        _ => &mut form.explorer,
                    };
                    *field = text;
                }
            }
            ids::CAPS_FEE_EDIT | ids::CAPS_TIP_EDIT | ids::CAPS_TOTAL_EDIT => {
                let text = self.edit_text(id);
                if let Some(caps) = self.evm.caps.as_mut() {
                    match id {
                        ids::CAPS_FEE_EDIT => caps.fee = text,
                        ids::CAPS_TIP_EDIT => caps.tip = text,
                        _ => caps.total = text,
                    }
                }
            }
            _ => {}
        }
    }

    /// EVM commands; `false` when `id` is not one of them.
    #[expect(clippy::too_many_lines, reason = "one arm per EVM command id")]
    pub fn on_evm_command(&mut self, id: u16) -> bool {
        match id {
            ids::SEND_OPEN => {
                if matches!(self.mode, AppMode::Unlocked { .. }) {
                    self.open_send();
                }
            }
            ids::RECEIVE_OPEN => self.set_screen(Screen::Receive),
            ids::REFRESH => {
                self.refresh_balances();
                self.schedule_tracking(true);
            }
            ids::BOOK_OPEN => self.set_screen(Screen::AddressBook),
            ids::TOKEN_OPEN => {
                self.evm.token = crate::app_evm::TokenForm::default();
                self.set_screen(Screen::TokenAdd);
            }
            ids::REPIN_SETTINGS | ids::SECTION_CHAINS => {
                self.set_screen(Screen::Settings(SettingsSection::Chains));
            }
            ids::SEND_MAX => self.fill_max(),
            ids::SEND_PICK => {
                self.evm.send.picker = !self.evm.send.picker;
                self.refresh();
            }
            ids::SEND_ACK => {
                self.evm.send.ack = self.controls.checked(ids::SEND_ACK).unwrap_or(false);
                self.refresh();
            }
            ids::SEND_REVIEW => {
                self.evm.send.to_text = self.edit_text(ids::SEND_TO_EDIT);
                self.evm.send.amount_text = self.edit_text(ids::SEND_AMOUNT_EDIT);
                self.review_send();
            }
            ids::SEND_CANCEL => {
                self.evm.send = SendForm::default();
                self.set_screen(Screen::Main);
            }
            ids::COPY_ADDRESS => {
                if let Some((address, ..)) = self.selected_account() {
                    let text = address.to_checksum();
                    self.copy_text(&text);
                    self.info = Some(
                        "주소를 복사했습니다. 붙여넣은 곳에서 주소 전체를 확인하세요.".to_owned(),
                    );
                    self.refresh();
                }
            }
            ids::BOOK_VERIFIED => {
                self.evm.book.verified = self.controls.checked(ids::BOOK_VERIFIED).unwrap_or(false);
            }
            ids::BOOK_SAVE => {
                self.evm.book.address = self.edit_text(ids::BOOK_ADDR_EDIT);
                self.evm.book.label = self.edit_text(ids::BOOK_LABEL_EDIT);
                self.save_book();
            }
            ids::BOOK_CANCEL => {
                self.evm.book = crate::app_evm::BookForm::default();
                self.refresh();
            }
            ids::TOKEN_LOOKUP => {
                self.evm.token.address = self.edit_text(ids::TOKEN_ADDR_EDIT);
                self.lookup_token();
            }
            ids::TOKEN_SAVE => {
                self.evm.token.label = self.edit_text(ids::TOKEN_LABEL_EDIT);
                self.save_token();
            }
            ids::CHAIN_ADD => self.open_chain_form(None),
            ids::CHAIN_SIM_AUTO | ids::CHAIN_SIM_UNSUPPORTED => {
                if let Some(form) = self.evm.chain_form.as_mut() {
                    form.unsupported = id == ids::CHAIN_SIM_UNSUPPORTED;
                }
            }
            ids::CHAIN_SAVE => {
                for edit in [
                    ids::CHAIN_ID_EDIT,
                    ids::CHAIN_NAME_EDIT,
                    ids::CHAIN_SYMBOL_EDIT,
                    ids::CHAIN_DECIMALS_EDIT,
                    ids::CHAIN_EXPLORER_EDIT,
                ] {
                    self.on_edit_change(edit);
                }
                let units = self.controls.text_wiping(ids::CHAIN_RPC_EDIT, 2_048);
                let rpc = units
                    .map(|units| String::from_utf16_lossy(units.as_slice()))
                    .map(yw_core::secret::Zeroizing::new)
                    .unwrap_or_default();
                self.save_chain_form(&rpc);
                self.controls.clear_text(ids::CHAIN_RPC_EDIT);
            }
            ids::CHAIN_CANCEL => {
                self.evm.chain_form = None;
                self.set_screen(Screen::Settings(SettingsSection::Chains));
            }
            ids::CAPS_SAVE | ids::CAPS_DEFAULT => {
                for edit in [ids::CAPS_FEE_EDIT, ids::CAPS_TIP_EDIT, ids::CAPS_TOTAL_EDIT] {
                    self.on_edit_change(edit);
                }
                self.save_caps(id == ids::CAPS_DEFAULT);
            }
            ids::REPIN_CHECK => {
                let checked = self.controls.checked(ids::REPIN_CHECK).unwrap_or(false);
                if let Some(repin) = self.evm.repin.as_mut() {
                    repin.checked = checked;
                }
                self.refresh();
            }
            other => return self.on_evm_indexed(other),
        }
        true
    }

    #[expect(clippy::too_many_lines, reason = "one block per indexed id range")]
    fn on_evm_indexed(&mut self, id: u16) -> bool {
        let chain_id = self.settings.evm_chain_id;
        if let Some(index) = offset(id, ids::SEND_ASSET_BASE, ids::SEND_ASSET_SPAN) {
            let asset = if index == 0 {
                SendAsset::Native
            } else {
                self.chain_tokens(chain_id)
                    .get(usize::from(index).saturating_sub(1))
                    .map_or(SendAsset::Native, |(address, ..)| {
                        SendAsset::Token(*address)
                    })
            };
            self.evm.send.asset = asset;
            self.evm.send.quote = None;
            self.evm.send.contract = None;
            self.validate_send(true);
            return true;
        }
        if let Some(index) = offset(id, ids::SEND_PICK_BASE, ids::SEND_PICK_SPAN) {
            if let Some(address) = self.picker_entries().get(usize::from(index)).copied() {
                self.evm.send.to_text = address.to_checksum();
                self.evm.send.picker = false;
                self.controls
                    .set_text(ids::SEND_TO_EDIT, &self.evm.send.to_text.clone());
                self.validate_send(true);
            }
            return true;
        }
        if let Some(index) = offset(id, ids::BOOK_ROW_BASE, ids::BOOK_ROW_SPAN) {
            let entries: Vec<BookEntry> = self
                .meta
                .as_ref()
                .map(crate::meta::Meta::book)
                .unwrap_or_default();
            if let Some(entry) = entries.get(usize::from(index / 2)) {
                if index % 2 == 0 {
                    self.evm.book = crate::app_evm::BookForm {
                        editing: Some(entry.address.clone()),
                        address: entry.address.clone(),
                        label: entry.label.clone(),
                        verified: entry.verified,
                        message: None,
                    };
                    self.refresh();
                } else {
                    self.evm.book.editing = Some(entry.address.clone());
                    self.set_screen(Screen::Confirm(Confirm::BookDelete));
                }
            }
            return true;
        }
        if let Some(index) = offset(id, ids::CHAIN_ROW_BASE, ids::CHAIN_ROW_SPAN) {
            let chains = self.settings.registered_evm();
            if let Some(chain) = chains.get(usize::from(index / 4)).copied() {
                match index % 4 {
                    0 if builtin_chain(chain).is_none() => self.open_chain_form(Some(chain)),
                    1 if builtin_chain(chain).is_none() => self.request_delete_chain(chain),
                    2 => self.start_repin(chain),
                    _ => {}
                }
            }
            return true;
        }
        if let Some(index) = offset(id, ids::CAPS_CHAIN_BASE, ids::CAPS_CHAIN_SPAN) {
            if let Some(chain) = self
                .settings
                .registered_evm()
                .get(usize::from(index))
                .copied()
            {
                self.select_caps_chain(chain);
            }
            return true;
        }
        if let Some(index) = offset(id, ids::ACTIVITY_BASE, ids::ACTIVITY_SPAN) {
            let rows = self.activity_rows();
            let Some(row) = rows.get(usize::from(index / 8)).cloned() else {
                return true;
            };
            match index % 8 {
                0 => self.copy_text(&row.hash),
                1 => {
                    if let Some(key) = row.open {
                        self.replace_group(key, ReplaceMode::SpeedUp);
                    }
                }
                2 => {
                    if let Some(key) = row.open {
                        self.replace_group(key, ReplaceMode::Cancel);
                    }
                }
                3 => {
                    if let Some(key) = row.open {
                        self.resend_group(key);
                    }
                }
                4 => {
                    if let Some(key) = row.open {
                        self.evm.discard = Some(key);
                        self.set_screen(Screen::Confirm(Confirm::Discard));
                    }
                }
                5 => {
                    if let Some(explorer) = self.explorer(chain_id) {
                        let link = format!("{explorer}/tx/{}", row.hash);
                        self.copy_text(&link);
                    }
                }
                _ => {}
            }
            return true;
        }
        false
    }

    /// `삭제` of an address-book entry confirmed.
    pub fn delete_book_entry(&mut self) {
        if let Some(address) = self.evm.book.editing.take()
            && let Some(meta) = self.meta.as_mut()
        {
            meta.remove_book(&address);
            self.save_meta();
        }
        self.evm.book = crate::app_evm::BookForm::default();
    }

    /// The hash text of a record (shared by screens).
    #[must_use]
    pub fn record_hash(record: &yw_core::journal::evm::EvmRecord) -> String {
        hash_text(&record.tx_hash)
    }
}
