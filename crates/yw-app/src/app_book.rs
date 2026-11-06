//! The address book of every chain (S14, spec/04 §2.10) and its send-side helpers: favorites
//! (`★`, meta `address_book_favorites`), the favorite chips and `주소록에서 선택` of every send
//! form, and the inline `주소록에 저장` prompt of the send forms, the send results and the
//! activity rows.
//!
//! One EVM entry (`chain = "evm"`) serves every EVM chain, built-in or user-added, and any
//! EVM-address form (the `HyperCore` send form included) uses it through [`BookTarget::Evm`].
//! Solana entries serve mainnet and devnet (the same base58 key). Bitcoin entries are one family,
//! but a send form only offers the entries its network parses (`bc1…` vs `tb1…`).
//!
//! Saving never weakens the send checks: the send forms still run their recipient rules
//! (format, checksum, look-alike / poisoning, first-time) on whatever a chip or the picker
//! fills in, and a new entry that looks like an existing one (same ends) needs
//! `주소 전체를 직접 확인했습니다` before it is saved.

use yw_core::btc::BtcNetwork;
use yw_core::evm::address::{Address, AddressError, parse_address};
use yw_core::sol::SolAddress;

use crate::app::{App, Confirm, Screen};
use crate::errors::ErrorCode;
use crate::meta::{BookChain, Contact, ListError, MAX_ADDRESS_BOOK};
use crate::text::is_valid_label;
use crate::ui::screens_book::ids;

/// Favorite chips shown above a recipient field.
pub const FAVORITE_CHIPS: usize = 5;

/// The address family a send form takes (and the Bitcoin network that filters its entries).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BookTarget {
    /// Any EVM-address form (every EVM chain; `HyperCore` uses the same addresses).
    Evm,
    /// Solana (mainnet and devnet).
    Sol,
    /// Bitcoin on one network.
    Btc(BtcNetwork),
}

impl BookTarget {
    /// The book family.
    #[must_use]
    pub const fn chain(self) -> BookChain {
        match self {
            Self::Evm => BookChain::Evm,
            Self::Sol => BookChain::Sol,
            Self::Btc(_) => BookChain::Btc,
        }
    }
}

/// Where the inline `주소록에 저장` prompt is drawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptPlace {
    /// Under the recipient field of a send form.
    SendForm,
    /// On a send result screen.
    Result,
    /// Under the activity row of this address.
    Activity,
}

/// The S14 add/edit form.
#[derive(Clone, Debug, Default)]
pub struct BookForm {
    /// Family of a new entry (fixed while editing).
    pub chain: BookChain,
    /// The edited entry's canonical address (`None`: adding).
    pub editing: Option<String>,
    /// Address text.
    pub address: String,
    /// Label text.
    pub label: String,
    /// Verified out of band.
    pub verified: bool,
    /// Starred.
    pub favorite: bool,
    /// The look-alike note of the last `추가` (the entry it resembles).
    pub look_alike: Option<String>,
    /// `주소 전체를 직접 확인했습니다` for that note.
    pub ack: bool,
    /// Error message.
    pub message: Option<String>,
}

/// The inline `주소록에 저장` prompt (label only; the address is fixed).
#[derive(Clone, Debug)]
pub struct SavePrompt {
    /// Family.
    pub chain: BookChain,
    /// Canonical address.
    pub address: String,
    /// Label text.
    pub label: String,
    /// Where it is drawn.
    pub place: PromptPlace,
    /// The look-alike note (needs the check before saving).
    pub look_alike: Option<String>,
    /// `주소 전체를 직접 확인했습니다`.
    pub ack: bool,
    /// Error message.
    pub message: Option<String>,
}

/// Address-book UI state (dropped at lock).
#[derive(Clone, Debug, Default)]
pub struct BookUi {
    /// S14 form.
    pub form: BookForm,
    /// The inline save prompt.
    pub prompt: Option<SavePrompt>,
    /// Entry awaiting the delete confirmation.
    pub delete: Option<(BookChain, String)>,
    /// The Bitcoin send form's picker is open.
    pub btc_picker: bool,
    /// Last saved address (`저장했습니다` note of the prompt place).
    pub saved: Option<(BookChain, String)>,
}

/// The canonical form of an address typed for `chain`, or the error text.
///
/// # Errors
///
/// E-INP-009 (format) or E-INP-010 (EVM checksum).
pub fn canonical(chain: BookChain, text: &str) -> Result<String, String> {
    let text = text.trim();
    match chain {
        BookChain::Evm => match parse_address(text) {
            Ok(address) => Ok(address.to_lower_hex()),
            Err(AddressError::BadChecksum) => Err(ErrorCode::Inp010.text()),
            Err(_) => Err(ErrorCode::Inp009.text()),
        },
        BookChain::Sol => SolAddress::parse_input(text)
            .map(SolAddress::to_base58)
            .map_err(|_| ErrorCode::Inp009.text()),
        BookChain::Btc => BtcNetwork::ALL
            .iter()
            .find_map(|net| {
                yw_core::btc::address::parse_address(text, *net)
                    .ok()
                    .map(|kind| yw_core::btc::address::encode_address(&kind, *net))
            })
            .ok_or_else(|| ErrorCode::Inp009.text()),
    }
}

/// The Bitcoin network of a canonical BTC address.
#[must_use]
pub fn btc_network_of(address: &str) -> Option<BtcNetwork> {
    BtcNetwork::ALL
        .iter()
        .copied()
        .find(|net| yw_core::btc::address::parse_address(address, *net).is_ok())
}

/// Whether a canonical address belongs to `target` (Bitcoin: its network).
#[must_use]
pub fn fits(target: BookTarget, address: &str) -> bool {
    match target {
        BookTarget::Btc(net) => yw_core::btc::address::parse_address(address, net).is_ok(),
        BookTarget::Evm | BookTarget::Sol => true,
    }
}

/// `0x1234…abcd` / `7xKX…sAsU`: the first and last characters of a canonical address for a
/// chip (the full address is shown when it is filled in).
#[must_use]
pub fn short_address(chain: BookChain, address: &str) -> String {
    let shown = match chain {
        BookChain::Evm => {
            parse_address(address).map_or_else(|_| address.to_owned(), Address::to_checksum)
        }
        BookChain::Sol | BookChain::Btc => address.to_owned(),
    };
    let head: usize = match chain {
        BookChain::Evm => 6,
        BookChain::Sol => 4,
        // bech32 keeps its `bc1q`/`tb1p` prefix plus three characters.
        BookChain::Btc if shown.starts_with("bc1") || shown.starts_with("tb1") => 7,
        BookChain::Btc => 5,
    };
    let chars: Vec<char> = shown.chars().collect();
    if chars.len() <= head.saturating_add(6) {
        return shown;
    }
    let start: String = chars.iter().take(head).collect();
    let end: String = chars.iter().skip(chars.len().saturating_sub(4)).collect();
    format!("{start}…{end}")
}

/// The entry of `contacts` that `address` looks like (same family rules as the send forms:
/// EVM [`crate::flow::evm::form::look_alike`], Solana `is_lookalike`, Bitcoin `is_look_alike`).
#[must_use]
pub fn look_alike_of<'c>(
    chain: BookChain,
    address: &str,
    contacts: &'c [Contact],
) -> Option<&'c Contact> {
    contacts.iter().find(|entry| {
        entry.address != address
            && match chain {
                BookChain::Evm => match (parse_address(&entry.address), parse_address(address)) {
                    (Ok(known), Ok(typed)) => {
                        crate::flow::evm::form::look_alike(&known, &typed).is_some()
                    }
                    _ => false,
                },
                BookChain::Sol => match (
                    SolAddress::parse(&entry.address),
                    SolAddress::parse(address),
                ) {
                    (Ok(known), Ok(typed)) => yw_core::sol::recipient::is_lookalike(&known, &typed),
                    _ => false,
                },
                BookChain::Btc => yw_core::btc::address::is_look_alike(&entry.address, address),
            }
    })
}

/// The W-ADDR-3-style note of a new entry that looks like `known`.
#[must_use]
pub fn look_alike_note(known: &Contact) -> String {
    format!(
        "주소록의 '{}'과 앞·끝 글자가 같지만 다른 주소입니다. 주소 오염 공격일 수 있으니 주소 전체를 확인한 뒤 저장하세요.",
        known.label
    )
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

fn offset(id: u16, base: u16, span: u16) -> Option<u16> {
    id.checked_sub(base).filter(|offset| *offset < span)
}

impl App {
    /// The S14 rows in display order: each family's entries, favorites first.
    #[must_use]
    pub fn book_rows(&self) -> Vec<Contact> {
        self.meta.as_ref().map_or_else(Vec::new, |meta| {
            BookChain::ALL
                .iter()
                .flat_map(|chain| meta.contacts_favorites_first(*chain))
                .take(MAX_ADDRESS_BOOK)
                .collect()
        })
    }

    /// The entries a send form of `target` offers, favorites first.
    #[must_use]
    pub fn target_contacts(&self, target: BookTarget) -> Vec<Contact> {
        self.meta.as_ref().map_or_else(Vec::new, |meta| {
            meta.contacts_favorites_first(target.chain())
                .into_iter()
                .filter(|entry| fits(target, &entry.address))
                .collect()
        })
    }

    /// The favorite chips of a send form (at most [`FAVORITE_CHIPS`]).
    #[must_use]
    pub fn favorite_contacts(&self, target: BookTarget) -> Vec<Contact> {
        let Some(meta) = self.meta.as_ref() else {
            return Vec::new();
        };
        self.target_contacts(target)
            .into_iter()
            .filter(|entry| meta.is_favorite(entry.chain, &entry.address))
            .take(FAVORITE_CHIPS)
            .collect()
    }

    /// Whether `(chain, address)` is in the book.
    #[must_use]
    pub fn in_book(&self, chain: BookChain, address: &str) -> bool {
        self.meta
            .as_ref()
            .is_some_and(|meta| meta.contact(chain, address).is_some())
    }

    /// The send form of the current screen.
    #[must_use]
    pub fn send_target(&self) -> Option<BookTarget> {
        match self.screen {
            Screen::Send | Screen::SendResult => Some(BookTarget::Evm),
            Screen::SolSend | Screen::SolSendResult => Some(BookTarget::Sol),
            Screen::BtcSend | Screen::BtcSendResult => Some(BookTarget::Btc(self.btc_ctx().net())),
            _ => None,
        }
    }

    /// The canonical recipient a send form has accepted (parsed), if any.
    #[must_use]
    pub fn send_recipient(&self, target: BookTarget) -> Option<String> {
        match target {
            BookTarget::Evm => self
                .evm
                .send
                .recipient
                .as_ref()
                .map(|(address, _)| address.to_lower_hex()),
            BookTarget::Sol => self
                .sol
                .send
                .check
                .as_ref()
                .map(|check| check.to.to_base58()),
            BookTarget::Btc(net) => self
                .btc
                .send
                .recipient
                .map(|kind| yw_core::btc::address::encode_address(&kind, net)),
        }
    }

    /// The recipient of the send shown on a result screen.
    #[must_use]
    pub fn result_recipient(&self, target: BookTarget) -> Option<String> {
        match target {
            BookTarget::Evm => {
                let sent = self.evm.sent?;
                let record = self
                    .evm
                    .records()
                    .iter()
                    .find(|record| record.tx_hash == sent.tx_hash)?;
                let tx = record.tx()?;
                crate::flow::evm::form::tx_recipients(&tx)
                    .last()
                    .map(|address| address.to_lower_hex())
            }
            BookTarget::Sol => {
                let (_, signature) = self.sol.sent?;
                self.sol_records()
                    .iter()
                    .find(|record| record.signature() == signature)
                    .and_then(yw_core::journal::sol::SolRecord::core)
                    .map(|core| core.to.to_base58())
            }
            BookTarget::Btc(_) => {
                let txid = self.btc.result?.to_display_hex();
                let ctx = self.btc_ctx();
                self.btc
                    .activity_rows(&ctx)
                    .into_iter()
                    .find(|row| row.txid == txid)
                    .map(|row| row.counterparty)
                    .filter(|counterparty| !counterparty.is_empty())
            }
        }
    }

    /// Puts a picked address into the send form of `target` and runs its recipient checks.
    pub fn fill_recipient(&mut self, target: BookTarget, address: &str) {
        match target {
            BookTarget::Evm => {
                let text = parse_address(address)
                    .map_or_else(|_| address.to_owned(), Address::to_checksum);
                self.evm.send.to_text.clone_from(&text);
                self.evm.send.picker = false;
                self.controls
                    .set_text(crate::ui::screens_evm::ids::SEND_TO_EDIT, &text);
                self.validate_send(true);
            }
            BookTarget::Sol => {
                if self.sol.send.moving.is_some() {
                    return;
                }
                address.clone_into(&mut self.sol.send.to_text);
                self.sol.send.picker = false;
                self.controls
                    .set_text(crate::ui::screens_sol::ids::SEND_TO_EDIT, address);
                self.sol_validate_send();
            }
            BookTarget::Btc(_) => {
                self.book.btc_picker = false;
                let id = crate::ui::screens_btc::ids::SEND_TO_EDIT;
                self.controls.set_text(id, address);
                self.btc_apply_field(id, address);
                self.refresh();
            }
        }
    }

    /// Opens the inline `주소록에 저장` prompt for an address not in the book yet.
    pub fn open_save_prompt(&mut self, chain: BookChain, address: &str, place: PromptPlace) {
        if self.in_book(chain, address) {
            return;
        }
        let contacts = self
            .meta
            .as_ref()
            .map(|meta| meta.contacts(chain))
            .unwrap_or_default();
        let look_alike = look_alike_of(chain, address, &contacts).map(look_alike_note);
        self.book.saved = None;
        self.book.prompt = Some(SavePrompt {
            chain,
            address: address.to_owned(),
            label: String::new(),
            place,
            look_alike,
            ack: false,
            message: None,
        });
        self.refresh();
    }

    fn save_prompt(&mut self) {
        let label = self
            .controls
            .text(ids::PROMPT_LABEL_EDIT, 512)
            .unwrap_or_default();
        let Some(prompt) = self.book.prompt.as_mut() else {
            return;
        };
        prompt.label.clone_from(&label);
        let label = label.trim().to_owned();
        if !is_valid_label(&label) {
            prompt.message = Some(ErrorCode::Inp017.text());
            self.refresh();
            return;
        }
        if prompt.look_alike.is_some() && !prompt.ack {
            prompt.message = Some("주소 전체를 확인했으면 체크한 뒤 저장하세요.".to_owned());
            self.refresh();
            return;
        }
        let entry = Contact {
            chain: prompt.chain,
            address: prompt.address.clone(),
            label,
            verified: false,
            added_at_unix_ms: now_unix_ms(),
        };
        let Some(meta) = self.meta.as_mut() else {
            return;
        };
        match meta.add_contact(&entry) {
            Ok(()) => {
                self.book.prompt = None;
                self.book.saved = Some((entry.chain, entry.address));
                self.save_meta();
                // The send form's notes now say "주소록: {이름}".
                match self.screen {
                    Screen::Send => self.validate_send(true),
                    Screen::SolSend => self.sol_validate_send(),
                    _ => {}
                }
            }
            Err(error) => {
                if let Some(prompt) = self.book.prompt.as_mut() {
                    prompt.message = Some(list_error_text(error));
                }
            }
        }
        self.refresh();
    }

    /// `추가` / `저장` of the S14 form.
    fn save_book_form(&mut self) {
        let read = |app: &Self, id| app.controls.text(id, 512).unwrap_or_default();
        if self.book.form.editing.is_none() {
            self.book.form.address = read(self, ids::ADDR_EDIT);
        }
        self.book.form.label = read(self, ids::LABEL_EDIT);
        let form = self.book.form.clone();
        let address = match &form.editing {
            Some(address) => address.clone(),
            None => match canonical(form.chain, &form.address) {
                Ok(address) => address,
                Err(message) => {
                    self.book.form.message = Some(message);
                    self.refresh();
                    return;
                }
            },
        };
        let label = form.label.trim().to_owned();
        if !is_valid_label(&label) {
            self.book.form.message = Some(ErrorCode::Inp017.text());
            self.refresh();
            return;
        }
        let Some(meta) = self.meta.as_mut() else {
            return;
        };
        if form.editing.is_none() {
            if meta.contact(form.chain, &address).is_some() {
                self.book.form.message = Some(ErrorCode::Inp016.text());
                self.refresh();
                return;
            }
            let contacts = meta.contacts(form.chain);
            if let Some(known) = look_alike_of(form.chain, &address, &contacts) {
                let note = look_alike_note(known);
                if !form.ack || form.look_alike.as_deref() != Some(note.as_str()) {
                    self.book.form.look_alike = Some(note);
                    self.book.form.ack = false;
                    self.book.form.message = None;
                    self.refresh();
                    return;
                }
            }
        }
        let entry = Contact {
            chain: form.chain,
            address: address.clone(),
            label,
            verified: form.verified,
            added_at_unix_ms: now_unix_ms(),
        };
        let result = if form.editing.is_some() {
            meta.update_contact(&entry);
            Ok(())
        } else {
            meta.add_contact(&entry)
        };
        match result {
            Ok(()) => {
                meta.set_favorite(form.chain, &address, form.favorite);
                self.book.form = BookForm {
                    chain: form.chain,
                    ..BookForm::default()
                };
                self.save_meta();
            }
            Err(error) => self.book.form.message = Some(list_error_text(error)),
        }
        self.refresh();
    }

    fn toggle_favorite(&mut self, chain: BookChain, address: &str) {
        if let Some(meta) = self.meta.as_mut() {
            let on = !meta.is_favorite(chain, address);
            meta.set_favorite(chain, address, on);
            self.save_meta();
        }
        self.refresh();
    }

    /// `삭제` of an address-book entry confirmed (T-BOOK-DELETE).
    pub fn delete_book_entry(&mut self) {
        if let Some((chain, address)) = self.book.delete.take()
            && let Some(meta) = self.meta.as_mut()
        {
            meta.remove_contact(chain, &address);
            self.save_meta();
        }
        if self.book.form.editing.is_some() {
            self.book.form = BookForm::default();
        }
    }

    /// The canonical counterparty of an activity row (`activity` id offset `row`), per chain.
    fn activity_counterparty(&self, chain: BookChain, row: usize) -> Option<String> {
        match chain {
            BookChain::Evm => self
                .activity_rows()
                .get(row)
                .and_then(|view| view.counterparty)
                .map(Address::to_lower_hex),
            BookChain::Sol => self.sol_activity_counterparties().get(row).cloned(),
            BookChain::Btc => {
                let ctx = self.btc_ctx();
                self.btc
                    .activity_rows(&ctx)
                    .get(row)
                    .map(|view| view.counterparty.clone())
                    .filter(|counterparty| !counterparty.is_empty())
            }
        }
    }

    /// `이 주소 저장` of an activity row.
    pub fn save_activity_address(&mut self, chain: BookChain, row: usize) {
        if let Some(address) = self.activity_counterparty(chain, row) {
            self.open_save_prompt(chain, &address, PromptPlace::Activity);
        }
    }

    /// `EN_CHANGE` of an address-book edit; `false` when `id` is not one of them.
    pub fn on_book_edit_change(&mut self, id: u16) -> bool {
        match id {
            ids::ADDR_EDIT => {
                self.book.form.address = self.controls.text(id, 512).unwrap_or_default();
            }
            ids::LABEL_EDIT => {
                self.book.form.label = self.controls.text(id, 512).unwrap_or_default();
            }
            ids::PROMPT_LABEL_EDIT => {
                let text = self.controls.text(id, 512).unwrap_or_default();
                if let Some(prompt) = self.book.prompt.as_mut() {
                    prompt.label = text;
                }
            }
            _ => return false,
        }
        true
    }

    /// Address-book commands; `false` when `id` is not one of them.
    pub fn on_book_command(&mut self, id: u16) -> bool {
        match id {
            ids::CHAIN_EVM | ids::CHAIN_SOL | ids::CHAIN_BTC => {
                if self.book.form.editing.is_none() {
                    self.book.form.address =
                        self.controls.text(ids::ADDR_EDIT, 512).unwrap_or_default();
                    self.book.form.label =
                        self.controls.text(ids::LABEL_EDIT, 512).unwrap_or_default();
                    self.book.form.chain = match id {
                        ids::CHAIN_SOL => BookChain::Sol,
                        ids::CHAIN_BTC => BookChain::Btc,
                        _ => BookChain::Evm,
                    };
                    self.book.form.look_alike = None;
                    self.book.form.ack = false;
                    self.book.form.message = None;
                }
                self.refresh();
            }
            ids::VERIFIED => {
                self.book.form.verified = self.controls.checked(id).unwrap_or(false);
            }
            ids::FAVORITE => {
                self.book.form.favorite = self.controls.checked(id).unwrap_or(false);
            }
            ids::FORM_ACK => {
                self.book.form.ack = self.controls.checked(id).unwrap_or(false);
                self.refresh();
            }
            ids::SAVE => self.save_book_form(),
            ids::CANCEL => {
                self.book.form = BookForm {
                    chain: self.book.form.chain,
                    ..BookForm::default()
                };
                self.refresh();
            }
            ids::PROMPT_SAVE => self.save_prompt(),
            ids::PROMPT_CANCEL => {
                self.book.prompt = None;
                self.refresh();
            }
            ids::PROMPT_ACK => {
                let checked = self.controls.checked(id).unwrap_or(false);
                if let Some(prompt) = self.book.prompt.as_mut() {
                    prompt.ack = checked;
                    prompt.message = None;
                }
                self.refresh();
            }
            ids::SEND_SAVE => {
                if let Some(target) = self.send_target()
                    && let Some(address) = self.send_recipient(target)
                {
                    self.open_save_prompt(target.chain(), &address, PromptPlace::SendForm);
                }
            }
            ids::RESULT_SAVE => {
                if let Some(target) = self.send_target()
                    && let Some(address) = self.result_recipient(target)
                {
                    self.open_save_prompt(target.chain(), &address, PromptPlace::Result);
                }
            }
            ids::BTC_PICK => {
                self.book.btc_picker = !self.book.btc_picker;
                self.refresh();
            }
            _ => return self.on_book_indexed(id),
        }
        true
    }

    fn on_book_indexed(&mut self, id: u16) -> bool {
        if let Some(index) = offset(id, ids::FAV_BASE, ids::FAV_SPAN) {
            if let Some(target) = self.send_target()
                && let Some(entry) = self.favorite_contacts(target).get(usize::from(index))
            {
                let address = entry.address.clone();
                self.fill_recipient(target, &address);
            }
            return true;
        }
        if let Some(index) = offset(id, ids::BTC_PICK_BASE, ids::BTC_PICK_SPAN) {
            if let Some(target @ BookTarget::Btc(_)) = self.send_target()
                && let Some(entry) = self.btc_picker_entries(target).get(usize::from(index))
            {
                let address = entry.address.clone();
                self.fill_recipient(target, &address);
            }
            return true;
        }
        if let Some(index) = offset(id, ids::ROW_BASE, ids::ROW_SPAN) {
            let rows = self.book_rows();
            let Some(entry) = rows.get(usize::from(index / ids::ROW_STRIDE)).cloned() else {
                return true;
            };
            match index % ids::ROW_STRIDE {
                0 => self.toggle_favorite(entry.chain, &entry.address),
                1 => {
                    let favorite = self
                        .meta
                        .as_ref()
                        .is_some_and(|meta| meta.is_favorite(entry.chain, &entry.address));
                    self.book.form = BookForm {
                        chain: entry.chain,
                        editing: Some(entry.address.clone()),
                        address: entry.address.clone(),
                        label: entry.label.clone(),
                        verified: entry.verified,
                        favorite,
                        ..BookForm::default()
                    };
                    self.scroll = 0;
                    self.refresh();
                }
                _ => {
                    self.book.delete = Some((entry.chain, entry.address));
                    self.set_screen(Screen::Confirm(Confirm::BookDelete));
                }
            }
            return true;
        }
        if let Some(row) = offset(id, ids::SOL_ACTIVITY_BASE, ids::SOL_ACTIVITY_SPAN) {
            self.save_activity_address(BookChain::Sol, usize::from(row));
            return true;
        }
        false
    }

    /// The Bitcoin picker entries (book entries of the form's network, filtered by the text).
    #[must_use]
    pub fn btc_picker_entries(&self, target: BookTarget) -> Vec<Contact> {
        let filter = self.btc.send.to_text.trim().to_ascii_lowercase();
        self.target_contacts(target)
            .into_iter()
            .filter(|entry| {
                filter.is_empty()
                    || entry.address.to_ascii_lowercase().contains(&filter)
                    || entry.label.to_lowercase().contains(&filter)
            })
            .take(usize::from(ids::BTC_PICK_SPAN))
            .collect()
    }
}

fn list_error_text(error: ListError) -> String {
    match error {
        ListError::Duplicate => ErrorCode::Inp016.text(),
        ListError::Full => "주소록은 최대 500개입니다.".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVM: &str = "0x52908400098527886e0f7030069857d2e4169ee7";

    #[test]
    fn canonical_forms_and_networks() {
        assert_eq!(
            canonical(
                BookChain::Evm,
                " 0x52908400098527886E0F7030069857D2E4169EE7 "
            )
            .unwrap(),
            EVM
        );
        assert!(canonical(BookChain::Evm, "0x52908400098527886e0F7030069857D2E4169EE7").is_err());
        assert!(canonical(BookChain::Sol, EVM).is_err());
        let main = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        assert_eq!(
            canonical(BookChain::Btc, &main.to_uppercase()).unwrap(),
            main
        );
        assert_eq!(btc_network_of(main), Some(BtcNetwork::Mainnet));
        assert!(fits(BookTarget::Btc(BtcNetwork::Mainnet), main));
        assert!(!fits(BookTarget::Btc(BtcNetwork::Testnet4), main));
        assert_eq!(short_address(BookChain::Evm, EVM), "0x5290…9EE7");
    }

    #[test]
    fn look_alikes_are_found_per_family() {
        let known = Contact {
            chain: BookChain::Evm,
            address: EVM.to_owned(),
            label: "친구".to_owned(),
            verified: true,
            added_at_unix_ms: 1,
        };
        let poisoned = format!("0x5290{}4169ee7", "0".repeat(29));
        let found = look_alike_of(BookChain::Evm, &poisoned, core::slice::from_ref(&known));
        assert_eq!(found.map(|entry| entry.label.as_str()), Some("친구"));
        assert!(look_alike_of(BookChain::Evm, EVM, core::slice::from_ref(&known)).is_none());
        let other = "0x1111111111111111111111111111111111111111";
        assert!(look_alike_of(BookChain::Evm, other, core::slice::from_ref(&known)).is_none());
    }
}
