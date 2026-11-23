//! One account card for the chain tabs (2026-11-15, spec/04 §2.6): the EVM `내 EVM 계정`, the
//! Solana `내 Solana 계정`, the Bitcoin `내 Bitcoin 계정` and the Zcash `내 Zcash 계정` cards are
//! laid out by [`Screen::push_account_card`] from an [`AccountCard`] — title, the shared help
//! (`accounts_help`), the drop-down whose items read `label · source`, the selected account's line
//! (its rename field or its buttons) and details, the hidden accounts, a rule and the card's
//! actions. Zcash's items are its key sources (one account per network: no rename, no hide).
//!
//! Before 2026-11-15 each tab wrote its own card: the EVM title was `내 계정`, a `YubiKey`
//! account's item ended in a bare `· YubiKey` (which card held the key was not said), an imported
//! Solana key read `· imported key` in English, and a derived account named no source even next
//! to imported and `YubiKey` accounts.
//!
//! The source part is app chrome only: approval display notes (`[내 계정: …]`, Solana
//! `RECIPIENT_OWN_HARDWARE`) carry account labels and never card names (they are digested).
//!
//! 2026-11-22 (spec/15 §11.4 S4d E0a): `AccountSource`, the card roles (`evm_card_role`,
//! `sol_card_role`, `btc_card_role`) and the source words `SOURCE_WORDS`, `SOURCE_IMPORTED`,
//! `SOURCE_EVM_KEY` moved to `crate::screen` unchanged (the wallet's Bitcoin and hidden-account
//! code names them); the card is drawn here.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): moved here unchanged from yw-app
//! `ui/screens_accounts.rs` (`impl App` builders became `impl Screen<'_>`, yw-app paths engine
//! paths); it had no control ids.

use super::Screen;
use crate::cmd::{MnPress, Press};
use crate::form::EditField;
use crate::screen::AccountSource;
use crate::screen::build::links::PickerEntry;
use crate::screen::model::{Ctl, Item};
use crate::screen::text::{SOURCE_EVM_KEY, SOURCE_IMPORTED, SOURCE_WORDS};
use crate::wallet::app_hidden::Family;

/// One account of the card's drop-down.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountItem {
    /// The entry's press (the radio's of before; 2026-11-24 S5-4: its control id before).
    pub press: Press,
    /// The account's label.
    pub label: String,
    /// Where its key comes from.
    pub source: AccountSource,
    /// The selected account.
    pub selected: bool,
    /// Whether the entry can be picked (Bitcoin: not while its tab is gated or an approval is
    /// open; the selected entry always can).
    pub enabled: bool,
}

/// The selected account's line under the drop-down.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectedLine {
    /// Its inline rename: the field (`edit`, holding `label`), `저장` (`save`), `취소` (`cancel`).
    Rename {
        /// The field (2026-11-24 S5-4: the three were control ids before).
        edit: EditField,
        /// `저장`.
        save: Press,
        /// `취소`.
        cancel: Press,
        /// The current label.
        label: String,
    },
    /// Its buttons (`이름 바꾸기`, `숨기기`, `삭제` …).
    Buttons(Vec<Ctl>),
}

/// What one account card shows ([`Screen::push_account_card`] lays it out).
#[derive(Debug)]
pub struct AccountCard {
    /// The card title (`내 EVM 계정`, `내 Solana 계정`).
    pub title: String,
    /// The drop-down button's press (`LinksPress::Picker*`; 2026-11-24 S5-4: its control id
    /// `screens_links::ids::PICKER_*` before).
    pub picker: Press,
    /// The visible accounts in display order.
    pub accounts: Vec<AccountItem>,
    /// A muted line instead of the drop-down while there is no account.
    pub empty: Option<String>,
    /// Why the drop-down cannot be used now (Zcash: a transaction is unfinished): its button is
    /// disabled, it does not open, and this reason is the line under it.
    pub locked: Option<String>,
    /// The selected account's line.
    pub selected: Option<SelectedLine>,
    /// Items after the selected account's line (Bitcoin: a refusal note, the address mode, the
    /// key reminders).
    pub details: Vec<Item>,
    /// The tab's hidden accounts (`숨긴 계정 n개 보기 ▸`), if it hides accounts.
    pub hidden: Option<Family>,
    /// The card's actions after the rule (`계정 추가`, `개인키 가져오기`, the recovery-words link).
    pub actions: Vec<Ctl>,
    /// Items after the actions (pickers the actions open, hints).
    pub footer: Vec<Item>,
}

impl Screen<'_> {
    /// Lays out an account card (2026-11-15, one layout for every tab): title, the help of
    /// [`Screen::accounts_help`] judged from the accounts' sources, the drop-down (items
    /// `label · source`, [`Screen::account_item_labels`]), the selected account's line, the hidden
    /// accounts, a rule, the actions and the footer.
    pub fn push_account_card(&self, items: &mut Vec<Item>, card: AccountCard) {
        let lang = self.settings.language;
        items.push(Item::CardStart(Some(card.title)));
        let has_card = card
            .accounts
            .iter()
            .any(|account| matches!(account.source, AccountSource::Card(_)));
        let imported = card
            .accounts
            .iter()
            .any(|account| account.source == AccountSource::Imported);
        if let Some(help) = self.accounts_help(has_card, imported) {
            items.push(Item::Help(help));
        }
        if card.accounts.is_empty()
            && let Some(empty) = card.empty
        {
            items.push(Item::Muted(empty));
        }
        let entries: Vec<PickerEntry> = card
            .accounts
            .iter()
            .zip(self.account_item_labels(&card.accounts))
            .map(|(account, label)| PickerEntry {
                press: account.press,
                label,
                selected: account.selected,
                enabled: (account.enabled && card.locked.is_none()) || account.selected,
            })
            .collect();
        if !entries.is_empty() {
            self.push_account_picker(items, card.picker, &entries, card.locked.is_none());
        }
        if let Some(reason) = card.locked {
            items.push(Item::Help(reason));
        }
        match card.selected {
            Some(SelectedLine::Rename {
                edit,
                save,
                cancel,
                label,
            }) => items.push(Item::Row(vec![
                Ctl::edit(edit, &label, 260, false, 64),
                Ctl::primary(save, crate::screen::build::core::text::SAVE.get(lang)),
                Ctl::button(cancel, crate::screen::build::core::text::CANCEL.get(lang)),
            ])),
            Some(SelectedLine::Buttons(buttons)) => items.push(Item::Row(buttons)),
            None => {}
        }
        items.extend(card.details);
        if let Some(family) = card.hidden {
            self.hidden_items(family, items);
        }
        items.push(Item::Rule);
        if !card.actions.is_empty() {
            items.push(Item::Row(card.actions));
        }
        items.extend(card.footer);
        items.push(Item::CardEnd);
    }

    /// The drop-down items of `accounts`, `label · source` (2026-11-15). An imported key and a
    /// `YubiKey` account always name their source; an account of recovery words names its set
    /// when the wallet has several ([`Wallet::mnemonic_tag`]), else `복구 단어` / `Recovery words`
    /// when the list mixes kinds — so every item of a mixed list has a source — and nothing in
    /// a list of one set of recovery words only (`계정 1`, as before).
    #[must_use]
    pub fn account_item_labels(&self, accounts: &[AccountItem]) -> Vec<String> {
        let lang = self.settings.language;
        let mixed = accounts
            .iter()
            .any(|account| !matches!(account.source, AccountSource::Words(_)));
        accounts
            .iter()
            .map(|account| {
                let source = match account.source {
                    AccountSource::Words(mnemonic) => self
                        .mnemonic_tag(mnemonic)
                        .or_else(|| mixed.then(|| SOURCE_WORDS.get(lang).to_owned())),
                    AccountSource::Imported => Some(SOURCE_IMPORTED.get(lang).to_owned()),
                    AccountSource::Card(role) => Some(self.card_source(role)),
                    AccountSource::EvmKey(index) => {
                        Some(SOURCE_EVM_KEY.fill(lang, [&index.to_string()]))
                    }
                };
                source.map_or_else(
                    || account.label.clone(),
                    |source| format!("{} · {source}", account.label),
                )
            })
            .collect()
    }
}

impl Screen<'_> {
    /// The `복구 단어 추가·관리` link of the account cards.
    #[must_use]
    pub fn mnemonics_link(&self) -> Ctl {
        Ctl::link(
            MnPress::MainLink,
            crate::screen::build::core::text::ADD_MANAGE_MNEMONICS.get(self.settings.language),
        )
        .compact()
    }
}
