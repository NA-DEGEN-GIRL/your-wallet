//! Bitcoin account names and hiding (2026-11-15; spec/04 §2.6, spec/08 §3.6, §12.3d): the
//! account card's `이름 바꾸기` and `숨기기` like the EVM and Solana cards. Names and hidden marks
//! live in the lenient top-level meta key `btc_account_view` ([`crate::meta::BtcAccountView`]),
//! never inside the strictly decoded `btc`/`btc_accounts*` keys. Hiding takes the account out of
//! the drop-down and every dApp connect list and deletes the Bitcoin grants listing its stable
//! address (spec/05 §4.9); the selection falls back like EVM's. Labels are never logged (D28).
//!
//! Before 2026-11-15 a Bitcoin account had no name of its own (its type and number, or a one-key
//! account's shortened address) and could not be hidden.

use yw_core::bip32::path::BtcChain;
use yw_core::btc::{BtcAccountId, BtcAccountKey, BtcMeta, BtcNetwork};

use crate::errors::ErrorCode;
use crate::events::KeyJob;
use crate::logging;
use crate::screen::AccountSource;
use crate::screen::Tone;
use crate::text::is_valid_label;
use crate::wallet::Wallet;
use crate::wallet::app_btc::{ACCOUNT_SWITCH_BUSY, BtcUi};
use crate::wallet::app_hidden::HiddenId;
use crate::workers::journal::btc::BtcMetaOp;

impl Wallet {
    /// The name of a Bitcoin account of the settings network (meta `btc_account_view`, default
    /// `Bitcoin N`).
    #[must_use]
    pub(crate) fn btc_label_of(&self, account: &BtcMeta) -> String {
        self.meta.as_ref().map_or_else(
            || crate::meta::BTC_ACCOUNT_LABEL.fill(self.settings.language, ["1"]),
            |meta| meta.btc_label(account.network(), account.id(), self.settings.language),
        )
    }

    /// Whether account `account` of the settings network is hidden.
    #[must_use]
    pub fn btc_is_hidden(&self, account: BtcAccountId) -> bool {
        self.meta
            .as_ref()
            .is_some_and(|meta| meta.btc_hidden(self.btc_network_now(), account))
    }

    /// The source part of a Bitcoin account's drop-down item (spec/04 §2.6): recovery words, an
    /// imported key, an EVM account's key or the `YubiKey` cards holding its key.
    #[must_use]
    pub(crate) fn btc_source(account: &BtcAccountKey, network: BtcNetwork) -> AccountSource {
        match account.id() {
            BtcAccountId::Hd { mnemonic, .. } => {
                AccountSource::Words(mnemonic.map(|id| *id.as_bytes()))
            }
            BtcAccountId::Imported { .. } => AccountSource::Imported,
            BtcAccountId::EvmShared { evm_index, .. } => AccountSource::EvmKey(evm_index),
            BtcAccountId::Hardware { .. } => {
                AccountSource::Card(crate::screen::btc_card_role(account, network))
            }
        }
    }

    /// The source of a hidden row (always named): as on the drop-down, recovery words by their
    /// set's label when there are several, else `복구 단어`.
    #[must_use]
    pub fn btc_source_text(&self, account: &BtcAccountKey, network: BtcNetwork) -> String {
        use crate::screen::text;
        let lang = self.settings.language;
        match Self::btc_source(account, network) {
            AccountSource::Words(mnemonic) => self
                .mnemonic_tag(mnemonic)
                .unwrap_or_else(|| text::SOURCE_WORDS.get(lang).to_owned()),
            AccountSource::Imported => text::SOURCE_IMPORTED.get(lang).to_owned(),
            AccountSource::Card(role) => self.card_source(role),
            AccountSource::EvmKey(index) => text::SOURCE_EVM_KEY.fill(lang, [&index.to_string()]),
        }
    }

    /// The visible account rows of the settings network (the drop-down's entries, in order).
    #[must_use]
    pub(crate) fn btc_visible_rows(&self) -> Vec<crate::wallet::app_btc::BtcAccountRow> {
        let ctx = self.btc_ctx();
        self.btc
            .account_rows(&ctx)
            .into_iter()
            .filter(|row| !self.btc_is_hidden(row.id))
            .collect()
    }

    /// The `잔액 …` line of a hidden Bitcoin row (the available balance the account's last
    /// refresh left in meta).
    #[must_use]
    pub(crate) fn btc_hidden_balance(&self, hidden: HiddenId) -> Option<String> {
        let HiddenId::Btc(_, account) = hidden else {
            return None;
        };
        let ctx = self.btc_ctx();
        let row = self
            .btc
            .account_rows(&ctx)
            .into_iter()
            .find(|row| row.id == account)?;
        Some(
            crate::wallet::app_hidden::text::BALANCE
                .fill(self.settings.language, [&BtcUi::amount_text(row.available)]),
        )
    }

    /// Whether the selected Bitcoin account `account` may be hidden (2026-11-15, as EVM and
    /// Solana): not the first recovery words' BIP84 account 0 (the default account), not an
    /// imported key (it has `삭제`), and not the last visible account of the network.
    #[must_use]
    pub(crate) fn btc_can_hide(&self, account: BtcAccountId) -> bool {
        let kind_ok =
            !matches!(account, BtcAccountId::Imported { .. }) && account != BtcAccountId::PRIMARY;
        kind_ok && self.btc_visible_rows().iter().any(|row| row.id != account)
    }

    /// `이름 바꾸기` of the selected Bitcoin account: opens its name field.
    pub fn btc_rename_start(&mut self) {
        let selected = self.btc_ctx().btc_meta().map(BtcMeta::id);
        self.btc.rename = selected;
        self.refresh();
    }

    /// `취소` of the name field.
    pub fn btc_rename_cancel(&mut self) {
        self.btc.rename = None;
        self.refresh();
    }

    /// `저장` of the name field (`label` as typed; trimmed, checked like every account label).
    pub fn btc_save_rename(&mut self, label: &str) {
        let Some(account) = self.btc.rename else {
            return;
        };
        let label = label.trim();
        if !is_valid_label(label) {
            self.banner(
                Some(ErrorCode::Inp017),
                ErrorCode::Inp017.text_in(self.settings.language),
            );
            self.refresh();
            return;
        }
        let network = self.btc_network_now();
        let lang = self.settings.language;
        if let Some(meta) = self.meta.as_mut() {
            // The other accounts keep the default names shown now (a default is numbered after
            // the stored names, so storing this one alone could renumber them).
            meta.reconcile_btc_view(lang);
            meta.btc_view_update(network, account, |view| {
                view.label = Some(label.to_owned());
            });
        }
        self.btc.rename = None;
        // The name itself is a label: never logged (D28).
        logging::info("btc", "btc.account_renamed", &[]);
        self.save_meta();
        self.refresh();
    }

    /// `숨기기` of the selected Bitcoin account ([`Self::btc_can_hide`]): marks it hidden, selects
    /// the default account (BIP84 account 0, or the first visible account of a wallet without
    /// it), deletes the Bitcoin grants listing its stable address and says where it went.
    /// Refused while a Bitcoin approval is open (the selection cannot change then).
    pub fn btc_hide_selected(&mut self) {
        let (account, address, fallback) = {
            let ctx = self.btc_ctx();
            let Some(meta) = ctx.btc_meta() else {
                return;
            };
            let account = meta.id();
            let address = meta
                .address(BtcChain::Receive, 0)
                .ok()
                .map(|address| address.as_str().to_owned());
            let fallback = ctx
                .accounts()
                .into_iter()
                .map(BtcMeta::id)
                .find(|id| *id != account && !self.btc_is_hidden(*id));
            (account, address, fallback)
        };
        if !self.btc_can_hide(account) {
            return;
        }
        if self.btc.slot {
            self.btc.account_message =
                Some(ACCOUNT_SWITCH_BUSY.get(self.settings.language).to_owned());
            self.refresh();
            return;
        }
        let Some(fallback) = fallback else {
            return;
        };
        let network = self.btc_network_now();
        let label = self
            .meta
            .as_ref()
            .map(|meta| meta.btc_label(network, account, self.settings.language))
            .unwrap_or_default();
        let lang = self.settings.language;
        if let Some(meta) = self.meta.as_mut() {
            meta.reconcile_btc_view(lang);
            meta.btc_view_update(network, account, |view| view.hidden = true);
        }
        self.btc.rename = None;
        self.btc.account_message = None;
        self.save_meta();
        // The selection is the key worker's (meta `btc_accounts*`): it falls back like EVM's.
        self.key(KeyJob::BtcMeta {
            op: BtcMetaOp::Select {
                network,
                account: fallback,
            },
        });
        logging::info("btc", "btc.account_hidden", &[]);
        if let Some(address) = address {
            self.btc_addresses_removed_from_sites(&[address]);
        }
        self.notice(
            crate::wallet::app_hidden::hidden_note(self.settings.language, &label),
            Tone::Info,
        );
        self.refresh();
    }
}
