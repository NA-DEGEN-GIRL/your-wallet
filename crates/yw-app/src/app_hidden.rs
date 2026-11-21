//! Hidden accounts (spec/04 §2.6, 2026-11-08). `숨기기` only marks meta `hidden` (and takes the
//! account out of every dApp grant, spec/05 §4.9); until now nothing showed those accounts again.
//! The EVM, Solana and Bitcoin account cards (`내 EVM 계정`, `내 Solana 계정`, `내 Bitcoin 계정`)
//! list them under `숨긴 계정 n개 보기 ▸`, and `다시 보이기` clears the mark. Site connections
//! are not restored (the user connects again from the dApp). Bitcoin accounts can be hidden since
//! 2026-11-15 (meta `btc_account_view`, spec/08 §12.3d); the list shows the settings network's.

use crate::app::{App, Wallet};
use crate::app_sol::SolAccountId;
use crate::meta::EvmAccountPref;
use crate::ui::main_window::{Ctl, Item, Tone};
use yw_core::lang::Lang;
use yw_engine::cmd::{HiddenPress, Row};

/// The fixed texts of the hidden-account rows (spec/14).
pub mod text {
    yw_core::texts! {
        /// The note after `숨기기`: {0} the account's label (2026-11-15: "… '내 계정' 아래 …" before;
        /// the cards are `내 EVM 계정` and `내 Solana 계정`).
        HIDDEN_NOTE(1) = "'{0}'을(를) 숨겼습니다. 이 계정의 사이트 연결도 해제했습니다. 계정 카드 아래 '숨긴 계정'에서 다시 볼 수 있습니다."
            / "'{0}' is hidden. Its site connections were removed too. You can see it again under 'Hidden accounts' on the accounts card.";
        /// The opened toggle: {0} count.
        TOGGLE_CLOSE(1) = "숨긴 계정 {0}개 접기 ▾" / "Hide hidden accounts ({0}) ▾";
        /// The closed toggle: {0} count.
        TOGGLE_OPEN(1) = "숨긴 계정 {0}개 보기 ▸" / "Show hidden accounts ({0}) ▸";
        /// The help line of the opened list.
        HIDDEN_HELP = "숨긴 계정은 목록·보내기·사이트 연결에서 빠질 뿐 블록체인의 자산은 그대로입니다. '다시 보이기'를 누르면 목록으로 돌아옵니다(사이트 연결은 dApp에서 다시 하세요)."
            / "Hidden accounts are only left out of the list, sending and site connections; their assets on the blockchain stay as they are. 'Unhide' brings an account back to the list (connect it to sites again from the dApp).";
        /// A hidden row's title: {0} label, {1} source.
        HIDDEN_ROW(2) = "{0} · {1} · 숨김" / "{0} · {1} · hidden";
        /// A Solana balance: {0} amount.
        BALANCE(1) = "잔액 {0}" / "Balance {0}";
        /// The last-read balance line: {0} the balance text.
        LAST_READ(1) = "마지막으로 읽은 {0}" / "{0} (last read)";
        /// The row button.
        UNHIDE = "다시 보이기" / "Unhide";
        /// The note after `다시 보이기`: {0} label.
        UNHIDDEN_NOTE(1) = "'{0}'을(를) 다시 보이게 했습니다. 사이트에서 쓰려면 dApp에서 다시 연결하세요."
            / "'{0}' is visible again. To use it on a site, connect again from the dApp.";
    }
}

/// Command ids (blocks 16,100–16,199 and 16,200–16,599 of `ui::command_ids`).
pub mod ids {
    /// EVM `숨긴 계정 n개 보기 ▸` / `접기 ▾`.
    pub const EVM_TOGGLE: u16 = 16_200;
    /// Solana `숨긴 계정 n개 보기 ▸` / `접기 ▾`.
    pub const SOL_TOGGLE: u16 = 16_201;
    /// EVM `다시 보이기` (one id per hidden row).
    pub const EVM_ROW_BASE: u16 = 16_210;
    /// Solana `다시 보이기` (one id per hidden row).
    pub const SOL_ROW_BASE: u16 = 16_400;
    /// Rows of each list.
    pub const ROW_SPAN: u16 = 190;
    /// Bitcoin `숨긴 계정 n개 보기 ▸` / `접기 ▾` (2026-11-15).
    pub const BTC_TOGGLE: u16 = 16_100;
    /// Bitcoin `다시 보이기` (one id per hidden row of the settings network).
    pub const BTC_ROW_BASE: u16 = 16_110;
    /// Bitcoin rows (`btc_accounts` bound + the BIP84 account 0).
    pub const BTC_ROW_SPAN: u16 = 65;
    /// Every fixed id.
    pub const FIXED: &[u16] = &[EVM_TOGGLE, SOL_TOGGLE, BTC_TOGGLE];

    /// The press control `id` stands for (2026-11-18, S3 C1: `ui::cmd_table`); `None` when `id`
    /// is not one of this module's.
    #[must_use]
    pub fn press_of(id: u16) -> Option<yw_engine::cmd::HiddenPress> {
        use yw_engine::cmd::{HiddenPress, Row};
        let row = |base: u16, span: u16| {
            id.checked_sub(base)
                .filter(|offset| *offset < span)
                .map(Row)
        };
        Some(match id {
            EVM_TOGGLE => HiddenPress::EvmToggle,
            SOL_TOGGLE => HiddenPress::SolToggle,
            BTC_TOGGLE => HiddenPress::BtcToggle,
            _ => {
                if let Some(row) = row(EVM_ROW_BASE, ROW_SPAN) {
                    HiddenPress::EvmUnhide(row)
                } else if let Some(row) = row(SOL_ROW_BASE, ROW_SPAN) {
                    HiddenPress::SolUnhide(row)
                } else {
                    HiddenPress::BtcUnhide(row(BTC_ROW_BASE, BTC_ROW_SPAN)?)
                }
            }
        })
    }

    /// The control id of `press` (the inverse of [`press_of`]).
    #[must_use]
    pub const fn id_of(press: yw_engine::cmd::HiddenPress) -> u16 {
        use yw_engine::cmd::{HiddenPress, Row};
        match press {
            HiddenPress::EvmToggle => EVM_TOGGLE,
            HiddenPress::SolToggle => SOL_TOGGLE,
            HiddenPress::BtcToggle => BTC_TOGGLE,
            HiddenPress::EvmUnhide(Row(row)) => EVM_ROW_BASE.wrapping_add(row),
            HiddenPress::SolUnhide(Row(row)) => SOL_ROW_BASE.wrapping_add(row),
            HiddenPress::BtcUnhide(Row(row)) => BTC_ROW_BASE.wrapping_add(row),
        }
    }
}

/// Which account card.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// EVM tab.
    Evm,
    /// Solana tab.
    Sol,
    /// Bitcoin tab (the settings network's accounts).
    Btc,
}

/// A hidden account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiddenId {
    /// An EVM account.
    Evm(EvmAccountPref),
    /// A Solana account.
    Sol(SolAccountId),
    /// A Bitcoin account of a network.
    Btc(yw_core::btc::BtcNetwork, yw_core::btc::BtcAccountId),
}

/// One row of the hidden list: which account, its label, address text and source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiddenRow {
    /// The account.
    pub id: HiddenId,
    /// Its label.
    pub label: String,
    /// Its address (as stored).
    pub address: String,
    /// Where it comes from (`m/…`, the recovery phrase, `YubiKey`).
    pub source: String,
}

/// The note after `숨기기` (the way back is in the same card).
#[must_use]
pub fn hidden_note(lang: Lang, label: &str) -> String {
    text::HIDDEN_NOTE.fill(lang, [label])
}

impl Wallet {
    /// The hidden accounts of `family`, in the order of the visible rows' sources.
    #[must_use]
    #[expect(clippy::too_many_lines, reason = "one block per kind of account")]
    pub fn hidden_rows(&self, family: Family) -> Vec<HiddenRow> {
        let Some(meta) = self.meta.as_ref() else {
            return Vec::new();
        };
        let mut rows = Vec::new();
        match family {
            Family::Evm => {
                for account in meta.evm_accounts.iter().filter(|account| account.hidden) {
                    rows.push(HiddenRow {
                        id: HiddenId::Evm(EvmAccountPref::Index(account.index)),
                        label: account.label.clone(),
                        address: account.address.clone(),
                        source: format!("m/44'/60'/0'/0/{}", account.index),
                    });
                }
                for entry in &meta.mnemonics {
                    for account in entry.evm.iter().filter(|account| account.hidden) {
                        rows.push(HiddenRow {
                            id: HiddenId::Evm(EvmAccountPref::Mnemonic(
                                entry.record_id,
                                account.index,
                            )),
                            label: account.label.clone(),
                            address: account.address.clone(),
                            source: format!("{} · m/44'/60'/0'/0/{}", entry.label, account.index),
                        });
                    }
                }
                for account in meta.hw_accounts.evm.iter().filter(|account| account.hidden) {
                    rows.push(HiddenRow {
                        id: HiddenId::Evm(EvmAccountPref::Hardware(account.index)),
                        label: account.label.clone(),
                        address: account.address.clone(),
                        // The holder cards as on the drop-down (2026-11-15; `YubiKey` before).
                        source: self
                            .card_source(crate::ui::screens_accounts::evm_card_role(account.index)),
                    });
                }
            }
            Family::Btc => {
                let network = self.btc_network_now();
                let ctx = self.btc_ctx();
                for (account, label) in meta.btc_labels(network, self.settings.language) {
                    if !meta.btc_hidden(network, account) {
                        continue;
                    }
                    let Some(stored) = ctx.accounts().into_iter().find(|m| m.id() == account)
                    else {
                        continue;
                    };
                    rows.push(HiddenRow {
                        id: HiddenId::Btc(network, account),
                        label,
                        address: stored
                            .address(yw_core::bip32::path::BtcChain::Receive, 0)
                            .map(|address| address.as_str().to_owned())
                            .unwrap_or_default(),
                        source: self.btc_source_text(stored.account(), network),
                    });
                }
            }
            Family::Sol => {
                for account in meta.sol_accounts.iter().filter(|account| account.hidden) {
                    rows.push(HiddenRow {
                        id: HiddenId::Sol(SolAccountId::Derived(account.index)),
                        label: account.label.clone(),
                        address: account.address.clone(),
                        source: SolAccountId::Derived(account.index)
                            .path_text_in(self.settings.language),
                    });
                }
                for (id, account) in meta
                    .mnemonic_accounts
                    .sol
                    .iter()
                    .filter(|(_, account)| account.hidden)
                {
                    let source = meta
                        .mnemonics
                        .iter()
                        .find(|entry| entry.record_id == *id)
                        .map(|entry| entry.label.clone());
                    let path = SolAccountId::Mnemonic(*id, account.index)
                        .path_text_in(self.settings.language);
                    rows.push(HiddenRow {
                        id: HiddenId::Sol(SolAccountId::Mnemonic(*id, account.index)),
                        label: account.label.clone(),
                        address: account.address.clone(),
                        source: source
                            .map_or_else(|| path.clone(), |name| format!("{name} · {path}")),
                    });
                }
                for account in meta.hw_accounts.sol.iter().filter(|account| account.hidden) {
                    rows.push(HiddenRow {
                        id: HiddenId::Sol(SolAccountId::Hardware(account.index)),
                        label: account.label.clone(),
                        address: account.address.clone(),
                        source: self
                            .card_source(crate::ui::screens_accounts::sol_card_role(account.index)),
                    });
                }
            }
        }
        rows
    }
}

impl App {
    /// The end of a `내 계정` card: `숨긴 계정 n개 보기 ▸` and, opened, the hidden rows with
    /// `다시 보이기` (nothing when no account is hidden).
    pub fn hidden_items(&self, family: Family, items: &mut Vec<Item>) {
        let rows = self.hidden_rows(family);
        if rows.is_empty() {
            return;
        }
        let (toggle, base, span) = match family {
            Family::Evm => (ids::EVM_TOGGLE, ids::EVM_ROW_BASE, ids::ROW_SPAN),
            Family::Sol => (ids::SOL_TOGGLE, ids::SOL_ROW_BASE, ids::ROW_SPAN),
            Family::Btc => (ids::BTC_TOGGLE, ids::BTC_ROW_BASE, ids::BTC_ROW_SPAN),
        };
        let lang = self.settings.language;
        let open = self.hidden_open;
        let count = rows.len().to_string();
        items.push(Item::Row(vec![Ctl::link(
            toggle,
            &if open {
                text::TOGGLE_CLOSE.fill(lang, [&count])
            } else {
                text::TOGGLE_OPEN.fill(lang, [&count])
            },
        )]));
        if !open {
            return;
        }
        items.push(Item::Help(text::HIDDEN_HELP.get(lang).to_owned()));
        for (row, hidden) in rows.into_iter().take(usize::from(span)).enumerate() {
            items.push(Item::Muted(
                text::HIDDEN_ROW.fill(lang, [&hidden.label, &hidden.source]),
            ));
            let (shown, balance) = match family {
                Family::Evm => (
                    yw_core::evm::address::parse_address(&hidden.address).map_or_else(
                        |_| hidden.address.clone(),
                        |parsed| yw_core::evm::display::format_address(&parsed),
                    ),
                    self.balance_text(&hidden.address),
                ),
                Family::Sol => (
                    crate::ui::screens_btc::grouped(&hidden.address),
                    yw_core::sol::SolAddress::parse(&hidden.address)
                        .ok()
                        .and_then(|address| self.sol_balance(&address))
                        .map(|lamports| text::BALANCE.fill(lang, [&Wallet::sol_text(lamports)])),
                ),
                // The whole address, grouped like the tab's (spec/04 §3.3), and the available
                // balance the account's last refresh left in meta.
                Family::Btc => (
                    crate::ui::screens_btc::grouped(&hidden.address),
                    self.btc_hidden_balance(hidden.id),
                ),
            };
            items.push(Item::Mono(shown));
            if let Some(balance) = balance {
                items.push(Item::Help(text::LAST_READ.fill(lang, [&balance])));
            }
            items.push(Item::Row(vec![Ctl::button(
                base.saturating_add(u16::try_from(row).unwrap_or(u16::MAX)),
                text::UNHIDE.get(lang),
            )]));
        }
    }
}

impl Wallet {
    /// The hidden-account presses (2026-11-18, S3 C1: a `HiddenPress`; before, the control id).
    pub(crate) fn on_hidden(&mut self, press: HiddenPress) {
        let family = match press {
            HiddenPress::EvmToggle | HiddenPress::SolToggle | HiddenPress::BtcToggle => {
                self.hidden_open = !self.hidden_open;
                self.refresh();
                return;
            }
            HiddenPress::EvmUnhide(Row(row)) => (Family::Evm, row),
            HiddenPress::SolUnhide(Row(row)) => (Family::Sol, row),
            HiddenPress::BtcUnhide(Row(row)) => (Family::Btc, row),
        };
        self.unhide(family.0, usize::from(family.1));
    }
}

impl App {
    /// Test adapter (S3 C1, plan §3.2): presses hidden-account control `id` directly, as the
    /// tests did before; `false` when `id` is not one.
    #[cfg(test)]
    pub(crate) fn on_hidden_command(&mut self, id: u16) -> bool {
        self.press_family(
            id,
            |press| match press {
                yw_engine::cmd::Press::Hidden(press) => Some(press),
                _ => None,
            },
            |app, press| {
                app.on_hidden(press);
                true
            },
        )
    }
}

impl Wallet {
    /// `다시 보이기` of hidden row `row`: clears the mark only (no site grant comes back).
    pub fn unhide(&mut self, family: Family, row: usize) {
        let Some(hidden) = self.hidden_rows(family).into_iter().nth(row) else {
            return;
        };
        let Some(meta) = self.meta.as_mut() else {
            return;
        };
        let mark = |hidden: &mut bool| *hidden = false;
        match hidden.id {
            HiddenId::Btc(network, account) => {
                meta.btc_view_update(network, account, |view| view.hidden = false);
            }
            HiddenId::Evm(EvmAccountPref::Index(index)) => meta
                .evm_accounts
                .iter_mut()
                .filter(|account| account.index == index)
                .for_each(|account| mark(&mut account.hidden)),
            HiddenId::Evm(EvmAccountPref::Mnemonic(record, index)) => meta
                .mnemonics
                .iter_mut()
                .filter(|entry| entry.record_id == record)
                .flat_map(|entry| entry.evm.iter_mut())
                .filter(|account| account.index == index)
                .for_each(|account| mark(&mut account.hidden)),
            HiddenId::Evm(EvmAccountPref::Hardware(index)) => meta
                .hw_accounts
                .evm
                .iter_mut()
                .filter(|account| account.index == index)
                .for_each(|account| mark(&mut account.hidden)),
            HiddenId::Evm(EvmAccountPref::Record(_)) | HiddenId::Sol(SolAccountId::Imported(_)) => {
                return;
            }
            HiddenId::Sol(SolAccountId::Derived(index)) => meta
                .sol_accounts
                .iter_mut()
                .filter(|account| account.index == index)
                .for_each(|account| mark(&mut account.hidden)),
            HiddenId::Sol(SolAccountId::Mnemonic(record, index)) => meta
                .mnemonic_accounts
                .sol
                .iter_mut()
                .filter(|(id, account)| *id == record && account.index == index)
                .for_each(|(_, account)| mark(&mut account.hidden)),
            HiddenId::Sol(SolAccountId::Hardware(index)) => meta
                .hw_accounts
                .sol
                .iter_mut()
                .filter(|account| account.index == index)
                .for_each(|account| mark(&mut account.hidden)),
        }
        self.save_meta();
        self.notice(
            text::UNHIDDEN_NOTE.fill(self.settings.language, [&hidden.label]),
            Tone::Info,
        );
        self.refresh();
    }
}
