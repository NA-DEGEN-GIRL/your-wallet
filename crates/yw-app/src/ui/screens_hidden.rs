//! The hidden-account rows at the end of the `내 EVM 계정`, `내 Solana 계정` and `내 Bitcoin 계정`
//! cards (spec/04 §2.6): their command ids and render builder. 2026-11-22 (S4d E0c): moved from
//! `app_hidden`, which keeps the rows (`Wallet::hidden_rows`), the presses and their texts.

use crate::app::{App, Wallet};
use crate::app_hidden::{Family, text};
use crate::ui::main_window::{Ctl, Item};

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
                    yw_engine::text::grouped(&hidden.address),
                    yw_core::sol::SolAddress::parse(&hidden.address)
                        .ok()
                        .and_then(|address| self.sol_balance(&address))
                        .map(|lamports| text::BALANCE.fill(lang, [&Wallet::sol_text(lamports)])),
                ),
                // The whole address, grouped like the tab's (spec/04 §3.3), and the available
                // balance the account's last refresh left in meta.
                Family::Btc => (
                    yw_engine::text::grouped(&hidden.address),
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
