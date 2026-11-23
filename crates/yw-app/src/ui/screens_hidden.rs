//! The hidden-account rows at the end of the `내 EVM 계정`, `내 Solana 계정` and `내 Bitcoin 계정`
//! cards (spec/04 §2.6): their command ids and render builder. 2026-11-22 (S4d E0c): moved from
//! `app_hidden`, which keeps the rows (`Wallet::hidden_rows`), the presses and their texts.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): the builders, their helpers and texts moved to yw-engine
//! `screen::build::hidden` (bodies unchanged); this file keeps the control ids of its controls
//! (`ids`), which only the Windows shell has.

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
