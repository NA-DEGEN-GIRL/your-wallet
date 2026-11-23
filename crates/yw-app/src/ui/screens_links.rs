//! Copyable values, icon actions and the account drop-downs of the main wallet tab (2026-11-11,
//! spec/04 §2.6): a transaction hash or an address is drawn whole on a flat button whose click
//! copies it ([`Item::CopyLine`]), with small icon buttons at the right end of its line —
//! `탐색기에서 열기` ↗, `탐색기 링크 복사` 🔗, `이 주소 저장` ☆ — instead of the rows of
//! labelled buttons under it; and `내 계정` picks its account from a drop-down like the network's.
//!
//! Copy rules: the account cards' own address, the token contracts, the recipients of the
//! wallet's **own** sent transactions (its signed journal) and every transaction hash may be
//! copied. The senders of the received history (`screens_received`) never are — they stay
//! display-only (address poisoning, spec/07 §12.3).
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): the builders, their helpers and texts moved to yw-engine
//! `screen::build::links` (bodies unchanged); this file keeps the control ids of its controls
//! (`ids`) and the tests' press adapter, which only the Windows shell has.

/// Command ids (18,400–18,659; the whole map is `ui::command_ids`).
pub mod ids {
    /// The EVM `내 계정` drop-down button.
    pub const PICKER_EVM: u16 = 18_400;
    /// The Solana `내 Solana 계정` drop-down button.
    pub const PICKER_SOL: u16 = 18_401;
    /// The Bitcoin `내 Bitcoin 계정` drop-down button.
    pub const PICKER_BTC: u16 = 18_402;
    /// The Zcash `내 Zcash 계정` drop-down button (2026-11-15: its items are the key sources).
    pub const PICKER_ZEC: u16 = 18_403;
    /// Every fixed id.
    pub const FIXED: [u16; 4] = [PICKER_EVM, PICKER_SOL, PICKER_BTC, PICKER_ZEC];
    /// EVM activity: a click on the recipient copies it (row order of `Wallet::activity_rows`).
    pub const EVM_TO_BASE: u16 = 18_410;
    /// EVM recipient span (`app_evm::MAX_ACTIVITY_ROWS`).
    pub const EVM_TO_SPAN: u16 = 50;
    /// Solana activity recipients (display order, as `Wallet::sol_activity_counterparties`).
    pub const SOL_TO_BASE: u16 = 18_460;
    /// Solana recipient span (the journal's 64 records).
    pub const SOL_TO_SPAN: u16 = 64;
    /// Bitcoin activity recipients (display order, as `BtcUi::activity_rows`).
    pub const BTC_TO_BASE: u16 = 18_530;
    /// Bitcoin recipient span (`app_btc::BTC_MAX_ACTIVITY_ROWS`).
    pub const BTC_TO_SPAN: u16 = 50;
    /// Zcash activity recipients (newest first, as drawn).
    pub const ZEC_TO_BASE: u16 = 18_580;
    /// Zcash recipient span (the journal's 80 records).
    pub const ZEC_TO_SPAN: u16 = 80;

    const _: () = assert!(PICKER_ZEC < EVM_TO_BASE);
    const _: () = assert!(EVM_TO_BASE + EVM_TO_SPAN <= SOL_TO_BASE);
    const _: () = assert!(SOL_TO_BASE + SOL_TO_SPAN <= BTC_TO_BASE);
    const _: () = assert!(BTC_TO_BASE + BTC_TO_SPAN <= ZEC_TO_BASE);
    const _: () = assert!(ZEC_TO_BASE + ZEC_TO_SPAN <= 18_660);

    /// The row of `id` in a list starting at `base` (`None` outside it).
    #[must_use]
    pub fn row_of(id: u16, base: u16, span: u16) -> Option<usize> {
        id.checked_sub(base)
            .filter(|offset| *offset < span)
            .map(usize::from)
    }

    /// The press control `id` stands for (2026-11-18, S3 C1: `ui::cmd_table`); `None` when `id`
    /// is not one of this module's.
    #[must_use]
    pub fn press_of(id: u16) -> Option<yw_engine::cmd::LinksPress> {
        use yw_engine::cmd::{LinksPress, Row};
        let row = |base: u16, span: u16| {
            id.checked_sub(base)
                .filter(|offset| *offset < span)
                .map(Row)
        };
        Some(match id {
            PICKER_EVM => LinksPress::PickerEvm,
            PICKER_SOL => LinksPress::PickerSol,
            PICKER_BTC => LinksPress::PickerBtc,
            PICKER_ZEC => LinksPress::PickerZec,
            _ => {
                if let Some(row) = row(EVM_TO_BASE, EVM_TO_SPAN) {
                    LinksPress::EvmTo(row)
                } else if let Some(row) = row(SOL_TO_BASE, SOL_TO_SPAN) {
                    LinksPress::SolTo(row)
                } else if let Some(row) = row(BTC_TO_BASE, BTC_TO_SPAN) {
                    LinksPress::BtcTo(row)
                } else {
                    LinksPress::ZecTo(row(ZEC_TO_BASE, ZEC_TO_SPAN)?)
                }
            }
        })
    }

    /// The control id of `press` (the inverse of [`press_of`]).
    #[must_use]
    pub const fn id_of(press: yw_engine::cmd::LinksPress) -> u16 {
        use yw_engine::cmd::{LinksPress, Row};
        match press {
            LinksPress::PickerEvm => PICKER_EVM,
            LinksPress::PickerSol => PICKER_SOL,
            LinksPress::PickerBtc => PICKER_BTC,
            LinksPress::PickerZec => PICKER_ZEC,
            LinksPress::EvmTo(Row(row)) => EVM_TO_BASE.wrapping_add(row),
            LinksPress::SolTo(Row(row)) => SOL_TO_BASE.wrapping_add(row),
            LinksPress::BtcTo(Row(row)) => BTC_TO_BASE.wrapping_add(row),
            LinksPress::ZecTo(Row(row)) => ZEC_TO_BASE.wrapping_add(row),
        }
    }
}

#[cfg(test)]
impl crate::app::App {
    /// Test adapter (S3 C1, plan §3.2): presses drop-down or recipient control `id` directly, as
    /// the tests did before; `false` when `id` is not one.
    pub(crate) fn on_links_command(&mut self, id: u16) -> bool {
        self.press_family(
            id,
            |press| match press {
                yw_engine::cmd::Press::Links(press) => Some(press),
                _ => None,
            },
            |app, press| {
                crate::app::test_steps::on_links(&mut app.wallet, press);
                true
            },
        )
    }
}
