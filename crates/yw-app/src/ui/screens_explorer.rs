//! Block explorer controls (2026-11-11, spec/04 §2.6, §2.11 "블록 탐색기"): the command ids, the
//! S15 card "블록 탐색기" (네트워크(RPC) section, after "네트워크별 RPC 주소") and the small
//! button rows other screens add next to a hash or an address. The logic is `app_explorer`.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): the builders, their helpers and texts moved to yw-engine
//! `screen::build::explorer` (bodies unchanged); this file keeps the control ids of its controls
//! (`ids`) and the tests that need an `App`, which only the Windows shell has.

/// Command ids (17,200–17,709; the whole map is `ui::command_ids`).
pub mod ids {
    /// S15 card: the transaction template field.
    pub const EDIT_TX: u16 = 17_200;
    /// S15 card: the address template field.
    pub const EDIT_ADDRESS: u16 = 17_201;
    /// S15 card: `저장`.
    pub const SAVE: u16 = 17_202;
    /// S15 card: `취소`.
    pub const CANCEL: u16 = 17_203;
    /// EVM account card `탐색기에서 주소 보기`.
    pub const CARD_EVM: u16 = 17_204;
    /// Solana account card `탐색기에서 주소 보기`.
    pub const CARD_SOL: u16 = 17_205;
    /// Bitcoin account card `탐색기에서 주소 보기`.
    pub const CARD_BTC: u16 = 17_206;
    /// Zcash account card `탐색기에서 주소 보기`.
    pub const CARD_ZEC: u16 = 17_207;
    /// `HyperCore` card `탐색기에서 주소 보기`.
    pub const CARD_HC: u16 = 17_208;
    /// EVM send result `탐색기에서 열기`.
    pub const RESULT_EVM_OPEN: u16 = 17_210;
    /// EVM send result `탐색기 링크 복사`.
    pub const RESULT_EVM_COPY: u16 = 17_211;
    /// Solana send result `탐색기에서 열기`.
    pub const RESULT_SOL_OPEN: u16 = 17_212;
    /// Solana send result `탐색기 링크 복사`.
    pub const RESULT_SOL_COPY: u16 = 17_213;
    /// Bitcoin send result `탐색기에서 열기`.
    pub const RESULT_BTC_OPEN: u16 = 17_214;
    /// Bitcoin send result `탐색기 링크 복사`.
    pub const RESULT_BTC_COPY: u16 = 17_215;
    /// Zcash send result line `탐색기에서 열기`.
    pub const RESULT_ZEC_OPEN: u16 = 17_216;
    /// Zcash send result line `탐색기 링크 복사`.
    pub const RESULT_ZEC_COPY: u16 = 17_217;
    /// S15 card rows ([`ROW_STRIDE`] ids per row: `변경`, `기본값으로`), in
    /// `Wallet::explorer_networks` order.
    pub const ROW_BASE: u16 = 17_220;
    /// Ids per card row.
    pub const ROW_STRIDE: u16 = 2;
    /// Card rows span (50 rows × 2; at most 7 + 32 + 2 + 2 + 2 + 2 = 47 networks). 2026-11-22
    /// (S4d E0c): the row count is the wallet's `app_explorer::EXPLORER_ROWS`.
    pub const ROW_SPAN: u16 = yw_engine::wallet::app_explorer::EXPLORER_ROWS * ROW_STRIDE;
    /// Ids per activity row (`탐색기에서 열기`, `탐색기 링크 복사`).
    pub const ACTIVITY_STRIDE: u16 = 2;
    /// Solana activity rows (display order, as `Wallet::sol_activity_tx_ids`).
    pub const SOL_ACTIVITY_BASE: u16 = 17_320;
    /// Solana activity span (64 rows × 2).
    pub const SOL_ACTIVITY_SPAN: u16 = 128;
    /// Bitcoin activity rows (display order, as `BtcUi::activity_rows`).
    pub const BTC_ACTIVITY_BASE: u16 = 17_450;
    /// Bitcoin activity span (50 rows × 2).
    pub const BTC_ACTIVITY_SPAN: u16 = 100;
    /// Zcash activity rows (newest first, as drawn).
    pub const ZEC_ACTIVITY_BASE: u16 = 17_550;
    /// Zcash activity span (80 rows × 2).
    pub const ZEC_ACTIVITY_SPAN: u16 = 160;

    const _: () = assert!(RESULT_ZEC_COPY < ROW_BASE);
    const _: () = assert!(ROW_BASE + ROW_SPAN <= SOL_ACTIVITY_BASE);
    const _: () = assert!(SOL_ACTIVITY_BASE + SOL_ACTIVITY_SPAN <= BTC_ACTIVITY_BASE);
    const _: () = assert!(BTC_ACTIVITY_BASE + BTC_ACTIVITY_SPAN <= ZEC_ACTIVITY_BASE);
    const _: () = assert!(ZEC_ACTIVITY_BASE + ZEC_ACTIVITY_SPAN <= 17_710);

    /// Every fixed id (`ui::command_ids` checks them against all ranges).
    pub const FIXED: &[u16] = &[
        EDIT_TX,
        EDIT_ADDRESS,
        SAVE,
        CANCEL,
        CARD_EVM,
        CARD_SOL,
        CARD_BTC,
        CARD_ZEC,
        CARD_HC,
        RESULT_EVM_OPEN,
        RESULT_EVM_COPY,
        RESULT_SOL_OPEN,
        RESULT_SOL_COPY,
        RESULT_BTC_OPEN,
        RESULT_BTC_COPY,
        RESULT_ZEC_OPEN,
        RESULT_ZEC_COPY,
    ];

    /// The press control `id` stands for (2026-11-18, S3 C3: `ui::cmd_table`); `None` when `id`
    /// is not one of this module's presses (the card's two edits are fields, not presses).
    #[must_use]
    pub fn press_of(id: u16) -> Option<yw_engine::cmd::ExplorerPress> {
        use yw_engine::cmd::{ExplorerLinkAction, ExplorerPress, ExplorerRowAction, Row};
        let link = |position: u16| {
            (
                Row(position / ACTIVITY_STRIDE),
                if position.is_multiple_of(ACTIVITY_STRIDE) {
                    ExplorerLinkAction::Open
                } else {
                    ExplorerLinkAction::Copy
                },
            )
        };
        let within = |base: u16, span: u16| id.checked_sub(base).filter(|offset| *offset < span);
        Some(match id {
            SAVE => ExplorerPress::Save,
            CANCEL => ExplorerPress::Cancel,
            CARD_EVM => ExplorerPress::CardEvm,
            CARD_SOL => ExplorerPress::CardSol,
            CARD_BTC => ExplorerPress::CardBtc,
            CARD_ZEC => ExplorerPress::CardZec,
            CARD_HC => ExplorerPress::CardHc,
            RESULT_EVM_OPEN => ExplorerPress::ResultEvmOpen,
            RESULT_EVM_COPY => ExplorerPress::ResultEvmCopy,
            RESULT_SOL_OPEN => ExplorerPress::ResultSolOpen,
            RESULT_SOL_COPY => ExplorerPress::ResultSolCopy,
            RESULT_BTC_OPEN => ExplorerPress::ResultBtcOpen,
            RESULT_BTC_COPY => ExplorerPress::ResultBtcCopy,
            RESULT_ZEC_OPEN => ExplorerPress::ResultZecOpen,
            RESULT_ZEC_COPY => ExplorerPress::ResultZecCopy,
            _ => {
                if let Some(position) = within(ROW_BASE, ROW_SPAN) {
                    ExplorerPress::Row(
                        Row(position / ROW_STRIDE),
                        if position.is_multiple_of(ROW_STRIDE) {
                            ExplorerRowAction::Edit
                        } else {
                            ExplorerRowAction::Reset
                        },
                    )
                } else if let Some(position) = within(SOL_ACTIVITY_BASE, SOL_ACTIVITY_SPAN) {
                    let (row, action) = link(position);
                    ExplorerPress::SolActivity(row, action)
                } else if let Some(position) = within(BTC_ACTIVITY_BASE, BTC_ACTIVITY_SPAN) {
                    let (row, action) = link(position);
                    ExplorerPress::BtcActivity(row, action)
                } else {
                    let (row, action) = link(within(ZEC_ACTIVITY_BASE, ZEC_ACTIVITY_SPAN)?);
                    ExplorerPress::ZecActivity(row, action)
                }
            }
        })
    }

    /// The control id of `press` (the inverse of [`press_of`]).
    #[must_use]
    pub const fn id_of(press: yw_engine::cmd::ExplorerPress) -> u16 {
        use yw_engine::cmd::{ExplorerLinkAction, ExplorerPress, ExplorerRowAction, Row};
        const fn link(base: u16, Row(row): Row, action: ExplorerLinkAction) -> u16 {
            base.wrapping_add(row.wrapping_mul(ACTIVITY_STRIDE))
                .wrapping_add(match action {
                    ExplorerLinkAction::Open => 0,
                    ExplorerLinkAction::Copy => 1,
                })
        }
        match press {
            ExplorerPress::Save => SAVE,
            ExplorerPress::Cancel => CANCEL,
            ExplorerPress::CardEvm => CARD_EVM,
            ExplorerPress::CardSol => CARD_SOL,
            ExplorerPress::CardBtc => CARD_BTC,
            ExplorerPress::CardZec => CARD_ZEC,
            ExplorerPress::CardHc => CARD_HC,
            ExplorerPress::ResultEvmOpen => RESULT_EVM_OPEN,
            ExplorerPress::ResultEvmCopy => RESULT_EVM_COPY,
            ExplorerPress::ResultSolOpen => RESULT_SOL_OPEN,
            ExplorerPress::ResultSolCopy => RESULT_SOL_COPY,
            ExplorerPress::ResultBtcOpen => RESULT_BTC_OPEN,
            ExplorerPress::ResultBtcCopy => RESULT_BTC_COPY,
            ExplorerPress::ResultZecOpen => RESULT_ZEC_OPEN,
            ExplorerPress::ResultZecCopy => RESULT_ZEC_COPY,
            ExplorerPress::Row(Row(row), action) => ROW_BASE
                .wrapping_add(row.wrapping_mul(ROW_STRIDE))
                .wrapping_add(match action {
                    ExplorerRowAction::Edit => 0,
                    ExplorerRowAction::Reset => 1,
                }),
            ExplorerPress::SolActivity(row, action) => link(SOL_ACTIVITY_BASE, row, action),
            ExplorerPress::BtcActivity(row, action) => link(BTC_ACTIVITY_BASE, row, action),
            ExplorerPress::ZecActivity(row, action) => link(ZEC_ACTIVITY_BASE, row, action),
        }
    }

    /// The two ids of activity row `row` of a list starting at `base` (`None` past `span`).
    #[must_use]
    pub fn activity_ids(base: u16, span: u16, row: usize) -> Option<(u16, u16)> {
        let offset = u16::try_from(row).ok()?.checked_mul(ACTIVITY_STRIDE)?;
        (offset.checked_add(1)? < span).then(|| {
            let open = base.saturating_add(offset);
            (open, open.saturating_add(1))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ids::{
        ACTIVITY_STRIDE, BTC_ACTIVITY_BASE, BTC_ACTIVITY_SPAN, ZEC_ACTIVITY_BASE,
        ZEC_ACTIVITY_SPAN, activity_ids,
    };

    #[test]
    fn activity_ids_stay_in_their_span() {
        assert_eq!(
            activity_ids(BTC_ACTIVITY_BASE, BTC_ACTIVITY_SPAN, 0),
            Some((BTC_ACTIVITY_BASE, BTC_ACTIVITY_BASE + 1))
        );
        let last = usize::from(BTC_ACTIVITY_SPAN / ACTIVITY_STRIDE) - 1;
        assert_eq!(
            activity_ids(BTC_ACTIVITY_BASE, BTC_ACTIVITY_SPAN, last),
            Some((BTC_ACTIVITY_BASE + 98, BTC_ACTIVITY_BASE + 99))
        );
        assert_eq!(
            activity_ids(BTC_ACTIVITY_BASE, BTC_ACTIVITY_SPAN, last + 1),
            None
        );
        assert_eq!(
            activity_ids(ZEC_ACTIVITY_BASE, ZEC_ACTIVITY_SPAN, 79),
            Some((ZEC_ACTIVITY_BASE + 158, ZEC_ACTIVITY_BASE + 159))
        );
    }
}
