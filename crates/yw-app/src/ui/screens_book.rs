//! S14 주소록 (spec/04 §2.10) and the address-book parts of every send form: the `즐겨찾기`
//! chips above the recipient field, the Bitcoin `주소록에서 선택` list, and the inline
//! `주소록에 저장` prompt (send forms, send results, activity rows). State and commands are in
//! `crate::app_book`.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): the builders, their helpers and texts moved to yw-engine
//! `screen::build::book` (bodies unchanged); this file keeps the control ids of its controls
//! (`ids`), which only the Windows shell has.

/// Command ids of the address book (14,000–15,699).
pub mod ids {
    /// S14 family tab: EVM.
    pub const CHAIN_EVM: u16 = 14_000;
    /// S14 family tab: Solana.
    pub const CHAIN_SOL: u16 = 14_001;
    /// S14 family tab: Bitcoin.
    pub const CHAIN_BTC: u16 = 14_002;
    /// S14 address edit.
    pub const ADDR_EDIT: u16 = 14_003;
    /// S14 label edit.
    pub const LABEL_EDIT: u16 = 14_004;
    /// S14 verified check.
    pub const VERIFIED: u16 = 14_005;
    /// S14 `즐겨찾기에 추가` check.
    pub const FAVORITE: u16 = 14_006;
    /// S14 `추가` / `저장`.
    pub const SAVE: u16 = 14_007;
    /// S14 `취소` (editing).
    pub const CANCEL: u16 = 14_008;
    /// S14 look-alike `주소 전체를 직접 확인했습니다`.
    pub const FORM_ACK: u16 = 14_009;
    /// Prompt label edit.
    pub const PROMPT_LABEL_EDIT: u16 = 14_010;
    /// Prompt `저장`.
    pub const PROMPT_SAVE: u16 = 14_011;
    /// Prompt `취소`.
    pub const PROMPT_CANCEL: u16 = 14_012;
    /// Prompt look-alike check.
    pub const PROMPT_ACK: u16 = 14_013;
    /// Send form `주소록에 저장` (opens the prompt for the parsed recipient).
    pub const SEND_SAVE: u16 = 14_014;
    /// Send result `주소록에 저장`.
    pub const RESULT_SAVE: u16 = 14_015;
    /// Bitcoin send form `주소록에서 선택`.
    pub const BTC_PICK: u16 = 14_016;
    /// S14 `＋ 주소 추가`: opens the add form (2026-11-12: the list comes first).
    pub const ADD_OPEN: u16 = 14_017;
    /// Favorite chips of the current send form.
    pub const FAV_BASE: u16 = 14_020;
    /// Favorite chips span (≥ `app_book::FAVORITE_CHIPS`).
    pub const FAV_SPAN: u16 = 8;
    /// Bitcoin picker rows.
    pub const BTC_PICK_BASE: u16 = 14_030;
    /// Bitcoin picker span.
    pub const BTC_PICK_SPAN: u16 = yw_engine::wallet::app_book::BTC_PICK_ROWS;
    /// Solana activity `이 주소 저장` (one per row, ≤ `SOL_MAX_ACTIVITY_ROWS`).
    pub const SOL_ACTIVITY_BASE: u16 = 14_080;
    /// Solana activity span.
    pub const SOL_ACTIVITY_SPAN: u16 = 64;
    /// S14 rows ([`ROW_STRIDE`] ids per row: ★, 편집, 삭제), all families in display order.
    pub const ROW_BASE: u16 = 14_200;
    /// Ids per S14 row.
    pub const ROW_STRIDE: u16 = 3;
    /// S14 rows span (500 rows × 3).
    pub const ROW_SPAN: u16 = 1_500;
    /// S14 rows' address lines (2026-11-12): `COPY_BASE + row` copies that entry's address.
    pub const COPY_BASE: u16 = 18_700;
    /// Span of [`COPY_BASE`] (the address book's maximum).
    pub const COPY_SPAN: u16 = 500;

    const _: () = assert!(FAV_BASE + FAV_SPAN <= BTC_PICK_BASE);
    const _: () = assert!(BTC_PICK_BASE + BTC_PICK_SPAN <= SOL_ACTIVITY_BASE);
    const _: () = assert!(SOL_ACTIVITY_BASE + SOL_ACTIVITY_SPAN <= ROW_BASE);

    /// Every fixed id of this module (`ui::command_ids` checks them against all ranges).
    pub const FIXED: &[u16] = &[
        CHAIN_EVM,
        CHAIN_SOL,
        CHAIN_BTC,
        ADDR_EDIT,
        LABEL_EDIT,
        VERIFIED,
        FAVORITE,
        SAVE,
        CANCEL,
        FORM_ACK,
        PROMPT_LABEL_EDIT,
        PROMPT_SAVE,
        PROMPT_CANCEL,
        PROMPT_ACK,
        SEND_SAVE,
        RESULT_SAVE,
        BTC_PICK,
        ADD_OPEN,
    ];

    /// The press control `id` stands for (2026-11-18, S3 C4: `ui::cmd_table`); the four check
    /// boxes carry their state now. `None` when `id` is not one of this module's presses (the
    /// edits are fields, not presses). Each range is claimed whole, as `on_book_command` claimed
    /// it (a chip past the five shown, a row past the list: nothing happens).
    #[must_use]
    pub fn press_of(
        id: u16,
        controls: &crate::ui::main_window::ControlSet,
    ) -> Option<yw_engine::cmd::BookPress> {
        use yw_engine::cmd::{BookPress, BookRowAction, Row};
        let within = |base: u16, span: u16| id.checked_sub(base).filter(|offset| *offset < span);
        Some(match id {
            CHAIN_EVM => BookPress::ChainEvm,
            CHAIN_SOL => BookPress::ChainSol,
            CHAIN_BTC => BookPress::ChainBtc,
            VERIFIED => BookPress::Verified(controls.checked(id)),
            FAVORITE => BookPress::Favorite(controls.checked(id)),
            SAVE => BookPress::Save,
            CANCEL => BookPress::Cancel,
            FORM_ACK => BookPress::FormAck(controls.checked(id)),
            PROMPT_SAVE => BookPress::PromptSave,
            PROMPT_CANCEL => BookPress::PromptCancel,
            PROMPT_ACK => BookPress::PromptAck(controls.checked(id)),
            SEND_SAVE => BookPress::SendSave,
            RESULT_SAVE => BookPress::ResultSave,
            BTC_PICK => BookPress::BtcPick,
            ADD_OPEN => BookPress::AddOpen,
            _ => {
                if let Some(index) = within(FAV_BASE, FAV_SPAN) {
                    BookPress::Chip(Row(index))
                } else if let Some(index) = within(BTC_PICK_BASE, BTC_PICK_SPAN) {
                    BookPress::BtcPickRow(Row(index))
                } else if let Some(index) = within(ROW_BASE, ROW_SPAN) {
                    BookPress::Row(
                        Row(index / ROW_STRIDE),
                        match index % ROW_STRIDE {
                            0 => BookRowAction::Favorite,
                            1 => BookRowAction::Edit,
                            _ => BookRowAction::Delete,
                        },
                    )
                } else if let Some(row) = within(COPY_BASE, COPY_SPAN) {
                    BookPress::Copy(Row(row))
                } else {
                    BookPress::SolActivitySave(Row(within(SOL_ACTIVITY_BASE, SOL_ACTIVITY_SPAN)?))
                }
            }
        })
    }

    /// The control id of `press` (the inverse of [`press_of`]).
    #[must_use]
    pub const fn id_of(press: yw_engine::cmd::BookPress) -> u16 {
        use yw_engine::cmd::{BookPress, BookRowAction, Row};
        match press {
            BookPress::ChainEvm => CHAIN_EVM,
            BookPress::ChainSol => CHAIN_SOL,
            BookPress::ChainBtc => CHAIN_BTC,
            BookPress::Verified(_) => VERIFIED,
            BookPress::Favorite(_) => FAVORITE,
            BookPress::Save => SAVE,
            BookPress::Cancel => CANCEL,
            BookPress::FormAck(_) => FORM_ACK,
            BookPress::PromptSave => PROMPT_SAVE,
            BookPress::PromptCancel => PROMPT_CANCEL,
            BookPress::PromptAck(_) => PROMPT_ACK,
            BookPress::SendSave => SEND_SAVE,
            BookPress::ResultSave => RESULT_SAVE,
            BookPress::BtcPick => BTC_PICK,
            BookPress::AddOpen => ADD_OPEN,
            BookPress::Chip(Row(index)) => FAV_BASE.wrapping_add(index),
            BookPress::BtcPickRow(Row(index)) => BTC_PICK_BASE.wrapping_add(index),
            BookPress::SolActivitySave(Row(row)) => SOL_ACTIVITY_BASE.wrapping_add(row),
            BookPress::Row(Row(row), action) => ROW_BASE
                .wrapping_add(row.wrapping_mul(ROW_STRIDE))
                .wrapping_add(match action {
                    BookRowAction::Favorite => 0,
                    BookRowAction::Edit => 1,
                    BookRowAction::Delete => 2,
                }),
            BookPress::Copy(Row(row)) => COPY_BASE.wrapping_add(row),
        }
    }
}
