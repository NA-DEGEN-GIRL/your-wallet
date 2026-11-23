//! EVM screen contents (M4, spec/04 §2.6–§2.8, §2.10, §2.11, §2.16, §2.17): the S10 network,
//! balance, token and activity sections, S11 send, S12 receive, S14 address book, S16 token add,
//! the S15 `EVM 체인` section with fee caps, S17 chain add/edit and their confirmation texts.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): the builders, their helpers and texts moved to yw-engine
//! `screen::build::evm` (bodies unchanged); this file keeps the control ids of its controls
//! (`ids`), which only the Windows shell has.

/// Command ids of the EVM screens (900 and up; spec/04 screens).
pub mod ids {
    /// 보내기.
    pub const SEND_OPEN: u16 = 900;
    /// 받기.
    pub const RECEIVE_OPEN: u16 = 901;
    /// 새로고침.
    pub const REFRESH: u16 = 902;
    /// 주소록.
    pub const BOOK_OPEN: u16 = 903;
    /// 토큰 추가.
    pub const TOKEN_OPEN: u16 = 904;
    /// 설정에서 다시 고정.
    pub const REPIN_SETTINGS: u16 = 905;
    /// S10 network drop-down: opens / closes the list (2026-11-11; the entries keep the chip
    /// ids `screens::ids::NETWORK_BASE`…).
    pub const NETWORK_PICKER: u16 = 906;
    /// Recipient edit.
    pub const SEND_TO_EDIT: u16 = 910;
    /// Amount edit.
    pub const SEND_AMOUNT_EDIT: u16 = 911;
    /// 최대.
    pub const SEND_MAX: u16 = 912;
    /// 주소록에서 선택.
    pub const SEND_PICK: u16 = 913;
    /// W-ADDR-3 check.
    pub const SEND_ACK: u16 = 914;
    /// 검토.
    pub const SEND_REVIEW: u16 = 915;
    /// 취소 / 돌아가기.
    pub const SEND_CANCEL: u16 = 916;
    /// Send form `숨긴 토큰 n개 보기` (asset radios of hidden tokens).
    pub const SEND_HIDDEN_TOGGLE: u16 = 917;
    /// Asset radios: native, then the chain's registry tokens and the user's tokens (≤ 100 per
    /// network, spec/02 §5.3). The old 920..960 span (40) let the 40th token reuse the first
    /// picker id; see `ui::command_ids`.
    pub const SEND_ASSET_BASE: u16 = 3_000;
    /// Asset radio span.
    pub const SEND_ASSET_SPAN: u16 = 200;
    /// Picker rows.
    pub const SEND_PICK_BASE: u16 = 960;
    /// Picker span.
    pub const SEND_PICK_SPAN: u16 = yw_engine::wallet::app_evm::SEND_PICK_ROWS;
    /// 주소 복사.
    pub const COPY_ADDRESS: u16 = 1_000;
    /// Receive QR: EIP-681 (`yw_engine::screen::EvmQrKind::Eip681`).
    pub const QR_EIP681: u16 = 1_001;
    /// Receive QR: the bare address (`yw_engine::screen::EvmQrKind::PlainAddress`).
    pub const QR_PLAIN: u16 = 1_002;
    /// Token card `주소 복사` of the contract (one per row, indexed like [`TOKEN_ROW_BASE`];
    /// 2026-11-11).
    pub const TOKEN_COPY_BASE: u16 = 1_010;
    /// Token contract copy span (120 rows).
    pub const TOKEN_COPY_SPAN: u16 = 120;
    /// Token address edit.
    pub const TOKEN_ADDR_EDIT: u16 = 2_100;
    /// 조회.
    pub const TOKEN_LOOKUP: u16 = 2_101;
    /// Token label edit.
    pub const TOKEN_LABEL_EDIT: u16 = 2_102;
    /// Token save.
    pub const TOKEN_SAVE: u16 = 2_103;
    /// Token card `잔액 0인 토큰 숨기기`.
    pub const TOKEN_HIDE_ZERO: u16 = 2_104;
    /// Token card `숨긴 토큰 n개 보기` / `접기`.
    pub const TOKEN_HIDDEN_TOGGLE: u16 = 2_105;
    /// Settings EVM-chains section.
    pub const SECTION_CHAINS: u16 = 2_200;
    /// 추가.
    pub const CHAIN_ADD: u16 = 2_201;
    /// Chain rows (3 ids per row: 편집, 삭제, 다시 고정).
    pub const CHAIN_ROW_BASE: u16 = 2_210;
    /// Chain rows span.
    pub const CHAIN_ROW_SPAN: u16 = 140;
    /// S17 chainId.
    pub const CHAIN_ID_EDIT: u16 = 2_350;
    /// S17 name.
    pub const CHAIN_NAME_EDIT: u16 = 2_351;
    /// S17 symbol.
    pub const CHAIN_SYMBOL_EDIT: u16 = 2_352;
    /// S17 decimals.
    pub const CHAIN_DECIMALS_EDIT: u16 = 2_353;
    /// S17 RPC (`ES_PASSWORD`).
    pub const CHAIN_RPC_EDIT: u16 = 2_354;
    /// S17 explorer.
    pub const CHAIN_EXPLORER_EDIT: u16 = 2_355;
    /// S17 simulation auto.
    pub const CHAIN_SIM_AUTO: u16 = 2_356;
    /// S17 simulation unsupported.
    pub const CHAIN_SIM_UNSUPPORTED: u16 = 2_357;
    /// S17 save.
    pub const CHAIN_SAVE: u16 = 2_358;
    /// S17 cancel.
    pub const CHAIN_CANCEL: u16 = 2_359;
    /// Fee caps chain radios.
    pub const CAPS_CHAIN_BASE: u16 = 2_400;
    /// Fee caps chain span.
    pub const CAPS_CHAIN_SPAN: u16 = 40;
    /// maxFee cap edit.
    pub const CAPS_FEE_EDIT: u16 = 2_450;
    /// tip cap edit.
    pub const CAPS_TIP_EDIT: u16 = 2_451;
    /// total cap edit.
    pub const CAPS_TOTAL_EDIT: u16 = 2_452;
    /// 저장.
    pub const CAPS_SAVE: u16 = 2_453;
    /// 기본값으로.
    pub const CAPS_DEFAULT: u16 = 2_454;
    /// Activity rows ([`ACTIVITY_STRIDE`] ids per row, at most `MAX_ACTIVITY_ROWS` = 50 rows).
    pub const ACTIVITY_BASE: u16 = 2_500;
    /// Ids per activity row (해시 복사, 수수료 올리기, 취소, 재전송, 폐기, 탐색기 링크 복사, 이 주소
    /// 저장, 탐색기에서 열기).
    pub const ACTIVITY_STRIDE: u16 = 8;
    /// Activity span (50 rows × 8).
    pub const ACTIVITY_SPAN: u16 = 400;
    /// Token card rows ([`TOKEN_ROW_STRIDE`] ids per row: 숨기기/다시 보이기, 삭제), indexed by
    /// the token's position in `Wallet::chain_tokens` (registry tokens + ≤ 100 user tokens).
    pub const TOKEN_ROW_BASE: u16 = 3_200;
    /// Ids per token row.
    pub const TOKEN_ROW_STRIDE: u16 = 2;
    /// Token rows span (120 rows × 2).
    pub const TOKEN_ROW_SPAN: u16 = 240;
    /// Token card `{기호} 보내기` links (one per row, indexed like [`TOKEN_ROW_BASE`]).
    pub const TOKEN_SEND_BASE: u16 = 3_440;
    /// Token send links span (120 rows).
    pub const TOKEN_SEND_SPAN: u16 = 120;
    /// Activity `이전 활동 n건 더 보기 ▸` / `접기 ▾`.
    pub const ACTIVITY_MORE: u16 = 3_560;
    /// Activity rows drawn before `이전 활동 n건 더 보기`.
    pub const ACTIVITY_FIRST: usize = 10;
    /// T-CHAIN-REPIN-ACK check.
    pub const REPIN_CHECK: u16 = 6_600;

    /// What a token-row id does.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TokenAction {
        /// `숨기기` / `다시 보이기` of the row.
        ToggleHidden(usize),
        /// `삭제` (user tokens only).
        Delete(usize),
    }

    /// The button id of a token action (`None` beyond the span).
    #[must_use]
    pub fn token_row_id(action: TokenAction) -> Option<u16> {
        let (row, extra) = match action {
            TokenAction::ToggleHidden(row) => (row, 0),
            TokenAction::Delete(row) => (row, 1),
        };
        let offset = u16::try_from(row)
            .ok()?
            .checked_mul(TOKEN_ROW_STRIDE)?
            .checked_add(extra)?;
        (offset < TOKEN_ROW_SPAN).then(|| TOKEN_ROW_BASE.saturating_add(offset))
    }

    /// The token action of `id`, if it is a token-row id.
    #[must_use]
    pub fn token_action(id: u16) -> Option<TokenAction> {
        let offset = id
            .checked_sub(TOKEN_ROW_BASE)
            .filter(|offset| *offset < TOKEN_ROW_SPAN)?;
        let row = usize::from(offset / TOKEN_ROW_STRIDE);
        Some(if offset % TOKEN_ROW_STRIDE == 0 {
            TokenAction::ToggleHidden(row)
        } else {
            TokenAction::Delete(row)
        })
    }

    /// Every fixed id of this module (`ui::command_ids` checks them against all ranges).
    pub const FIXED: &[u16] = &[
        SEND_OPEN,
        RECEIVE_OPEN,
        REFRESH,
        BOOK_OPEN,
        TOKEN_OPEN,
        REPIN_SETTINGS,
        NETWORK_PICKER,
        SEND_TO_EDIT,
        SEND_AMOUNT_EDIT,
        SEND_MAX,
        SEND_PICK,
        SEND_ACK,
        SEND_REVIEW,
        SEND_CANCEL,
        SEND_HIDDEN_TOGGLE,
        COPY_ADDRESS,
        QR_EIP681,
        QR_PLAIN,
        TOKEN_ADDR_EDIT,
        TOKEN_LOOKUP,
        TOKEN_LABEL_EDIT,
        TOKEN_SAVE,
        TOKEN_HIDE_ZERO,
        TOKEN_HIDDEN_TOGGLE,
        SECTION_CHAINS,
        CHAIN_ADD,
        CHAIN_ID_EDIT,
        CHAIN_NAME_EDIT,
        CHAIN_SYMBOL_EDIT,
        CHAIN_DECIMALS_EDIT,
        CHAIN_RPC_EDIT,
        CHAIN_EXPLORER_EDIT,
        CHAIN_SIM_AUTO,
        CHAIN_SIM_UNSUPPORTED,
        CHAIN_SAVE,
        CHAIN_CANCEL,
        CAPS_FEE_EDIT,
        CAPS_TIP_EDIT,
        CAPS_TOTAL_EDIT,
        CAPS_SAVE,
        CAPS_DEFAULT,
        REPIN_CHECK,
        ACTIVITY_MORE,
    ];

    /// The press control `id` stands for (2026-11-18, S3 C10: `ui::cmd_table`). `None` when `id`
    /// is not one of this module's presses (the thirteen edits are fields). The three check
    /// boxes carry their state (`controls.checked(id)` now); each row range is claimed whole, as
    /// the ids reached the handler before.
    #[must_use]
    pub fn press_of(
        id: u16,
        controls: &crate::ui::main_window::ControlSet,
    ) -> Option<yw_engine::cmd::EvmPress> {
        use yw_engine::cmd::{ChainRowAction, EvmActivityAction, EvmPress, Row};
        let within = |base: u16, span: u16| id.checked_sub(base).filter(|offset| *offset < span);
        Some(match id {
            SEND_OPEN => EvmPress::SendOpen,
            RECEIVE_OPEN => EvmPress::ReceiveOpen,
            REFRESH => EvmPress::Refresh,
            BOOK_OPEN => EvmPress::BookOpen,
            TOKEN_OPEN => EvmPress::TokenOpen,
            REPIN_SETTINGS => EvmPress::RepinSettings,
            NETWORK_PICKER => EvmPress::NetworkPicker,
            SEND_MAX => EvmPress::SendMax,
            SEND_PICK => EvmPress::SendPick,
            SEND_ACK => EvmPress::SendAck(controls.checked(id)),
            SEND_REVIEW => EvmPress::SendReview,
            SEND_CANCEL => EvmPress::SendCancel,
            SEND_HIDDEN_TOGGLE => EvmPress::SendHiddenToggle,
            COPY_ADDRESS => EvmPress::CopyAddress,
            QR_EIP681 => EvmPress::QrEip681,
            QR_PLAIN => EvmPress::QrPlain,
            TOKEN_LOOKUP => EvmPress::TokenLookup,
            TOKEN_SAVE => EvmPress::TokenSave,
            TOKEN_HIDE_ZERO => EvmPress::TokenHideZero(controls.checked(id)),
            TOKEN_HIDDEN_TOGGLE => EvmPress::TokenHiddenToggle,
            SECTION_CHAINS => EvmPress::SectionChains,
            CHAIN_ADD => EvmPress::ChainAdd,
            CHAIN_SIM_AUTO => EvmPress::ChainSimAuto,
            CHAIN_SIM_UNSUPPORTED => EvmPress::ChainSimUnsupported,
            CHAIN_SAVE => EvmPress::ChainSave,
            CHAIN_CANCEL => EvmPress::ChainCancel,
            CAPS_SAVE => EvmPress::CapsSave,
            CAPS_DEFAULT => EvmPress::CapsDefault,
            ACTIVITY_MORE => EvmPress::ActivityMore,
            REPIN_CHECK => EvmPress::RepinCheck(controls.checked(id)),
            _ => {
                if let Some(row) = within(SEND_ASSET_BASE, SEND_ASSET_SPAN) {
                    EvmPress::SendAsset(Row(row))
                } else if let Some(row) = within(TOKEN_SEND_BASE, TOKEN_SEND_SPAN) {
                    EvmPress::TokenSend(Row(row))
                } else if let Some(row) = within(TOKEN_COPY_BASE, TOKEN_COPY_SPAN) {
                    EvmPress::TokenCopy(Row(row))
                } else if let Some(offset) = within(TOKEN_ROW_BASE, TOKEN_ROW_SPAN) {
                    let row = Row(offset / TOKEN_ROW_STRIDE);
                    if offset % TOKEN_ROW_STRIDE == 0 {
                        EvmPress::TokenToggleHidden(row)
                    } else {
                        EvmPress::TokenDelete(row)
                    }
                } else if let Some(row) = within(SEND_PICK_BASE, SEND_PICK_SPAN) {
                    EvmPress::PickRecipient(Row(row))
                } else if let Some(offset) = within(CHAIN_ROW_BASE, CHAIN_ROW_SPAN) {
                    let action = match offset % 3 {
                        0 => ChainRowAction::Edit,
                        1 => ChainRowAction::Delete,
                        _ => ChainRowAction::Repin,
                    };
                    EvmPress::ChainRow(Row(offset / 3), action)
                } else if let Some(row) = within(CAPS_CHAIN_BASE, CAPS_CHAIN_SPAN) {
                    EvmPress::CapsChain(Row(row))
                } else {
                    let offset = within(ACTIVITY_BASE, ACTIVITY_SPAN)?;
                    let action = match offset % ACTIVITY_STRIDE {
                        0 => EvmActivityAction::CopyHash,
                        1 => EvmActivityAction::SpeedUp,
                        2 => EvmActivityAction::Cancel,
                        3 => EvmActivityAction::Resend,
                        4 => EvmActivityAction::Discard,
                        5 => EvmActivityAction::CopyExplorerLink,
                        6 => EvmActivityAction::SaveAddress,
                        _ => EvmActivityAction::OpenExplorer,
                    };
                    EvmPress::Activity(Row(offset / ACTIVITY_STRIDE), action)
                }
            }
        })
    }

    /// The control id of `press` (the inverse of [`press_of`]; a check box's state is not part
    /// of it).
    /// A row past its span lands on another control's id (S3 C10–C12 review: listed in
    /// `ui::cmd_table`'s `c10_c12_payloads_round_trip_or_are_undrawn`; a press that arrives as
    /// data must refuse it).
    #[must_use]
    pub const fn id_of(press: yw_engine::cmd::EvmPress) -> u16 {
        use yw_engine::cmd::{ChainRowAction, EvmActivityAction, EvmPress, Row};
        match press {
            EvmPress::SendOpen => SEND_OPEN,
            EvmPress::ReceiveOpen => RECEIVE_OPEN,
            EvmPress::Refresh => REFRESH,
            EvmPress::BookOpen => BOOK_OPEN,
            EvmPress::TokenOpen => TOKEN_OPEN,
            EvmPress::RepinSettings => REPIN_SETTINGS,
            EvmPress::NetworkPicker => NETWORK_PICKER,
            EvmPress::SendMax => SEND_MAX,
            EvmPress::SendPick => SEND_PICK,
            EvmPress::SendAck(_) => SEND_ACK,
            EvmPress::SendReview => SEND_REVIEW,
            EvmPress::SendCancel => SEND_CANCEL,
            EvmPress::SendHiddenToggle => SEND_HIDDEN_TOGGLE,
            EvmPress::CopyAddress => COPY_ADDRESS,
            EvmPress::QrEip681 => QR_EIP681,
            EvmPress::QrPlain => QR_PLAIN,
            EvmPress::TokenLookup => TOKEN_LOOKUP,
            EvmPress::TokenSave => TOKEN_SAVE,
            EvmPress::TokenHideZero(_) => TOKEN_HIDE_ZERO,
            EvmPress::TokenHiddenToggle => TOKEN_HIDDEN_TOGGLE,
            EvmPress::SectionChains => SECTION_CHAINS,
            EvmPress::ChainAdd => CHAIN_ADD,
            EvmPress::ChainSimAuto => CHAIN_SIM_AUTO,
            EvmPress::ChainSimUnsupported => CHAIN_SIM_UNSUPPORTED,
            EvmPress::ChainSave => CHAIN_SAVE,
            EvmPress::ChainCancel => CHAIN_CANCEL,
            EvmPress::CapsSave => CAPS_SAVE,
            EvmPress::CapsDefault => CAPS_DEFAULT,
            EvmPress::ActivityMore => ACTIVITY_MORE,
            EvmPress::RepinCheck(_) => REPIN_CHECK,
            EvmPress::SendAsset(Row(row)) => SEND_ASSET_BASE.wrapping_add(row),
            EvmPress::TokenSend(Row(row)) => TOKEN_SEND_BASE.wrapping_add(row),
            EvmPress::TokenCopy(Row(row)) => TOKEN_COPY_BASE.wrapping_add(row),
            EvmPress::TokenToggleHidden(Row(row)) => {
                TOKEN_ROW_BASE.wrapping_add(row.wrapping_mul(TOKEN_ROW_STRIDE))
            }
            EvmPress::TokenDelete(Row(row)) => TOKEN_ROW_BASE
                .wrapping_add(row.wrapping_mul(TOKEN_ROW_STRIDE))
                .wrapping_add(1),
            EvmPress::PickRecipient(Row(row)) => SEND_PICK_BASE.wrapping_add(row),
            EvmPress::ChainRow(Row(row), action) => CHAIN_ROW_BASE
                .wrapping_add(row.wrapping_mul(3))
                .wrapping_add(match action {
                    ChainRowAction::Edit => 0,
                    ChainRowAction::Delete => 1,
                    ChainRowAction::Repin => 2,
                }),
            EvmPress::CapsChain(Row(row)) => CAPS_CHAIN_BASE.wrapping_add(row),
            EvmPress::Activity(Row(row), action) => ACTIVITY_BASE
                .wrapping_add(row.wrapping_mul(ACTIVITY_STRIDE))
                .wrapping_add(match action {
                    EvmActivityAction::CopyHash => 0,
                    EvmActivityAction::SpeedUp => 1,
                    EvmActivityAction::Cancel => 2,
                    EvmActivityAction::Resend => 3,
                    EvmActivityAction::Discard => 4,
                    EvmActivityAction::CopyExplorerLink => 5,
                    EvmActivityAction::SaveAddress => 6,
                    EvmActivityAction::OpenExplorer => 7,
                }),
        }
    }
}
