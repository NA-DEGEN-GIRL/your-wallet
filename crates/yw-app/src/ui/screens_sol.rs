//! Solana screen contents (M7; spec/04 §2.6–§2.8, §2.10, §2.11, spec/07 §3.3, §12.3): the S10
//! Solana tab (with the allowlisted-token card of v1.1), the SOL/SPL send form with its asset
//! picker and its result, receive, the S15 Solana section, the recovery scan and the Solana part
//! of the address book. Addresses are always shown in full, in 4-character groups (spec/07
//! §12.3); activity addresses have no copy or select buttons (a transaction id, public data,
//! has `해시 복사` like Bitcoin's and EVM's).
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): the builders, their helpers and texts moved to yw-engine
//! `screen::build::sol` (bodies unchanged); this file keeps the control ids of its controls
//! (`ids`), which only the Windows shell has.

/// Command ids of the Solana screens (7000–7909 and the account radios at 12,000; the whole
/// map and its checks are in `ui::command_ids`).
pub mod ids {
    /// Tab `EVM`.
    pub const TAB_EVM: u16 = 7_000;
    /// Tab `Solana`.
    pub const TAB_SOL: u16 = 7_001;
    /// Cluster mainnet radio.
    pub const CLUSTER_MAINNET: u16 = 7_002;
    /// Cluster devnet radio.
    pub const CLUSTER_DEVNET: u16 = 7_003;
    /// 새로고침.
    pub const REFRESH: u16 = 7_004;
    /// 보내기.
    pub const SEND_OPEN: u16 = 7_005;
    /// 받기.
    pub const RECEIVE_OPEN: u16 = 7_006;
    /// 이름 바꾸기.
    pub const RENAME: u16 = 7_007;
    /// 숨기기.
    pub const HIDE: u16 = 7_008;
    /// 계정 추가.
    pub const ADD_ACCOUNT: u16 = 7_009;
    /// 다른 경로 스캔.
    pub const SCAN_OPEN: u16 = 7_010;
    /// Rename edit.
    pub const RENAME_EDIT: u16 = 7_011;
    /// Rename save.
    pub const RENAME_SAVE: u16 = 7_012;
    /// Rename cancel.
    pub const RENAME_CANCEL: u16 = 7_013;
    /// 주소 복사.
    pub const COPY_ADDRESS: u16 = 7_014;
    /// Send-form asset radios (SOL, then the cluster's allowlisted tokens; v1.1).
    pub const SEND_ASSET_BASE: u16 = 7_015;
    /// Asset radio span.
    pub const SEND_ASSET_SPAN: u16 = 4;
    /// Token card "이 토큰 보내기" (allowlist index of the cluster; v1.1).
    pub const TOKEN_SEND_BASE: u16 = 7_027;
    /// Token send span.
    pub const TOKEN_SEND_SPAN: u16 = 3;
    /// Token card `숨기기` / `다시 보이기` (allowlist index of the cluster).
    pub const TOKEN_HIDE_BASE: u16 = 7_070;
    /// Token hide span.
    pub const TOKEN_HIDE_SPAN: u16 = 4;
    /// Token card `숨긴 토큰 n개 보기` / `접기`.
    pub const TOKEN_HIDDEN_TOGGLE: u16 = 7_075;
    /// Token card `주소 복사` of the mint (one per allowlist row; 2026-11-11).
    pub const TOKEN_COPY_BASE: u16 = 7_080;
    /// Mint copy span.
    pub const TOKEN_COPY_SPAN: u16 = 4;
    /// `해시 복사` of the send result (the signature, i.e. the transaction id).
    pub const RESULT_COPY: u16 = 7_076;
    /// `해시 복사` of the S10 activity rows (display order, one id per row).
    pub const ACTIVITY_COPY_BASE: u16 = 7_400;
    /// Activity copy span (the journal's records, or the drawn activity rows).
    pub const ACTIVITY_COPY_SPAN: u16 = 64;
    /// Account radios (one id per row; rows ≤ 100, spec/02 §5.3). The span covers the whole
    /// account-index range 0..=999. It used to start at 7,200, inside the scan rows below, so
    /// the 41st scan row's `계정 추가` selected account 0 instead.
    pub const ACCOUNT_BASE: u16 = 12_000;
    /// Account radio span.
    pub const ACCOUNT_SPAN: u16 = 1_000;
    /// Recipient edit.
    pub const SEND_TO_EDIT: u16 = 7_020;
    /// Amount edit.
    pub const SEND_AMOUNT_EDIT: u16 = 7_021;
    /// 최대.
    pub const SEND_MAX: u16 = 7_022;
    /// 검토.
    pub const SEND_REVIEW: u16 = 7_023;
    /// 취소.
    pub const SEND_CANCEL: u16 = 7_024;
    /// 주소록에서 선택.
    pub const SEND_PICK: u16 = 7_025;
    /// "다시 보내기" on the result screen (spec/07 §14.3).
    pub const SEND_AGAIN: u16 = 7_026;
    /// "지금 다시 전송": the same signed bytes of a pending transfer, now (spec/07 §14.3).
    pub const SEND_NOW: u16 = 7_019;
    /// Picker rows.
    pub const SEND_PICK_BASE: u16 = 7_030;
    /// Picker span.
    pub const SEND_PICK_SPAN: u16 = yw_engine::wallet::app_sol::SOL_SEND_PICK_ROWS;
    /// Settings Solana section.
    pub const SECTION_SOL: u16 = 7_100;
    /// Fee cap edit.
    pub const FEE_CAP_EDIT: u16 = 7_101;
    /// CU price cap edit.
    pub const CU_PRICE_EDIT: u16 = 7_102;
    /// Fee settings save.
    pub const FEE_SAVE: u16 = 7_103;
    /// Fee settings defaults.
    pub const FEE_DEFAULT: u16 = 7_104;
    /// Settings cluster mainnet.
    pub const SET_MAINNET: u16 = 7_105;
    /// Settings cluster devnet.
    pub const SET_DEVNET: u16 = 7_106;
    /// Scan: confirm and start.
    pub const SCAN_START: u16 = 7_110;
    /// Scan results: `다시 스캔` (back to the notice).
    pub const SCAN_AGAIN: u16 = 7_111;
    /// Send result of a scan move: `스캔 결과로`.
    pub const SCAN_BACK: u16 = 7_112;
    /// Scan rows ([`SCAN_ROW_STRIDE`] ids per row: 계정 추가, 표준 계정으로 이동). Rows ≤ 107
    /// (spec/07 §3.3: 50 standard + 50 BIP44 + root + seed + 5 Sollet sources).
    pub const SCAN_ROW_BASE: u16 = 7_120;
    /// Ids per scan row.
    pub const SCAN_ROW_STRIDE: u16 = 2;
    /// Scan rows span (128 rows × 2; ends at 7,376).
    pub const SCAN_ROW_SPAN: u16 = 256;

    /// Every fixed id of this module (`ui::command_ids` checks them against all ranges).
    pub const FIXED: &[u16] = &[
        TAB_EVM,
        TAB_SOL,
        CLUSTER_MAINNET,
        CLUSTER_DEVNET,
        REFRESH,
        SEND_OPEN,
        RECEIVE_OPEN,
        RENAME,
        HIDE,
        ADD_ACCOUNT,
        SCAN_OPEN,
        RENAME_EDIT,
        RENAME_SAVE,
        RENAME_CANCEL,
        COPY_ADDRESS,
        SEND_TO_EDIT,
        SEND_AMOUNT_EDIT,
        SEND_MAX,
        SEND_REVIEW,
        SEND_CANCEL,
        SEND_PICK,
        SEND_AGAIN,
        SEND_NOW,
        TOKEN_HIDDEN_TOGGLE,
        RESULT_COPY,
        SECTION_SOL,
        FEE_CAP_EDIT,
        CU_PRICE_EDIT,
        FEE_SAVE,
        FEE_DEFAULT,
        SET_MAINNET,
        SET_DEVNET,
        SCAN_START,
        SCAN_AGAIN,
        SCAN_BACK,
    ];

    /// The press control `id` stands for (2026-11-18, S3 C8: `ui::cmd_table`). `None` when `id`
    /// is not one of this module's presses (the five edits are fields). Each row range is claimed
    /// whole, as the ids reached the handler before; a scan row's two buttons are
    /// `SolPress::ScanRow` with their action ([`scan_action`]).
    #[must_use]
    pub fn press_of(id: u16) -> Option<yw_engine::cmd::SolPress> {
        use yw_engine::cmd::{Row, SolPress, SolScanAction};
        let within = |base: u16, span: u16| {
            id.checked_sub(base)
                .filter(|offset| *offset < span)
                .map(Row)
        };
        Some(match id {
            TAB_EVM => SolPress::TabEvm,
            TAB_SOL => SolPress::TabSol,
            CLUSTER_MAINNET => SolPress::ClusterMainnet,
            CLUSTER_DEVNET => SolPress::ClusterDevnet,
            REFRESH => SolPress::Refresh,
            SEND_OPEN => SolPress::SendOpen,
            RECEIVE_OPEN => SolPress::ReceiveOpen,
            RENAME => SolPress::Rename,
            HIDE => SolPress::Hide,
            ADD_ACCOUNT => SolPress::AddAccount,
            SCAN_OPEN => SolPress::ScanOpen,
            RENAME_SAVE => SolPress::RenameSave,
            RENAME_CANCEL => SolPress::RenameCancel,
            COPY_ADDRESS => SolPress::CopyAddress,
            SEND_MAX => SolPress::SendMax,
            SEND_REVIEW => SolPress::SendReview,
            SEND_CANCEL => SolPress::SendCancel,
            SEND_PICK => SolPress::SendPick,
            SEND_AGAIN => SolPress::SendAgain,
            SEND_NOW => SolPress::SendNow,
            TOKEN_HIDDEN_TOGGLE => SolPress::TokenHiddenToggle,
            RESULT_COPY => SolPress::ResultCopy,
            SECTION_SOL => SolPress::SectionSol,
            FEE_SAVE => SolPress::FeeSave,
            FEE_DEFAULT => SolPress::FeeDefault,
            SET_MAINNET => SolPress::SetMainnet,
            SET_DEVNET => SolPress::SetDevnet,
            SCAN_START => SolPress::ScanStart,
            SCAN_AGAIN => SolPress::ScanAgain,
            SCAN_BACK => SolPress::ScanBack,
            _ => within(ACCOUNT_BASE, ACCOUNT_SPAN)
                .map(SolPress::Account)
                .or_else(|| within(SEND_ASSET_BASE, SEND_ASSET_SPAN).map(SolPress::SendAsset))
                .or_else(|| within(TOKEN_HIDE_BASE, TOKEN_HIDE_SPAN).map(SolPress::TokenHide))
                .or_else(|| within(TOKEN_COPY_BASE, TOKEN_COPY_SPAN).map(SolPress::TokenCopy))
                .or_else(|| {
                    within(ACTIVITY_COPY_BASE, ACTIVITY_COPY_SPAN).map(SolPress::ActivityCopy)
                })
                .or_else(|| within(TOKEN_SEND_BASE, TOKEN_SEND_SPAN).map(SolPress::TokenSend))
                .or_else(|| within(SEND_PICK_BASE, SEND_PICK_SPAN).map(SolPress::SendPickRow))
                .or_else(|| {
                    within(SCAN_ROW_BASE, SCAN_ROW_SPAN).map(|Row(offset)| {
                        let action = if offset % SCAN_ROW_STRIDE == 0 {
                            SolScanAction::Add
                        } else {
                            SolScanAction::Move
                        };
                        SolPress::ScanRow(Row(offset / SCAN_ROW_STRIDE), action)
                    })
                })?,
        })
    }

    /// The control id of `press` (the inverse of [`press_of`]).
    #[must_use]
    pub const fn id_of(press: yw_engine::cmd::SolPress) -> u16 {
        use yw_engine::cmd::{Row, SolPress, SolScanAction};
        match press {
            SolPress::TabEvm => TAB_EVM,
            SolPress::TabSol => TAB_SOL,
            SolPress::ClusterMainnet => CLUSTER_MAINNET,
            SolPress::ClusterDevnet => CLUSTER_DEVNET,
            SolPress::Refresh => REFRESH,
            SolPress::SendOpen => SEND_OPEN,
            SolPress::ReceiveOpen => RECEIVE_OPEN,
            SolPress::Rename => RENAME,
            SolPress::Hide => HIDE,
            SolPress::AddAccount => ADD_ACCOUNT,
            SolPress::ScanOpen => SCAN_OPEN,
            SolPress::RenameSave => RENAME_SAVE,
            SolPress::RenameCancel => RENAME_CANCEL,
            SolPress::CopyAddress => COPY_ADDRESS,
            SolPress::SendMax => SEND_MAX,
            SolPress::SendReview => SEND_REVIEW,
            SolPress::SendCancel => SEND_CANCEL,
            SolPress::SendPick => SEND_PICK,
            SolPress::SendAgain => SEND_AGAIN,
            SolPress::SendNow => SEND_NOW,
            SolPress::TokenHiddenToggle => TOKEN_HIDDEN_TOGGLE,
            SolPress::ResultCopy => RESULT_COPY,
            SolPress::SectionSol => SECTION_SOL,
            SolPress::FeeSave => FEE_SAVE,
            SolPress::FeeDefault => FEE_DEFAULT,
            SolPress::SetMainnet => SET_MAINNET,
            SolPress::SetDevnet => SET_DEVNET,
            SolPress::ScanStart => SCAN_START,
            SolPress::ScanAgain => SCAN_AGAIN,
            SolPress::ScanBack => SCAN_BACK,
            SolPress::Account(Row(row)) => ACCOUNT_BASE.wrapping_add(row),
            SolPress::SendAsset(Row(row)) => SEND_ASSET_BASE.wrapping_add(row),
            SolPress::TokenHide(Row(row)) => TOKEN_HIDE_BASE.wrapping_add(row),
            SolPress::TokenCopy(Row(row)) => TOKEN_COPY_BASE.wrapping_add(row),
            SolPress::ActivityCopy(Row(row)) => ACTIVITY_COPY_BASE.wrapping_add(row),
            SolPress::TokenSend(Row(row)) => TOKEN_SEND_BASE.wrapping_add(row),
            SolPress::SendPickRow(Row(row)) => SEND_PICK_BASE.wrapping_add(row),
            SolPress::ScanRow(Row(row), action) => SCAN_ROW_BASE
                .wrapping_add(row.wrapping_mul(SCAN_ROW_STRIDE))
                .wrapping_add(match action {
                    SolScanAction::Add => 0,
                    SolScanAction::Move => 1,
                }),
        }
    }

    /// What a scan-row id does (row index into `sol_scan_rows`).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ScanAction {
        /// `계정 추가` (standard path).
        Add(usize),
        /// `표준 계정으로 이동` (non-standard path).
        Move(usize),
    }

    /// The button id of a scan action (`None` beyond the span).
    #[must_use]
    pub fn scan_row_id(action: ScanAction) -> Option<u16> {
        let (row, extra) = match action {
            ScanAction::Add(row) => (row, 0),
            ScanAction::Move(row) => (row, 1),
        };
        let offset = u16::try_from(row)
            .ok()?
            .checked_mul(SCAN_ROW_STRIDE)?
            .checked_add(extra)?;
        (offset < SCAN_ROW_SPAN).then(|| SCAN_ROW_BASE.saturating_add(offset))
    }

    /// The scan action of `id`, if it is a scan-row id.
    #[must_use]
    pub fn scan_action(id: u16) -> Option<ScanAction> {
        let offset = id
            .checked_sub(SCAN_ROW_BASE)
            .filter(|offset| *offset < SCAN_ROW_SPAN)?;
        let row = usize::from(offset / SCAN_ROW_STRIDE);
        Some(if offset % SCAN_ROW_STRIDE == 0 {
            ScanAction::Add(row)
        } else {
            ScanAction::Move(row)
        })
    }
}
