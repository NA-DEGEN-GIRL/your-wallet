//! Presses of the Solana screens: the tab (and its `EVM` tab button), the account card, send,
//! receive, result, the token card, the activity rows, the settings section and the recovery
//! scan (`ui::screens_sol` on Windows; spec/07 §3, §13–§14, spec/04 §2.6).
//!
//! 2026-11-18 (S3 C8): created.

use crate::cmd::Row;

/// A Solana press. The row presses name an item by its position in the list as drawn (`Row`);
/// a row past the list does nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolPress {
    /// Tab `EVM` (handled by the Solana screens, which own the tab row).
    TabEvm,
    /// Tab `Solana`.
    TabSol,
    /// The tab's cluster radio mainnet.
    ClusterMainnet,
    /// The tab's cluster radio devnet.
    ClusterDevnet,
    /// `새로고침`.
    Refresh,
    /// `보내기`.
    SendOpen,
    /// `받기`.
    ReceiveOpen,
    /// `이름 바꾸기`.
    Rename,
    /// `숨기기`.
    Hide,
    /// `계정 추가`.
    AddAccount,
    /// `다른 경로 스캔`.
    ScanOpen,
    /// The name form's `저장`.
    RenameSave,
    /// The name form's `취소`.
    RenameCancel,
    /// `주소 복사`.
    CopyAddress,
    /// `최대` (toggles; the box is not read).
    SendMax,
    /// `검토`.
    SendReview,
    /// `취소`.
    SendCancel,
    /// `주소록에서 선택`.
    SendPick,
    /// The result screen's `다시 보내기`.
    SendAgain,
    /// `지금 다시 전송`.
    SendNow,
    /// The token card's `숨긴 토큰 n개 보기` / `접기`.
    TokenHiddenToggle,
    /// The send result's `해시 복사`.
    ResultCopy,
    /// The settings section `Solana`.
    SectionSol,
    /// Settings: fee caps `저장`.
    FeeSave,
    /// Settings: fee caps `기본값으로`.
    FeeDefault,
    /// Settings: cluster mainnet.
    SetMainnet,
    /// Settings: cluster devnet.
    SetDevnet,
    /// Scan: confirm and start.
    ScanStart,
    /// Scan results: `다시 스캔`.
    ScanAgain,
    /// The result of a scan move: `스캔 결과로`.
    ScanBack,
    /// An account radio (row of the account list).
    Account(Row),
    /// A send-form asset radio (SOL, then the cluster's allowlisted tokens).
    SendAsset(Row),
    /// The token card's `숨기기` / `다시 보이기` (allowlist row).
    TokenHide(Row),
    /// The token card's `주소 복사` of the mint (allowlist row).
    TokenCopy(Row),
    /// An activity row's `해시 복사`.
    ActivityCopy(Row),
    /// The token card's `이 토큰 보내기` (allowlist row).
    TokenSend(Row),
    /// An address-book picker row of the send form.
    SendPickRow(Row),
    /// A scan result row's button.
    ScanRow(Row, SolScanAction),
}

/// The two buttons of a scan result row (stride 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolScanAction {
    /// `계정 추가` (a standard path).
    Add,
    /// `표준 계정으로 이동` (a non-standard path).
    Move,
}
