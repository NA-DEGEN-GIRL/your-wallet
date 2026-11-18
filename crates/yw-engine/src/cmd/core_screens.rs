//! Presses of the core screens: first run, create and import, unlock, the backup check, S08,
//! the account card's own buttons and drop-downs, the side-file and passphrase overlays, the
//! settings sections `보안`, `네트워크(RPC)` and `기타`, and the confirmation overlay
//! (`ui::screens` on Windows; spec/04 §2).
//!
//! 2026-11-18 (S3 C12): created.

use yw_core::lang::Lang;

use crate::cmd::Row;
use crate::logging::LogLevel;
use crate::settings::RpcTemplate;

/// A core-screen press. The row presses name an item by its position in the list as drawn
/// (`Row`); a row past the list does nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorePress {
    /// S01 `새 지갑 만들기`.
    FirstCreate,
    /// S01 `기존 지갑 가져오기`.
    FirstImport,
    /// `데이터 폴더 열기`.
    OpenDataFolder,
    /// `로그 폴더 열기`.
    OpenLogFolder,
    /// S02 `시작하기`.
    CreateNext,
    /// S02/S05 `취소`.
    IntroCancel,
    /// S05 `시작하기`.
    ImportNext,
    /// S06 `맞습니다`.
    ImportCorrect,
    /// S06 `다릅니다`.
    ImportWrong,
    /// S07 `잠금 해제`.
    Unlock,
    /// S04 `복구 단어 보고 백업 확인`.
    BackupCheck,
    /// `잠금`.
    Lock,
    /// S08 `RPC 설정 열기`.
    DoneRpc,
    /// S08 `지갑 열기`.
    DoneContinue,
    /// S09 `이전 사본으로 복구`.
    Recover,
    /// S09 `종료`.
    Exit,
    /// T-PASS-MISMATCH `다시 입력`.
    MismatchRetry,
    /// T-PASS-MISMATCH `이 passphrase로 계속`.
    MismatchContinue,
    /// The T-PASS-MISMATCH check box: the box's state when it was pressed (`None`: no such
    /// box).
    MismatchCheck(Option<bool>),
    /// E-VLT-006 `이전 사본 사용`.
    SidecarPrev,
    /// E-VLT-006 `격리하고 새로 시작`.
    SidecarFresh,
    /// `설정`.
    OpenSettings,
    /// `← 메인으로`.
    BackMain,
    /// The send forms' `다른 계정으로 바꾸기 (메인)` (the action of `BackMain`).
    SwitchAccount,
    /// A `네트워크(RPC) 설정으로` button inside a settings section.
    GoNetwork,
    /// `알림 닫기`.
    DismissBanners,
    /// The settings-file banner's `파일 값 사용`.
    SettingsAcceptFile,
    /// The settings-file banner's `앱에 저장된 값으로 되돌리기`.
    SettingsRestore,
    /// `고급 설정 보기 ▸` / `고급 설정 숨기기 ▾`.
    AdvancedToggle,
    /// `계정 추가`.
    AddAccount,
    /// `개인키 가져오기`.
    ImportKey,
    /// `이름 바꾸기`.
    Rename,
    /// `숨기기`.
    Hide,
    /// `개인키 계정 삭제`.
    RemoveKey,
    /// The name form's `저장`.
    RenameSave,
    /// The name form's `취소`.
    RenameCancel,
    /// The settings section `보안`.
    SectionSecurity,
    /// The settings section `네트워크(RPC)`.
    SectionNetwork,
    /// The settings section `기타`.
    SectionOther,
    /// The auto-lock `저장`.
    AutolockSave,
    /// The secret-copy switch: the box's state when it was pressed.
    CopyToggle(Option<bool>),
    /// `복구 단어 보기`.
    RevealMnemonic,
    /// `개인키 보기`.
    RevealKey,
    /// `비밀번호 변경`.
    ChangePassword,
    /// A `언어 · Language` radio.
    Lang(Lang),
    /// An RPC template radio.
    Template(RpcTemplate),
    /// `자격 정보만 저장` (reads the template's credential edits).
    TemplateSave,
    /// The template credential's `삭제`.
    TemplateDelete,
    /// `저장하고 RPC 주소 만들기` (reads the template's credential edits).
    Generate,
    /// `보관 항목 삭제`.
    PruneDormant,
    /// The `교체` field's `저장` (reads the field).
    ReplaceSave,
    /// The `교체` field's `취소`.
    ReplaceCancel,
    /// The localhost switch: the box's state when it was pressed.
    LocalhostToggle(Option<bool>),
    /// The browser auto-launch switch: the box's state when it was pressed.
    AutolaunchToggle(Option<bool>),
    /// A log-level radio.
    LogLevel(LogLevel),
    /// The confirmation overlay's confirm button.
    ConfirmYes,
    /// The confirmation overlay's cancel button.
    ConfirmNo,
    /// T-RPC-GENERATE `기존 주소 덮어쓰기`: the box's state when it was pressed.
    OverwriteCheck(Option<bool>),
    /// S08 `연결하기` (reads the S08 `QuickNode` field).
    DoneConnect,
    /// S08 `rpc.json이 있습니다 — 설정에서 가져오기 ▸`.
    DoneRpcJson,
    /// S08 `Ethereum 메인넷으로 보기`.
    DoneMainnet,
    /// S08 `WalletConnect` `설정` (S13).
    DoneWc,
    /// `← 처음 설정으로`.
    BackDone,
    /// `네트워크(RPC)` `모두 테스트`.
    TestAll,
    /// The EVM tab's `RPC 설정하기`.
    EvmRpcOpen,
    /// The Solana tab's `RPC 설정하기`.
    SolRpcOpen,
    /// The Bitcoin tab's `RPC 설정하기`.
    BtcRpcOpen,
    /// The Zcash tab's `RPC 설정하기`.
    ZecRpcOpen,
    /// The EVM network card's failure band: `RPC 테스트` (reads the open `교체` field).
    EvmRpcTest,
    /// The Solana network card's failure band: `RPC 테스트` (reads the open `교체` field).
    SolRpcTest,
    /// The EVM failure band's `RPC 설정`.
    EvmRpcRow,
    /// The Solana failure band's `RPC 설정`.
    SolRpcRow,
    /// A network chip of the S10 drop-down.
    Network(Row),
    /// An account selection radio (row).
    Account(Row),
    /// A failed network named on S08 or in the RPC summary: its row.
    RpcRowOpen(Row),
    /// A URL row's button.
    RpcRow(Row, RpcRowAction),
}

/// The three buttons of a URL row (stride 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcRowAction {
    /// `교체`.
    Replace,
    /// `테스트` (reads the open `교체` field when it is this row's).
    Test,
    /// `삭제`.
    Delete,
}
