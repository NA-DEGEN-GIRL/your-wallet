//! Presses of the EVM screens: the account card and its network drop-down, send (S11), receive
//! (S12), the token card and S16 `토큰 추가`, the activity rows, the settings sections `EVM 체인`
//! (S17 and the chain rows) and `수수료 상한` (`ui::screens_evm` on Windows; spec/03, spec/04
//! §2.6–§2.7).
//!
//! 2026-11-18 (S3 C10): created.

use crate::cmd::Row;

/// An EVM press. The row presses name an item by its position in the list as drawn (`Row`); a
/// row past the list does nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvmPress {
    /// `보내기`.
    SendOpen,
    /// `받기`.
    ReceiveOpen,
    /// `새로고침`.
    Refresh,
    /// `주소록`.
    BookOpen,
    /// `토큰 추가`.
    TokenOpen,
    /// `설정에서 다시 고정`.
    RepinSettings,
    /// The S10 network drop-down button (opens / closes the list).
    NetworkPicker,
    /// `최대`.
    SendMax,
    /// `주소록에서 선택`.
    SendPick,
    /// The W-ADDR-3 check: the box's state when it was pressed (`None`: no such box).
    SendAck(Option<bool>),
    /// `검토`.
    SendReview,
    /// `취소` / `돌아가기` of the send form.
    SendCancel,
    /// The send form's `숨긴 토큰 n개 보기`.
    SendHiddenToggle,
    /// `주소 복사` (S12 and the S10 account card).
    CopyAddress,
    /// The receive QR: EIP-681.
    QrEip681,
    /// The receive QR: the bare address.
    QrPlain,
    /// S16 `조회`.
    TokenLookup,
    /// S16 `저장`.
    TokenSave,
    /// The token card's `잔액 0인 토큰 숨기기`: the box's state when it was pressed.
    TokenHideZero(Option<bool>),
    /// The token card's `숨긴 토큰 n개 보기` / `접기`.
    TokenHiddenToggle,
    /// The settings section `EVM 체인`.
    SectionChains,
    /// `추가` (S17 for a new chain).
    ChainAdd,
    /// S17 simulation `자동`.
    ChainSimAuto,
    /// S17 simulation `지원 안 함`.
    ChainSimUnsupported,
    /// S17 `저장`.
    ChainSave,
    /// S17 `취소`.
    ChainCancel,
    /// Fee caps `저장`.
    CapsSave,
    /// Fee caps `기본값으로`.
    CapsDefault,
    /// Activity `이전 활동 n건 더 보기` / `접기`.
    ActivityMore,
    /// The T-CHAIN-REPIN-ACK check: the box's state when it was pressed.
    RepinCheck(Option<bool>),
    /// A send-form asset radio (the native asset, then the chain's tokens).
    SendAsset(Row),
    /// The token card's `{기호} 보내기` (token row).
    TokenSend(Row),
    /// The token card's `주소 복사` of the contract (token row).
    TokenCopy(Row),
    /// The token card's `숨기기` / `다시 보이기` (token row).
    TokenToggleHidden(Row),
    /// The token card's `삭제` (token row; user tokens only).
    TokenDelete(Row),
    /// An address-book picker row of the send form.
    PickRecipient(Row),
    /// A chain row's button in the settings section `EVM 체인`.
    ChainRow(Row, ChainRowAction),
    /// A fee-caps chain radio.
    CapsChain(Row),
    /// An activity row's button.
    Activity(Row, EvmActivityAction),
}

/// The three buttons of a chain row (stride 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainRowAction {
    /// `편집` (user chains only).
    Edit,
    /// `삭제` (user chains only).
    Delete,
    /// `다시 고정`.
    Repin,
}

/// The eight buttons of an activity row (stride 8, in id order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvmActivityAction {
    /// `해시 복사`.
    CopyHash,
    /// `수수료 올리기`.
    SpeedUp,
    /// `취소`.
    Cancel,
    /// `재전송`.
    Resend,
    /// `폐기`.
    Discard,
    /// `탐색기 링크 복사`.
    CopyExplorerLink,
    /// `이 주소 저장`.
    SaveAddress,
    /// `탐색기에서 열기`.
    OpenExplorer,
}
