//! Presses of the Bitcoin screens: the tab, account card and its address-type chooser, send,
//! fee bump, result, receive, activity and UTXO rows and the settings section
//! (`ui::screens_btc` on Windows; spec/08, spec/04 §2.6).
//!
//! 2026-11-18 (S3 C9): created.

use yw_core::btc::{BtcNetwork, ScriptType};

use crate::cmd::Row;

/// A Bitcoin press. The row presses name an item by its position in the list as drawn (`Row`);
/// a row past the list does nothing. The fee radios are one variant per choice and form (the
/// Windows app's `BtcFeeChoice` stays in yw-app until S4, plan D-d).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcPress {
    /// Tab `Bitcoin`.
    TabBtc,
    /// The settings section `Bitcoin` (also `Bitcoin 설정` on the disabled tab).
    SectionBtc,
    /// `새로고침`.
    Refresh,
    /// `보내기`.
    SendOpen,
    /// `받기`.
    ReceiveOpen,
    /// `수수료 올리기` (the current bump target).
    BumpOpen,
    /// Discovery `다시 시도`.
    DiscoverRetry,
    /// `더 찾기`.
    DiscoverMore,
    /// Discovery `취소`.
    DiscoverCancel,
    /// The network mismatch's `설정을 … 되돌리기`.
    MismatchKeepMeta,
    /// The network mismatch's `… 바꾸기`.
    MismatchUseSettings,
    /// `블록 높이 기록 초기화`.
    ResetTip,
    /// The selected account's `이름 바꾸기`.
    Rename,
    /// The name form's `저장`.
    RenameSave,
    /// The name form's `취소`.
    RenameCancel,
    /// The selected account's `숨기기`.
    Hide,
    /// `계정 추가` (opens the address-type chooser).
    AccountAdd,
    /// The chooser's `취소`.
    AccountAddCancel,
    /// The chooser's address type.
    AccountAddType(ScriptType),
    /// The chooser's key source `BTC 표준 경로`.
    AccountSourceStandard,
    /// The chooser's key source `EVM 계정과 같은 키`.
    AccountSourceEvm,
    /// Address mode `고정 주소 하나만 사용`.
    AddressModeSingle,
    /// Address mode `받을 때마다 새 주소`.
    AddressModeHd,
    /// W-ADDR-3 `주소 전체를 직접 확인했습니다` (toggles; the box is not read).
    SendAddrAck,
    /// Send unit `BTC`.
    UnitBtc,
    /// Send unit `sats`.
    UnitSats,
    /// `보내기 최대` (toggles; the box is not read).
    SendMax,
    /// Send fee `빠름`.
    FeeFast,
    /// Send fee `보통`.
    FeeNormal,
    /// Send fee `느림`.
    FeeSlow,
    /// Send fee `직접 입력`.
    FeeManual,
    /// Send `검토`.
    SendReview,
    /// Send `취소`.
    SendCancel,
    /// Result `해시 복사`.
    ResultCopy,
    /// Result `다시 시도`.
    ResultRetry,
    /// Result `보내기 화면으로`.
    ResultToSend,
    /// Bump fee `빠름`.
    BumpFeeFast,
    /// Bump fee `보통`.
    BumpFeeNormal,
    /// Bump fee `느림`.
    BumpFeeSlow,
    /// Bump fee `직접 입력`.
    BumpFeeManual,
    /// Bump `검토`.
    BumpReview,
    /// Bump `취소`.
    BumpCancel,
    /// The receive screen's `주소 복사` (its own copy anchor).
    CopyAddress,
    /// The account card's `주소 복사` (its own copy anchor).
    CardCopy,
    /// Receive `새 주소`.
    NewAddress,
    /// Settings `Bitcoin 사용` (toggles; the box is not read).
    Enable,
    /// Settings network `mainnet`.
    SetMainnet,
    /// Settings network `testnet4`.
    SetTestnet4,
    /// Settings indexer `Esplora`.
    IdxEsplora,
    /// Settings indexer `bb-rpc`.
    IdxBbRpc,
    /// Settings indexer `bb-rest`.
    IdxBbRest,
    /// A network's Esplora URL `저장`.
    EsploraSave(BtcNetwork),
    /// A network's Esplora URL `기본값으로`.
    EsploraDefault(BtcNetwork),
    /// A network's Esplora URL `테스트`.
    EsploraTest(BtcNetwork),
    /// The chooser's EVM account radio (row of the visible EVM accounts).
    EvmAccount(Row),
    /// An account drop-down item (row of the visible accounts).
    Account(Row),
    /// A UTXO row's `동결` / `해제`.
    Utxo(Row),
    /// An activity row's button.
    Activity(Row, BtcActivityAction),
}

/// The buttons of a Bitcoin activity row (stride 8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcActivityAction {
    /// `해시 복사`.
    CopyHash,
    /// `수수료 올리기`.
    Bump,
    /// `같은 바이트 다시 전송`.
    Rebroadcast,
    /// `포기`.
    Abandon,
    /// `Esplora로 전송`.
    Esplora,
    /// `전송 계속` / `다시 시도`.
    Continue,
    /// `취소` (a signed record).
    Cancel,
    /// `이 주소 저장` (address book).
    SaveAddress,
}
