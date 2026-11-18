//! Presses of the `YubiKey` screens (`ui::screens_yubikey` on Windows; spec/10): the settings
//! tab and the enrolment wizard ([`YkPress`]), the card actions re-slot and clear
//! ([`YkManagePress`]) and the connect flow ([`YkConnectPress`]) — the three handler functions
//! of the Windows app, one enum each (plan D-c).
//!
//! The Windows app's own choice enums (`PgpKind`, the re-slot `Chain`, `Preset`, the connect
//! `Choice`) stay in yw-app until S4 (plan D-d): each of their values is its own variant here;
//! the yw-core types (`PgpKey`, `ScriptType`, `TouchPolicy`, `ZecNetwork`) are carried as they
//! are.
//!
//! 2026-11-18 (S3 C11): created.

use yw_core::btc::ScriptType;
use yw_core::yubikey::plan::{PgpKey, TouchPolicy};
use yw_core::zec::ZecNetwork;

use crate::cmd::Row;

/// A press of the `YubiKey` settings tab and the enrolment wizard. The row presses name a card
/// by its position in the list as drawn (`Row`); a row past the list does nothing. The check
/// boxes of the wizard toggle their state and never read the box.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum YkPress {
    /// The settings tab `YubiKey`.
    SectionYubikey,
    /// The card name edit's `저장`.
    CardNameSave,
    /// The card name edit's `이름 지우기`.
    CardNameClear,
    /// The card name edit's `취소`.
    CardNameCancel,
    /// `YubiKey 등록` (settings, a key-only wallet's chain card).
    EnrolStart,
    /// S01 `YubiKey 지갑 만들기`.
    NewWallet,
    /// S20 `시작하기`.
    NewWalletStart,
    /// S20 `취소`.
    NewWalletCancel,
    /// PIV touch "항상".
    PivTouchAlways,
    /// PIV touch "15초 유지".
    PivTouchCached,
    /// The spec/10 §3.2 check box of the shared key.
    SharedAck,
    /// The "백업 복사본" check box.
    BackupToggle,
    /// Step (d): the T-YK-OCCUPIED check box.
    OverwriteAck,
    /// Step (a) `다음`.
    PlanNext,
    /// Step (e) `완료`.
    Finish,
    /// Step (e) `다른 YubiKey 등록(백업)`.
    Another,
    /// The wizard's `취소`.
    WizardCancel,
    /// The result's '슬롯·주소 자세히 ▸'.
    ResultDetails,
    /// "PIN 설정": 'PIN 안내 ▸'.
    PinGuide,
    /// Steps (c)/(d): `다시 읽기` of the inserted card.
    IdentifyAgain,
    /// Main window: `PIN 설정` after a signing refused for factory PINs.
    PinNeededOpen,
    /// Step (c): the same-mnemonic check box.
    SameAck,
    /// Step (c) `← 슬롯 다시 고르기`.
    ConfirmBack,
    /// Step (c) `다음`.
    ConfirmNext,
    /// Step (e) `다시 시도` after a failure.
    Retry,
    /// Step (d) `← 이전`.
    CredBack,
    /// Step (d) "기본 관리 키 사용".
    MgmtDefault,
    /// Step (d) "관리 키 직접 입력".
    MgmtCustom,
    /// Step (d) `가져오기`.
    Import,
    /// Step (d) `가져오기 없이 등록`.
    Adopt,
    /// Step (e) `다시 확인`.
    Recheck,
    /// Step (e) `OpenPGP PIN 바꾸기`.
    ChangePw1,
    /// Step (e) `OpenPGP 관리자 PIN 바꾸기`.
    ChangePw3,
    /// Step (e) `PIV PIN 바꾸기`.
    ChangePivPin,
    /// Step (e) `PIV PUK 바꾸기`.
    ChangePuk,
    /// Step (e) `PIV 관리 키 자동 보호`.
    ChangeMgmt,
    /// "PIN 설정" `PIN 설정하기`.
    SetPins,
    /// "PIN 설정" mode "8자리 하나로 통일".
    PinsUnified,
    /// "PIN 설정" mode "하나씩 따로".
    PinsSeparate,
    /// An `OpenPGP` slot's kind radio: nothing.
    PgpNone(PgpKey),
    /// An `OpenPGP` slot's kind radio: EVM account `i`.
    PgpEvm(PgpKey),
    /// An `OpenPGP` slot's kind radio: Bitcoin single address `i`.
    PgpBtc(PgpKey),
    /// An `OpenPGP` slot's kind radio: the EVM shared key (spec/10 §3.2).
    PgpShared(PgpKey),
    /// An `OpenPGP` slot's kind radio: Zcash transparent address `i`.
    PgpZec(PgpKey),
    /// An `OpenPGP` slot's Bitcoin address-type radio.
    PgpScript(PgpKey, ScriptType),
    /// An `OpenPGP` slot's touch-policy radio.
    PgpTouch(PgpKey, TouchPolicy),
    /// An `OpenPGP` slot's Zcash network radio.
    PgpZecNetwork(PgpKey, ZecNetwork),
    /// A "백업 복사본" source radio (card row).
    Backup(Row),
    /// Settings `삭제` of a card row.
    Remove(Row),
    /// `이름 바꾸기` of a card row (opens or closes its name edit).
    RenameCard(Row),
    /// Settings `PIN 설정 / 기본값 변경` of a card row (opens or closes it).
    Pins(Row),
    /// `PIN 설정` of the band of an account card or send form (card row).
    PinGate(Row),
}

/// A press of the card actions re-slot and clear (spec/10 §15). Their check boxes toggle
/// their state and never read the box.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum YkManagePress {
    /// `슬롯 구성 바꾸기` of a card row (spec/10 §15.1).
    Reslot(Row),
    /// `YubiKey 비우기` of a card row (spec/10 §15.2).
    Clear(Row),
    /// "백업 `YubiKey`에도 같은 구성 적용" of a card row.
    ReslotBackup(Row),
    /// A re-slot slot's chain radio: EVM account `i`.
    ReslotEvm(PgpKey),
    /// A re-slot slot's chain radio: Bitcoin single address `i`.
    ReslotBtc(PgpKey),
    /// A re-slot slot's chain radio: Zcash transparent address `i`.
    ReslotZec(PgpKey),
    /// A re-slot slot's chain radio: the EVM shared key (advanced).
    ReslotShared(PgpKey),
    /// A re-slot slot's Bitcoin address-type radio.
    ReslotScript(PgpKey, ScriptType),
    /// Preset radio SIG = EVM, AUT = Bitcoin.
    PresetEvmBtc,
    /// Preset radio SIG = EVM, AUT = Zcash.
    PresetEvmZec,
    /// Preset radio SIG = Bitcoin, AUT = Zcash.
    PresetBtcZec,
    /// Preset radio SIG = EVM `i`, AUT = EVM `i + 1`.
    PresetEvmEvm,
    /// Preset radio: chosen per slot.
    PresetCustom,
    /// Re-slot Zcash network "메인넷".
    ZecMain,
    /// Re-slot Zcash network "테스트넷".
    ZecTest,
    /// Re-slot "고급: EVM 공유 키도 보이기".
    Advanced,
    /// Re-slot spec/10 §3.2 check box of the shared key.
    SharedAck,
    /// Re-slot "이해했습니다" of the removed chains.
    RemovedAck,
    /// Re-slot T-YK-KEY-LOST check box.
    LossAck,
    /// Re-slot T-YK-SAME check box.
    SameAck,
    /// Clear T-YK-KEY-LOST check box.
    ClearLossAck,
    /// Re-slot `다음`.
    Next,
    /// Re-slot `← 다시 고르기`.
    Back,
    /// Re-slot `YubiKey에 넣기` (admin PIN).
    Import,
    /// Re-slot `다시 시도`.
    Retry,
    /// Card action `완료`.
    Done,
    /// Card action `취소`.
    Cancel,
    /// Re-slot result: `PIN 설정하기` of a card left on its factory PINs.
    PinNow,
    /// Clear: the `OpenPGP` wallet keys check box.
    ClearPgpToggle,
    /// Clear: the PIV Solana slots check box.
    ClearPivToggle,
    /// Clear: `OpenPGP` "우리 슬롯만 지우기".
    ClearPgpOurs,
    /// Clear: `OpenPGP` "애플릿 초기화".
    ClearPgpReset,
    /// Clear: PIV "우리 슬롯만 지우기".
    ClearPivOurs,
    /// Clear: PIV "애플릿 초기화".
    ClearPivReset,
    /// Clear `비우기`.
    ClearRun,
    /// Clear '어떻게 지우나요 ▸'.
    ClearHow,
}

/// A press of the connect flow (spec/10 §7.6). A found key's choice radio names its row and
/// the choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum YkConnectPress {
    /// "`YubiKey` 연결하기 (복구 단어 없이)" in settings and the chain cards.
    Start,
    /// The S01 entry of "`YubiKey` 연결하기" (a new `YubiKey` wallet).
    NewWallet,
    /// `다시 읽기` of the connect scan.
    Rescan,
    /// `다음` (choices → addresses).
    Next,
    /// `← 다시 고르기`.
    Back,
    /// `PIN으로 소유 확인 (선택)`.
    Pin,
    /// `저장`.
    Save,
    /// A found key's choice radio: EVM account.
    ChoiceEvm(Row),
    /// A found key's choice radio: a Bitcoin address of this type.
    ChoiceBtc(Row, ScriptType),
    /// A found key's choice radio: Zcash transparent address.
    ChoiceZec(Row),
    /// A found key's choice radio: Solana account.
    ChoiceSol(Row),
    /// A found key's choice radio: not connected.
    ChoiceSkip(Row),
}
