//! Presses of the settings section `복구 단어` and of the recovery-phrase pickers other screens
//! show (`ui::screens_mnemonics` on Windows; spec/04 §2.11 "복구 단어", spec/02 §8.6).
//!
//! 2026-11-18 (S3 C6): created.

use crate::cmd::Row;

/// A recovery-phrase press. The row presses name a phrase by its position in the list as drawn
/// (`Row`); a row past the list does nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MnPress {
    /// The settings tab `복구 단어`.
    SectionMnemonics,
    /// The main account card's `복구 단어 관리`.
    MainLink,
    /// `복구 단어 추가 가져오기`.
    Import,
    /// `새 복구 단어 만들기`.
    Create,
    /// The address preview's `가져오기`.
    PreviewConfirm,
    /// The address preview's `취소`.
    PreviewCancel,
    /// The address preview's T-YK-SAME check (toggles; the box is not read).
    PreviewSameAck,
    /// The label form's `저장`.
    RenameSave,
    /// The label form's `취소`.
    RenameCancel,
    /// The removal warning's `지우기`.
    RemoveConfirm,
    /// The removal warning's `단어 보기` (an unconfirmed phrase).
    RemoveReveal,
    /// The removal warning's `취소`.
    RemoveCancel,
    /// The `계정 추가` picker's `취소`.
    PickCancel,
    /// The Solana `계정 추가` picker's `취소`.
    SolPickCancel,
    /// A phrase card's `이름 바꾸기`.
    Rename(Row),
    /// A phrase card's `단어 보기`.
    Reveal(Row),
    /// A phrase card's `백업 확인`.
    Backup(Row),
    /// A phrase card's `지우기`.
    Remove(Row),
    /// The `계정 추가` picker's button of a phrase.
    Pick(Row),
    /// The Solana `계정 추가` picker's button of a phrase.
    SolPick(Row),
    /// The Bitcoin `계정 추가` key source radio of a phrase.
    BtcPick(Row),
    /// The Zcash key source button of a phrase.
    ZecPick(Row),
}
