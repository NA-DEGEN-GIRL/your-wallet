//! Presses of the address book (S14) and of its send-side parts: the favorite chips and the
//! Bitcoin `주소록에서 선택` of the send forms, and the inline `주소록에 저장` prompt
//! (`ui::screens_book` on Windows; spec/04 §2.10).
//!
//! 2026-11-18 (S3 C4): created.

use crate::cmd::Row;

/// An address-book press.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BookPress {
    /// S14 family tab EVM.
    ChainEvm,
    /// S14 family tab Solana.
    ChainSol,
    /// S14 family tab Bitcoin.
    ChainBtc,
    /// The form's verified check: the box's state when it was pressed (`None`: no such box).
    Verified(Option<bool>),
    /// The form's `즐겨찾기에 추가` check: the box's state when it was pressed.
    Favorite(Option<bool>),
    /// `추가` / `저장` of the form.
    Save,
    /// `취소` of the form (also Esc from one of its edits).
    Cancel,
    /// The form's look-alike `주소 전체를 직접 확인했습니다`: the box's state when it was pressed.
    FormAck(Option<bool>),
    /// `저장` of the inline prompt.
    PromptSave,
    /// `취소` of the inline prompt.
    PromptCancel,
    /// The prompt's look-alike check: the box's state when it was pressed.
    PromptAck(Option<bool>),
    /// The send form's `주소록에 저장`.
    SendSave,
    /// The send result's `주소록에 저장`.
    ResultSave,
    /// The Bitcoin send form's `주소록에서 선택`.
    BtcPick,
    /// S14 `＋ 주소 추가`.
    AddOpen,
    /// A favorite chip of the send form.
    Chip(Row),
    /// A row of the Bitcoin picker.
    BtcPickRow(Row),
    /// A Solana activity row's `이 주소 저장`.
    SolActivitySave(Row),
    /// An S14 row's button.
    Row(Row, BookRowAction),
    /// An S14 row's address line (copies the address).
    Copy(Row),
}

/// The buttons of an S14 row (stride 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BookRowAction {
    /// `★`: favorite on or off.
    Favorite,
    /// `편집`.
    Edit,
    /// `삭제` (asks first).
    Delete,
}
