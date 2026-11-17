//! Presses of the imported-key screens: S01's `개인키로 시작하기`, S18, S19 and the imported-key
//! part of the Solana and Bitcoin account cards (`ui::screens_keys` on Windows; spec/04 §2.18).
//!
//! 2026-11-18 (S3 C5): created.

use yw_core::btc::ScriptType;

/// An imported-key press.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeysPress {
    /// S01 `개인키로 시작하기`.
    FirstKey,
    /// S18 chain radio EVM.
    StartChainEvm,
    /// S18 chain radio Solana.
    StartChainSol,
    /// S18 chain radio Bitcoin.
    StartChainBtc,
    /// S18 `시작하기`.
    StartNext,
    /// S19 `맞습니다`.
    StartCorrect,
    /// S19 `다릅니다`.
    StartWrong,
    /// An address-type radio (S18 and the Bitcoin tab).
    Script(ScriptType),
    /// The Solana tab's `개인키 가져오기`.
    SolImport,
    /// The Bitcoin tab's `개인키 가져오기`.
    BtcImport,
    /// The selected imported Solana account's `개인키 보기`.
    SolReveal,
    /// The selected imported Solana account's `삭제`.
    SolRemove,
    /// The selected Bitcoin account's `개인키 보기` (WIF).
    BtcReveal,
    /// The selected imported Bitcoin account's `삭제`.
    BtcRemove,
    /// The Bitcoin tab's `다음 (개인키 입력)` (also a key-only wallet's empty Bitcoin card).
    BtcImportNext,
    /// The Bitcoin tab's `취소` of the address-type chooser.
    BtcImportCancel,
}
