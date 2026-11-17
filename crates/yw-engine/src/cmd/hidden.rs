//! Presses of the hidden-account lists of the account cards (`app_hidden` on Windows; spec/04
//! §2.6).
//!
//! 2026-11-18 (S3 C1): created.

use crate::cmd::Row;

/// A press on a hidden-account list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiddenPress {
    /// EVM `숨긴 계정 n개 보기 ▸` / `접기 ▾`.
    EvmToggle,
    /// Solana `숨긴 계정 n개 보기 ▸` / `접기 ▾`.
    SolToggle,
    /// Bitcoin `숨긴 계정 n개 보기 ▸` / `접기 ▾`.
    BtcToggle,
    /// EVM `다시 보이기` of a hidden row.
    EvmUnhide(Row),
    /// Solana `다시 보이기` of a hidden row.
    SolUnhide(Row),
    /// Bitcoin `다시 보이기` of a hidden row (the settings network's accounts).
    BtcUnhide(Row),
}
