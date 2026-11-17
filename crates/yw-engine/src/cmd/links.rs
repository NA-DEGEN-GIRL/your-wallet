//! Presses of the account drop-down buttons and of the copyable activity recipients
//! (`ui::screens_links` on Windows; spec/04 §2.6).
//!
//! 2026-11-18 (S3 C1): created.

use crate::cmd::Row;

/// A drop-down or recipient press.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinksPress {
    /// The EVM `내 계정` drop-down button.
    PickerEvm,
    /// The Solana `내 Solana 계정` drop-down button.
    PickerSol,
    /// The Bitcoin `내 Bitcoin 계정` drop-down button.
    PickerBtc,
    /// The Zcash `내 Zcash 계정` drop-down button.
    PickerZec,
    /// A click on an EVM activity recipient (copies it).
    EvmTo(Row),
    /// A click on a Solana activity recipient.
    SolTo(Row),
    /// A click on a Bitcoin activity recipient.
    BtcTo(Row),
    /// A click on a Zcash activity recipient.
    ZecTo(Row),
}
