//! Presses of the received-history cards (`ui::screens_received` on Windows; spec/04 §2.6).
//!
//! 2026-11-18 (S3 C1): created.

use crate::cmd::Row;
use crate::received::RecvChain;

/// A press on a received-history card.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceivedPress {
    /// `받은 내역도 보기` of `chain`'s card (one setting for every card).
    Toggle {
        /// The card.
        chain: RecvChain,
        /// The check box's state when it was pressed (`None`: no such box).
        checked: Option<bool>,
    },
    /// `받은 내역 n건 더 보기 ▸` / `접기 ▾` of `chain`'s card.
    More(RecvChain),
    /// A click on a row's hash: copies it.
    CopyHash(RecvChain, Row),
    /// The row's ↗ `탐색기에서 열기`.
    OpenExplorer(RecvChain, Row),
}
