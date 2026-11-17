//! Presses of the block-explorer card of S15 and of the explorer links other screens add next
//! to a hash or an address (`ui::screens_explorer` on Windows; spec/04 §2.6, §2.11 "블록
//! 탐색기").
//!
//! 2026-11-18 (S3 C3): created.

use crate::cmd::Row;

/// An explorer press.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExplorerPress {
    /// `저장` of the card's open form.
    Save,
    /// `취소` of the card's open form.
    Cancel,
    /// The EVM account card's `탐색기에서 주소 보기`.
    CardEvm,
    /// The Solana account card's `탐색기에서 주소 보기`.
    CardSol,
    /// The Bitcoin account card's `탐색기에서 주소 보기`.
    CardBtc,
    /// The Zcash account card's `탐색기에서 주소 보기`.
    CardZec,
    /// The `HyperCore` card's `탐색기에서 주소 보기`.
    CardHc,
    /// The EVM send result's `탐색기에서 열기`.
    ResultEvmOpen,
    /// The EVM send result's `탐색기 링크 복사`.
    ResultEvmCopy,
    /// The Solana send result's `탐색기에서 열기`.
    ResultSolOpen,
    /// The Solana send result's `탐색기 링크 복사`.
    ResultSolCopy,
    /// The Bitcoin send result's `탐색기에서 열기`.
    ResultBtcOpen,
    /// The Bitcoin send result's `탐색기 링크 복사`.
    ResultBtcCopy,
    /// The Zcash send result's `탐색기에서 열기`.
    ResultZecOpen,
    /// The Zcash send result's `탐색기 링크 복사`.
    ResultZecCopy,
    /// A network row of the card.
    Row(Row, ExplorerRowAction),
    /// A Solana activity row's explorer link.
    SolActivity(Row, ExplorerLinkAction),
    /// A Bitcoin activity row's explorer link.
    BtcActivity(Row, ExplorerLinkAction),
    /// A Zcash activity row's explorer link.
    ZecActivity(Row, ExplorerLinkAction),
}

/// The buttons of a network row of the card (stride 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExplorerRowAction {
    /// `변경`: opens the form for the row's network.
    Edit,
    /// `기본값으로`: removes the network's override.
    Reset,
}

/// The two explorer links of an activity row (stride 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExplorerLinkAction {
    /// ↗ `탐색기에서 열기`.
    Open,
    /// 🔗 `탐색기 링크 복사`.
    Copy,
}
