//! Presses of the `HyperCore` card on the EVM tab, the transfer form S-HC and the settings block
//! under `EVM 체인` (`ui::screens_hypercore` on Windows; spec/11 §8).
//!
//! 2026-11-18 (S3 C7): created.

use crate::cmd::Row;

/// A `HyperCore` press.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HcPress {
    /// The card's `새로고침`.
    Refresh,
    /// `보내기(Core)`.
    OpenSend,
    /// `현물↔선물 이동`.
    OpenClass,
    /// `Arbitrum으로 출금`.
    OpenWithdraw,
    /// `HyperEVM으로` 이동.
    OpenToEvm,
    /// `HyperEVM에서` Core로 이동.
    OpenFromEvm,
    /// Network radio mainnet (card and settings).
    NetMainnet,
    /// Network radio testnet (card and settings).
    NetTestnet,
    /// S-HC look-alike acknowledgement (toggles; the box is not read).
    Ack,
    /// S-HC `검토`.
    Review,
    /// S-HC `취소`.
    Cancel,
    /// Direction spot → perp.
    DirToPerp,
    /// Direction perp → spot.
    DirToSpot,
    /// Asset radio perp USDC.
    AssetPerp,
    /// `최대` (the whole available amount).
    Max,
    /// Settings: the card on/off (toggles; the box is not read).
    Enabled,
    /// Settings: save the testnet API.
    ApiSave,
    /// Settings: the official testnet API.
    ApiDefault,
    /// The folded card's `펼치기 ▸`.
    Expand,
    /// The unfolded card's `접기 ▴`.
    Collapse,
    /// An asset radio of a spot token (position in the list as drawn; past the list it does
    /// nothing).
    Asset(Row),
}
