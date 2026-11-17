//! Presses of the Zcash tab: its account card, 받기, 보내기 and activity cards and the
//! `내 Zcash 계정` drop-down (`ui::screens_zec` on Windows; spec/12 §11).
//!
//! 2026-11-18 (S3 C7): created.

use crate::cmd::Row;

/// A Zcash press. The row presses name an item by its position in the list as drawn (`Row`);
/// a row past the list does nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZecPress {
    /// Tab `Zcash`.
    TabZec,
    /// Enable on mainnet.
    EnableMainnet,
    /// Enable on testnet.
    EnableTestnet,
    /// Turn off.
    Disable,
    /// `새로고침`.
    Refresh,
    /// The 받기 card's `주소 복사` (its own copy anchor).
    CopyAddress,
    /// The account card's `주소 복사` (its own copy anchor).
    CardCopy,
    /// `QR 보기` / `숨기기`.
    QrToggle,
    /// `최대` (toggles; the box is not read).
    SendMax,
    /// `검토`.
    SendReview,
    /// The drop-down item of the standard path.
    SourceStandard,
    /// `정말 EVM 키 사용` of the EVM-key confirmation.
    SourceApply,
    /// `취소` of the EVM-key confirmation.
    SourceCancel,
    /// The drop-down item of the account's source when no other item is it.
    SourceCurrent,
    /// UTXO source: node.
    IndexerNode,
    /// UTXO source: Blockbook.
    IndexerBb,
    /// W-ADDR-3 `주소 전체를 직접 확인했습니다` (toggles; the box is not read).
    SendAddrAck,
    /// `해시 복사` of the 보내기 card's result line.
    ResultCopy,
    /// `개인키 가져오기`.
    Import,
    /// `개인키 보기` of the account's imported key.
    Reveal,
    /// `삭제` of the account's imported key.
    Remove,
    /// An activity row's `해시 복사` (newest first).
    ActivityCopy(Row),
    /// A drop-down item of an EVM account's key.
    SourceEvm(Row),
    /// A drop-down item of a `YubiKey` Zcash key.
    Hw(Row),
    /// A drop-down item of an imported key of the network.
    Imported(Row),
}
