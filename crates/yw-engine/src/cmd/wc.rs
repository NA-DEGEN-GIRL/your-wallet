//! Presses of the `WalletConnect` panel of S13 (`ui::screens_walletconnect` on Windows; spec/04
//! §2.9, spec/13 §6–§8).
//!
//! 2026-11-18 (S3 C2): created.

use crate::cmd::Row;

/// A press on the `WalletConnect` panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WcPress {
    /// `연결` with the pasted `wc:` link.
    Pair,
    /// `클립보드 이미지에서 QR 읽기`.
    ClipboardQr,
    /// `클립보드에서 연결` (a copied `wc:` link, else a copied QR image).
    ClipboardConnect,
    /// `다른 방법 (이미지 파일) ▸` / `접기 ▾`.
    FileToggle,
    /// `이미지 파일에서 QR 읽기`.
    FileQr,
    /// The Reown Project ID's `저장`.
    ProjectSave,
    /// `모든 WalletConnect 세션 끊기` (asks first).
    DisconnectAll,
    /// `Project ID 바꾸기 ▸` / `접기 ▾`.
    ProjectToggle,
    /// `dashboard.reown.com 주소 복사`.
    ReownCopy,
    /// `연결 해제` of a session card (the session that card was drawn for).
    Disconnect(Row),
}
