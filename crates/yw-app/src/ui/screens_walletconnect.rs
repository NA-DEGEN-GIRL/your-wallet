//! The `WalletConnect` panel at the top of S13 연결된 사이트 (spec/13 §6): `WalletConnect 연결`
//! (paste a `wc:` URI, `클립보드 이미지에서 QR 읽기`, `이미지 파일에서 QR 읽기`), the Reown
//! Project ID, the relay state, and the `WalletConnect 세션` cards (peer name, claimed URL,
//! `연결 확인 중` until the dApp confirms, Verify state, accounts, chains, expiry) with
//! `연결 해제` and `모든 WalletConnect 세션 끊기`.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): the builders, their helpers and texts moved to yw-engine
//! `screen::build::walletconnect` (bodies unchanged); this file keeps the control ids of its
//! controls (`ids`), which only the Windows shell has.

/// Control ids (16,000–16,099; the whole map is `ui::command_ids`).
pub mod ids {
    /// URI edit.
    pub const URI_EDIT: u16 = 16_000;
    /// 연결.
    pub const PAIR: u16 = 16_001;
    /// 클립보드 이미지에서 QR 읽기.
    pub const CLIPBOARD_QR: u16 = 16_002;
    /// Image path edit.
    pub const FILE_EDIT: u16 = 16_003;
    /// 이미지 파일에서 QR 읽기.
    pub const FILE_QR: u16 = 16_004;
    /// Project id edit.
    pub const PROJECT_EDIT: u16 = 16_005;
    /// Project id save.
    pub const PROJECT_SAVE: u16 = 16_006;
    /// `모든 WalletConnect 세션 끊기`.
    pub const DISCONNECT_ALL: u16 = 16_007;
    /// `Project ID 바꾸기 ▸` / `접기 ▾` (a saved id).
    pub const PROJECT_TOGGLE: u16 = 16_008;
    /// `클립보드에서 연결` (a copied `wc:` link, else a copied QR image).
    pub const CLIPBOARD_CONNECT: u16 = 16_009;
    /// `다른 방법 (이미지 파일) ▸` / `접기 ▾`.
    pub const FILE_TOGGLE: u16 = 16_010;
    /// `dashboard.reown.com 주소 복사` (copies the address, opens nothing).
    pub const REOWN_COPY: u16 = 16_011;
    /// Session row buttons (`연결 해제`).
    pub const ROW_BASE: u16 = 16_020;
    /// Row span (the engine keeps at most 64 sessions).
    pub const ROW_SPAN: u16 = 64;
    /// Every fixed id of this module.
    pub const FIXED: &[u16] = &[
        URI_EDIT,
        PAIR,
        CLIPBOARD_QR,
        FILE_EDIT,
        FILE_QR,
        PROJECT_EDIT,
        PROJECT_SAVE,
        DISCONNECT_ALL,
        PROJECT_TOGGLE,
        CLIPBOARD_CONNECT,
        FILE_TOGGLE,
        REOWN_COPY,
    ];

    /// The press control `id` stands for (2026-11-18, S3 C2: `ui::cmd_table`); `None` when `id`
    /// is not one of this module's presses (the three edits are fields, not presses).
    #[must_use]
    pub fn press_of(id: u16) -> Option<yw_engine::cmd::WcPress> {
        use yw_engine::cmd::{Row, WcPress};
        Some(match id {
            PAIR => WcPress::Pair,
            CLIPBOARD_QR => WcPress::ClipboardQr,
            CLIPBOARD_CONNECT => WcPress::ClipboardConnect,
            FILE_TOGGLE => WcPress::FileToggle,
            FILE_QR => WcPress::FileQr,
            PROJECT_SAVE => WcPress::ProjectSave,
            DISCONNECT_ALL => WcPress::DisconnectAll,
            PROJECT_TOGGLE => WcPress::ProjectToggle,
            REOWN_COPY => WcPress::ReownCopy,
            _ => WcPress::Disconnect(Row(id
                .checked_sub(ROW_BASE)
                .filter(|offset| *offset < ROW_SPAN)?)),
        })
    }

    /// The control id of `press` (the inverse of [`press_of`]).
    #[must_use]
    pub const fn id_of(press: yw_engine::cmd::WcPress) -> u16 {
        use yw_engine::cmd::{Row, WcPress};
        match press {
            WcPress::Pair => PAIR,
            WcPress::ClipboardQr => CLIPBOARD_QR,
            WcPress::ClipboardConnect => CLIPBOARD_CONNECT,
            WcPress::FileToggle => FILE_TOGGLE,
            WcPress::FileQr => FILE_QR,
            WcPress::ProjectSave => PROJECT_SAVE,
            WcPress::DisconnectAll => DISCONNECT_ALL,
            WcPress::ProjectToggle => PROJECT_TOGGLE,
            WcPress::ReownCopy => REOWN_COPY,
            WcPress::Disconnect(Row(row)) => ROW_BASE.wrapping_add(row),
        }
    }
}
