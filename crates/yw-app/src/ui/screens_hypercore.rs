//! `HyperCore` screen contents (spec/11 §8): the card on the EVM tab (S10), the transfer form
//! S-HC and the settings block under `EVM 체인`.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): the builders, their helpers and texts moved to yw-engine
//! `screen::build::hypercore` (bodies unchanged); this file keeps the control ids of its controls
//! (`ids`), which only the Windows shell has.

/// Command ids (13,450–13,499).
pub mod ids {
    /// 새로고침.
    pub const REFRESH: u16 = 13_450;
    /// 보내기(Core).
    pub const OPEN_SEND: u16 = 13_451;
    /// 현물↔선물 이동.
    pub const OPEN_CLASS: u16 = 13_452;
    /// Arbitrum으로 출금.
    pub const OPEN_WITHDRAW: u16 = 13_453;
    /// `HyperEVM으로` 이동.
    pub const OPEN_TO_EVM: u16 = 13_454;
    /// `HyperEVM에서` Core로 이동.
    pub const OPEN_FROM_EVM: u16 = 13_455;
    /// Network radio: mainnet (card and settings).
    pub const NET_MAINNET: u16 = 13_456;
    /// Network radio: testnet (card and settings).
    pub const NET_TESTNET: u16 = 13_457;
    /// Recipient edit.
    pub const TO_EDIT: u16 = 13_460;
    /// Amount edit.
    pub const AMOUNT_EDIT: u16 = 13_461;
    /// Look-alike acknowledgement.
    pub const ACK: u16 = 13_462;
    /// 검토.
    pub const REVIEW: u16 = 13_463;
    /// 취소.
    pub const CANCEL: u16 = 13_464;
    /// Direction spot → perp.
    pub const DIR_TO_PERP: u16 = 13_465;
    /// Direction perp → spot.
    pub const DIR_TO_SPOT: u16 = 13_466;
    /// Asset radio: perp USDC.
    pub const ASSET_PERP: u16 = 13_467;
    /// `최대` (the whole available amount).
    pub const MAX: u16 = 13_468;
    /// Settings: card on/off.
    pub const ENABLED: u16 = 13_490;
    /// Settings: testnet API edit.
    pub const API_EDIT: u16 = 13_491;
    /// Settings: save the testnet API.
    pub const API_SAVE: u16 = 13_492;
    /// Settings: official testnet API.
    pub const API_DEFAULT: u16 = 13_493;
    /// The folded card's `펼치기 ▸` (2026-11-10).
    pub const EXPAND: u16 = 13_494;
    /// The unfolded card's `접기 ▴`.
    pub const COLLAPSE: u16 = 13_495;
    /// Asset radios of spot tokens (row = position in the list).
    pub const ASSET_BASE: u16 = 13_470;
    /// Asset radio span.
    pub const ASSET_SPAN: u16 = 20;

    /// Every fixed id of this module.
    pub const FIXED: &[u16] = &[
        REFRESH,
        OPEN_SEND,
        OPEN_CLASS,
        OPEN_WITHDRAW,
        OPEN_TO_EVM,
        OPEN_FROM_EVM,
        NET_MAINNET,
        NET_TESTNET,
        TO_EDIT,
        AMOUNT_EDIT,
        ACK,
        REVIEW,
        CANCEL,
        DIR_TO_PERP,
        DIR_TO_SPOT,
        ASSET_PERP,
        MAX,
        ENABLED,
        API_EDIT,
        API_SAVE,
        API_DEFAULT,
        EXPAND,
        COLLAPSE,
    ];

    /// The press control `id` stands for (2026-11-18, S3 C7: `ui::cmd_table`). `None` when `id`
    /// is not one of this module's presses (the three edits are fields). The asset radio range
    /// is claimed whole ([`ASSET_SPAN`] rows), as the ids reached the handler before.
    #[must_use]
    pub fn press_of(id: u16) -> Option<yw_engine::cmd::HcPress> {
        use yw_engine::cmd::{HcPress, Row};
        Some(match id {
            REFRESH => HcPress::Refresh,
            OPEN_SEND => HcPress::OpenSend,
            OPEN_CLASS => HcPress::OpenClass,
            OPEN_WITHDRAW => HcPress::OpenWithdraw,
            OPEN_TO_EVM => HcPress::OpenToEvm,
            OPEN_FROM_EVM => HcPress::OpenFromEvm,
            NET_MAINNET => HcPress::NetMainnet,
            NET_TESTNET => HcPress::NetTestnet,
            ACK => HcPress::Ack,
            REVIEW => HcPress::Review,
            CANCEL => HcPress::Cancel,
            DIR_TO_PERP => HcPress::DirToPerp,
            DIR_TO_SPOT => HcPress::DirToSpot,
            ASSET_PERP => HcPress::AssetPerp,
            MAX => HcPress::Max,
            ENABLED => HcPress::Enabled,
            API_SAVE => HcPress::ApiSave,
            API_DEFAULT => HcPress::ApiDefault,
            EXPAND => HcPress::Expand,
            COLLAPSE => HcPress::Collapse,
            _ => HcPress::Asset(Row(id
                .checked_sub(ASSET_BASE)
                .filter(|row| *row < ASSET_SPAN)?)),
        })
    }

    /// The control id of `press` (the inverse of [`press_of`]).
    #[must_use]
    pub const fn id_of(press: yw_engine::cmd::HcPress) -> u16 {
        use yw_engine::cmd::{HcPress, Row};
        match press {
            HcPress::Refresh => REFRESH,
            HcPress::OpenSend => OPEN_SEND,
            HcPress::OpenClass => OPEN_CLASS,
            HcPress::OpenWithdraw => OPEN_WITHDRAW,
            HcPress::OpenToEvm => OPEN_TO_EVM,
            HcPress::OpenFromEvm => OPEN_FROM_EVM,
            HcPress::NetMainnet => NET_MAINNET,
            HcPress::NetTestnet => NET_TESTNET,
            HcPress::Ack => ACK,
            HcPress::Review => REVIEW,
            HcPress::Cancel => CANCEL,
            HcPress::DirToPerp => DIR_TO_PERP,
            HcPress::DirToSpot => DIR_TO_SPOT,
            HcPress::AssetPerp => ASSET_PERP,
            HcPress::Max => MAX,
            HcPress::Enabled => ENABLED,
            HcPress::ApiSave => API_SAVE,
            HcPress::ApiDefault => API_DEFAULT,
            HcPress::Expand => EXPAND,
            HcPress::Collapse => COLLAPSE,
            HcPress::Asset(Row(row)) => ASSET_BASE.wrapping_add(row),
        }
    }
}
