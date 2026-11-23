//! The S10 Zcash tab (spec/12 §11, spec/04 §2.6): enable / network, account and key source,
//! balance, receive (transparent address, QR, the Zashi note), send (t-address, TEX or the
//! transparent receiver of a UA; amount or `보내기 최대`; review, with what it ended with next
//! to `검토`), activity (this wallet's journal records with `해시 복사`, and the address UTXOs).
//! One page, no extra screens.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): the builders, their helpers and texts moved to yw-engine
//! `screen::build::zec` (bodies unchanged); this file keeps the control ids of its controls
//! (`ids`), which only the Windows shell has.

/// Command ids of the Zcash tab (8,000–8,099; the map and its checks are `ui::command_ids`).
pub mod ids {
    /// Tab `Zcash`.
    pub const TAB_ZEC: u16 = 8_000;
    /// Enable on mainnet.
    pub const ENABLE_MAINNET: u16 = 8_001;
    /// Enable on testnet.
    pub const ENABLE_TESTNET: u16 = 8_002;
    /// Turn off.
    pub const DISABLE: u16 = 8_003;
    /// 새로고침.
    pub const REFRESH: u16 = 8_004;
    /// 주소 복사.
    pub const COPY_ADDRESS: u16 = 8_005;
    /// QR 보기 / 숨기기.
    pub const QR_TOGGLE: u16 = 8_006;
    /// Recipient edit.
    pub const SEND_TO_EDIT: u16 = 8_007;
    /// Amount edit.
    pub const SEND_AMOUNT_EDIT: u16 = 8_008;
    /// 최대 (check box).
    pub const SEND_MAX: u16 = 8_009;
    /// 검토.
    pub const SEND_REVIEW: u16 = 8_010;
    /// The drop-down item of the standard path: picking it applies it (2026-11-15; its radio
    /// before, applied by `이 키 출처 사용`).
    pub const SOURCE_STANDARD: u16 = 8_011;
    /// `정말 EVM 키 사용` of the EVM-key confirmation (2026-11-15: shown for that step only;
    /// before, also the radios' `이 키 출처 사용`).
    pub const SOURCE_APPLY: u16 = 8_012;
    /// Key source: cancel the EVM-key confirmation.
    pub const SOURCE_CANCEL: u16 = 8_013;
    /// The drop-down item of the account's source when no other item is it (a path, an EVM
    /// account, a card key or an imported key not listed now): picking it changes nothing.
    pub const SOURCE_CURRENT: u16 = 8_019;
    /// UTXO source: node.
    pub const INDEXER_NODE: u16 = 8_014;
    /// UTXO source: Blockbook.
    pub const INDEXER_BB: u16 = 8_015;
    /// W-ADDR-3 `주소 전체를 직접 확인했습니다`.
    pub const SEND_ADDR_ACK: u16 = 8_016;
    /// `해시 복사` of the 보내기 card's result line (the txid the node accepted).
    pub const RESULT_COPY: u16 = 8_017;
    /// The account card's `주소 복사` (2026-11-11; the 받기 card keeps [`COPY_ADDRESS`]).
    pub const CARD_COPY: u16 = 8_018;
    /// `해시 복사` of the activity rows (newest first, one id per row).
    pub const ACTIVITY_COPY_BASE: u16 = 8_100;
    /// Activity copy span (every record the journal can hold).
    pub const ACTIVITY_COPY_SPAN: u16 = 80;
    /// Drop-down items of the EVM accounts' keys (position in the EVM account list; their radios
    /// before 2026-11-15).
    pub const SOURCE_EVM_BASE: u16 = 8_020;
    /// EVM item span.
    pub const SOURCE_EVM_SPAN: u16 = yw_engine::wallet::app_zec::ZEC_SOURCE_EVM_ROWS;
    /// Drop-down items of the `YubiKey` Zcash keys (position in the slot list; buttons before
    /// 2026-11-15).
    pub const HW_BASE: u16 = 8_040;
    /// `YubiKey` item span.
    pub const HW_SPAN: u16 = yw_engine::wallet::app_zec::ZEC_HW_ROWS;
    /// `개인키 가져오기` (spec/12 §2.3).
    pub const IMPORT: u16 = 8_050;
    /// `개인키 보기` of the account's imported key.
    pub const REVEAL: u16 = 8_051;
    /// `삭제` of the account's imported key.
    pub const REMOVE: u16 = 8_052;
    /// Drop-down items of the imported keys of the network (position in the list; their
    /// `이 키 사용` before 2026-11-15).
    pub const IMPORTED_BASE: u16 = 8_060;
    /// Imported-key item span (15 keys per chain).
    pub const IMPORTED_SPAN: u16 = 16;

    const _: () = assert!(CARD_COPY < SOURCE_CURRENT);
    const _: () = assert!(SOURCE_CURRENT < SOURCE_EVM_BASE);
    const _: () = assert!(SOURCE_EVM_BASE + SOURCE_EVM_SPAN <= HW_BASE);
    const _: () = assert!(HW_BASE + HW_SPAN <= IMPORT);
    const _: () = assert!(IMPORTED_BASE + IMPORTED_SPAN <= ACTIVITY_COPY_BASE);
    const _: () = assert!(ACTIVITY_COPY_BASE + ACTIVITY_COPY_SPAN <= 8_200);

    /// Every fixed id.
    pub const FIXED: [u16; 23] = [
        CARD_COPY,
        SOURCE_CURRENT,
        TAB_ZEC,
        ENABLE_MAINNET,
        ENABLE_TESTNET,
        DISABLE,
        REFRESH,
        COPY_ADDRESS,
        QR_TOGGLE,
        SEND_TO_EDIT,
        SEND_AMOUNT_EDIT,
        SEND_MAX,
        SEND_REVIEW,
        SOURCE_STANDARD,
        SOURCE_APPLY,
        SOURCE_CANCEL,
        INDEXER_NODE,
        INDEXER_BB,
        SEND_ADDR_ACK,
        RESULT_COPY,
        IMPORT,
        REVEAL,
        REMOVE,
    ];

    /// The press control `id` stands for (2026-11-18, S3 C7: `ui::cmd_table`). `None` when `id`
    /// is not one of this module's presses (the two edits are fields). Each row range is claimed
    /// whole, as the ids reached the handler before.
    #[must_use]
    pub fn press_of(id: u16) -> Option<yw_engine::cmd::ZecPress> {
        use yw_engine::cmd::{Row, ZecPress};
        let within = |base: u16, span: u16| {
            id.checked_sub(base)
                .filter(|offset| *offset < span)
                .map(Row)
        };
        Some(match id {
            TAB_ZEC => ZecPress::TabZec,
            ENABLE_MAINNET => ZecPress::EnableMainnet,
            ENABLE_TESTNET => ZecPress::EnableTestnet,
            DISABLE => ZecPress::Disable,
            REFRESH => ZecPress::Refresh,
            COPY_ADDRESS => ZecPress::CopyAddress,
            CARD_COPY => ZecPress::CardCopy,
            QR_TOGGLE => ZecPress::QrToggle,
            SEND_MAX => ZecPress::SendMax,
            SEND_REVIEW => ZecPress::SendReview,
            SOURCE_STANDARD => ZecPress::SourceStandard,
            SOURCE_APPLY => ZecPress::SourceApply,
            SOURCE_CANCEL => ZecPress::SourceCancel,
            SOURCE_CURRENT => ZecPress::SourceCurrent,
            INDEXER_NODE => ZecPress::IndexerNode,
            INDEXER_BB => ZecPress::IndexerBb,
            SEND_ADDR_ACK => ZecPress::SendAddrAck,
            RESULT_COPY => ZecPress::ResultCopy,
            IMPORT => ZecPress::Import,
            REVEAL => ZecPress::Reveal,
            REMOVE => ZecPress::Remove,
            _ => within(ACTIVITY_COPY_BASE, ACTIVITY_COPY_SPAN)
                .map(ZecPress::ActivityCopy)
                .or_else(|| within(IMPORTED_BASE, IMPORTED_SPAN).map(ZecPress::Imported))
                .or_else(|| within(SOURCE_EVM_BASE, SOURCE_EVM_SPAN).map(ZecPress::SourceEvm))
                .or_else(|| within(HW_BASE, HW_SPAN).map(ZecPress::Hw))?,
        })
    }

    /// The control id of `press` (the inverse of [`press_of`]).
    #[must_use]
    pub const fn id_of(press: yw_engine::cmd::ZecPress) -> u16 {
        use yw_engine::cmd::{Row, ZecPress};
        match press {
            ZecPress::TabZec => TAB_ZEC,
            ZecPress::EnableMainnet => ENABLE_MAINNET,
            ZecPress::EnableTestnet => ENABLE_TESTNET,
            ZecPress::Disable => DISABLE,
            ZecPress::Refresh => REFRESH,
            ZecPress::CopyAddress => COPY_ADDRESS,
            ZecPress::CardCopy => CARD_COPY,
            ZecPress::QrToggle => QR_TOGGLE,
            ZecPress::SendMax => SEND_MAX,
            ZecPress::SendReview => SEND_REVIEW,
            ZecPress::SourceStandard => SOURCE_STANDARD,
            ZecPress::SourceApply => SOURCE_APPLY,
            ZecPress::SourceCancel => SOURCE_CANCEL,
            ZecPress::SourceCurrent => SOURCE_CURRENT,
            ZecPress::IndexerNode => INDEXER_NODE,
            ZecPress::IndexerBb => INDEXER_BB,
            ZecPress::SendAddrAck => SEND_ADDR_ACK,
            ZecPress::ResultCopy => RESULT_COPY,
            ZecPress::Import => IMPORT,
            ZecPress::Reveal => REVEAL,
            ZecPress::Remove => REMOVE,
            ZecPress::ActivityCopy(Row(row)) => ACTIVITY_COPY_BASE.wrapping_add(row),
            ZecPress::Imported(Row(row)) => IMPORTED_BASE.wrapping_add(row),
            ZecPress::SourceEvm(Row(row)) => SOURCE_EVM_BASE.wrapping_add(row),
            ZecPress::Hw(Row(row)) => HW_BASE.wrapping_add(row),
        }
    }
}
