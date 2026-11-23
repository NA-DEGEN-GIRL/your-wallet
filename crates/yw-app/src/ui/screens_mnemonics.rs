//! The recovery-phrase screens (spec/04 §2.24): the settings section "복구 단어" (one card per
//! mnemonic with its label, words, backup state and actions; the address preview of
//! "복구 단어 추가 가져오기"; the removal warning) and the "계정 추가" mnemonic picker row.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): the builders, their helpers and texts moved to yw-engine
//! `screen::build::mnemonics` (bodies unchanged); this file keeps the control ids of its controls
//! (`ids`), which only the Windows shell has.

/// Command ids (block 13,600–13,699, `ui::command_ids`).
pub mod ids {
    /// Settings tab "복구 단어".
    pub const SECTION_MNEMONICS: u16 = 13_600;
    /// 복구 단어 추가 가져오기.
    pub const IMPORT: u16 = 13_601;
    /// 새 복구 단어 만들기 (추가).
    pub const CREATE: u16 = 13_602;
    /// Address preview: 가져오기.
    pub const PREVIEW_CONFIRM: u16 = 13_603;
    /// Address preview: 취소.
    pub const PREVIEW_CANCEL: u16 = 13_604;
    /// Label edit: 저장.
    pub const RENAME_SAVE: u16 = 13_605;
    /// Label edit: 취소.
    pub const RENAME_CANCEL: u16 = 13_606;
    /// Label edit field.
    pub const RENAME_EDIT: u16 = 13_607;
    /// Removal warning: 지우기.
    pub const REMOVE_CONFIRM: u16 = 13_608;
    /// Removal warning: 취소.
    pub const REMOVE_CANCEL: u16 = 13_609;
    /// "계정 추가" picker: 취소.
    pub const PICK_CANCEL: u16 = 13_610;
    /// Address preview: the T-YK-SAME checkbox (the words of an enrolled `YubiKey`).
    pub const PREVIEW_SAME_ACK: u16 = 13_613;
    /// Removal warning of an unconfirmed phrase: 단어 보기.
    pub const REMOVE_REVEAL: u16 = 13_614;
    /// Removal warning of an unconfirmed phrase: the typed `백업 없이 지우기`.
    pub const REMOVE_TYPED_EDIT: u16 = 13_615;
    /// Main account card: 복구 단어 관리.
    pub const MAIN_LINK: u16 = 13_611;
    /// Rows per indexed range (`MAX_MNEMONICS`).
    pub const ROW_SPAN: u16 = 8;
    /// Mnemonic card: 이름 바꾸기 (`+ row`).
    pub const RENAME_BASE: u16 = 13_620;
    /// Mnemonic card: 단어 보기.
    pub const REVEAL_BASE: u16 = 13_630;
    /// Mnemonic card: 백업 확인.
    pub const BACKUP_BASE: u16 = 13_640;
    /// Mnemonic card: 지우기.
    pub const REMOVE_BASE: u16 = 13_650;
    /// "계정 추가" picker: one button per mnemonic.
    pub const PICK_BASE: u16 = 13_660;
    /// Solana "계정 추가" picker: one button per mnemonic.
    pub const SOL_PICK_BASE: u16 = 13_670;
    /// Bitcoin "계정 추가" key source: one radio per mnemonic.
    pub const BTC_PICK_BASE: u16 = 13_680;
    /// Zcash key source: `{니모닉 N} 표준 경로 사용`, one button per mnemonic.
    pub const ZEC_PICK_BASE: u16 = 13_690;
    /// Solana "계정 추가" picker: 취소.
    pub const SOL_PICK_CANCEL: u16 = 13_612;

    /// Every fixed id of this module.
    pub const FIXED: &[u16] = &[
        SECTION_MNEMONICS,
        IMPORT,
        CREATE,
        PREVIEW_CONFIRM,
        PREVIEW_CANCEL,
        RENAME_SAVE,
        RENAME_CANCEL,
        RENAME_EDIT,
        REMOVE_CONFIRM,
        REMOVE_CANCEL,
        PICK_CANCEL,
        MAIN_LINK,
        SOL_PICK_CANCEL,
        PREVIEW_SAME_ACK,
        REMOVE_REVEAL,
        REMOVE_TYPED_EDIT,
    ];

    /// The press control `id` stands for (2026-11-18, S3 C6: `ui::cmd_table`). `None` when `id`
    /// is not one of this module's presses (the two edits are fields). Each row range is
    /// claimed whole ([`ROW_SPAN`] rows), as the ids reached the handler before.
    #[must_use]
    pub fn press_of(id: u16) -> Option<yw_engine::cmd::MnPress> {
        use yw_engine::cmd::{MnPress, Row};
        let within = |base: u16| id.checked_sub(base).filter(|row| *row < ROW_SPAN).map(Row);
        Some(match id {
            SECTION_MNEMONICS => MnPress::SectionMnemonics,
            MAIN_LINK => MnPress::MainLink,
            IMPORT => MnPress::Import,
            CREATE => MnPress::Create,
            PREVIEW_CONFIRM => MnPress::PreviewConfirm,
            PREVIEW_CANCEL => MnPress::PreviewCancel,
            PREVIEW_SAME_ACK => MnPress::PreviewSameAck,
            RENAME_SAVE => MnPress::RenameSave,
            RENAME_CANCEL => MnPress::RenameCancel,
            REMOVE_CONFIRM => MnPress::RemoveConfirm,
            REMOVE_REVEAL => MnPress::RemoveReveal,
            REMOVE_CANCEL => MnPress::RemoveCancel,
            PICK_CANCEL => MnPress::PickCancel,
            SOL_PICK_CANCEL => MnPress::SolPickCancel,
            _ => within(RENAME_BASE)
                .map(MnPress::Rename)
                .or_else(|| within(REVEAL_BASE).map(MnPress::Reveal))
                .or_else(|| within(BACKUP_BASE).map(MnPress::Backup))
                .or_else(|| within(REMOVE_BASE).map(MnPress::Remove))
                .or_else(|| within(PICK_BASE).map(MnPress::Pick))
                .or_else(|| within(SOL_PICK_BASE).map(MnPress::SolPick))
                .or_else(|| within(BTC_PICK_BASE).map(MnPress::BtcPick))
                .or_else(|| within(ZEC_PICK_BASE).map(MnPress::ZecPick))?,
        })
    }

    /// The control id of `press` (the inverse of [`press_of`]).
    #[must_use]
    pub const fn id_of(press: yw_engine::cmd::MnPress) -> u16 {
        use yw_engine::cmd::{MnPress, Row};
        match press {
            MnPress::SectionMnemonics => SECTION_MNEMONICS,
            MnPress::MainLink => MAIN_LINK,
            MnPress::Import => IMPORT,
            MnPress::Create => CREATE,
            MnPress::PreviewConfirm => PREVIEW_CONFIRM,
            MnPress::PreviewCancel => PREVIEW_CANCEL,
            MnPress::PreviewSameAck => PREVIEW_SAME_ACK,
            MnPress::RenameSave => RENAME_SAVE,
            MnPress::RenameCancel => RENAME_CANCEL,
            MnPress::RemoveConfirm => REMOVE_CONFIRM,
            MnPress::RemoveReveal => REMOVE_REVEAL,
            MnPress::RemoveCancel => REMOVE_CANCEL,
            MnPress::PickCancel => PICK_CANCEL,
            MnPress::SolPickCancel => SOL_PICK_CANCEL,
            MnPress::Rename(Row(row)) => RENAME_BASE.wrapping_add(row),
            MnPress::Reveal(Row(row)) => REVEAL_BASE.wrapping_add(row),
            MnPress::Backup(Row(row)) => BACKUP_BASE.wrapping_add(row),
            MnPress::Remove(Row(row)) => REMOVE_BASE.wrapping_add(row),
            MnPress::Pick(Row(row)) => PICK_BASE.wrapping_add(row),
            MnPress::SolPick(Row(row)) => SOL_PICK_BASE.wrapping_add(row),
            MnPress::BtcPick(Row(row)) => BTC_PICK_BASE.wrapping_add(row),
            MnPress::ZecPick(Row(row)) => ZEC_PICK_BASE.wrapping_add(row),
        }
    }
}
