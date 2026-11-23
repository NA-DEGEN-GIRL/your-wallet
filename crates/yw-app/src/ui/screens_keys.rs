//! Imported-key screens (spec/04 §2.18): the S01 card "개인키로 시작하기", S18 (chain and address
//! type), S19 (address confirmation), the empty-chain card of a key-only wallet, and the imported
//! key part of the Bitcoin account card (`개인키 가져오기` with its address-type radios, `개인키
//! 보기`·`삭제` of the selected imported account; the accounts themselves are rows of the normal
//! Bitcoin account list with the "[가져온 키]" badge). Fixed sentences are the T-KEY-* rows of
//! spec/04 §2.16.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): the builders, their helpers and texts moved to yw-engine
//! `screen::build::keys` (bodies unchanged); this file keeps the control ids of its controls
//! (`ids`), which only the Windows shell has.

/// Command ids (block 13,000–13,199, `ui::command_ids`).
pub mod ids {
    use yw_core::btc::ScriptType;

    /// S01 개인키로 시작하기.
    pub const FIRST_KEY: u16 = 13_000;
    /// S18 chain radio: EVM.
    pub const START_CHAIN_EVM: u16 = 13_001;
    /// S18 chain radio: Solana.
    pub const START_CHAIN_SOL: u16 = 13_002;
    /// S18 chain radio: Bitcoin.
    pub const START_CHAIN_BTC: u16 = 13_003;
    /// S18 시작하기.
    pub const START_NEXT: u16 = 13_004;
    /// S19 맞습니다.
    pub const START_CORRECT: u16 = 13_005;
    /// S19 다릅니다.
    pub const START_WRONG: u16 = 13_006;
    /// Script-type radios (S18 and the Bitcoin tab), `SCRIPT_BASE + id − 1` for ids 1–4.
    pub const SCRIPT_BASE: u16 = 13_010;
    /// Solana tab 개인키 가져오기.
    pub const SOL_IMPORT: u16 = 13_020;
    /// Bitcoin tab 개인키 가져오기.
    pub const BTC_IMPORT: u16 = 13_021;
    /// Selected imported Solana account: 개인키 보기.
    pub const SOL_REVEAL: u16 = 13_022;
    /// Selected imported Solana account: 삭제.
    pub const SOL_REMOVE: u16 = 13_023;
    /// Selected imported Bitcoin account: 개인키 보기 (WIF).
    pub const BTC_REVEAL: u16 = 13_024;
    /// Selected imported Bitcoin account: 삭제.
    pub const BTC_REMOVE: u16 = 13_025;
    /// Bitcoin tab: `다음 (개인키 입력)` of the opened address-type chooser (W07); also the
    /// primary button of a key-only wallet's empty Bitcoin card.
    pub const BTC_IMPORT_NEXT: u16 = 13_026;
    /// Bitcoin tab: `취소` of the opened address-type chooser.
    pub const BTC_IMPORT_CANCEL: u16 = 13_027;

    /// Every fixed id of this module.
    pub const FIXED: &[u16] = &[
        FIRST_KEY,
        START_CHAIN_EVM,
        START_CHAIN_SOL,
        START_CHAIN_BTC,
        START_NEXT,
        START_CORRECT,
        START_WRONG,
        SCRIPT_BASE,
        SCRIPT_BASE + 1,
        SCRIPT_BASE + 2,
        SCRIPT_BASE + 3,
        SOL_IMPORT,
        BTC_IMPORT,
        SOL_REVEAL,
        SOL_REMOVE,
        BTC_REVEAL,
        BTC_REMOVE,
        BTC_IMPORT_NEXT,
        BTC_IMPORT_CANCEL,
    ];

    /// The radio id of an address type (its stable code 1–4).
    #[must_use]
    pub const fn script_id(script: ScriptType) -> u16 {
        SCRIPT_BASE + script.code() as u16 - 1
    }

    /// The address type of a radio id.
    #[must_use]
    pub fn script_of(id: u16) -> Option<ScriptType> {
        let offset = id.checked_sub(SCRIPT_BASE).filter(|offset| *offset < 4)?;
        ScriptType::from_code(u8::try_from(offset).ok()?.checked_add(1)?)
    }

    /// The press control `id` stands for (2026-11-18, S3 C5: `ui::cmd_table`; an address-type
    /// radio carries its `ScriptType`). `None` when `id` is not one of this module's.
    #[must_use]
    pub fn press_of(id: u16) -> Option<yw_engine::cmd::KeysPress> {
        use yw_engine::cmd::KeysPress;
        if let Some(script) = script_of(id) {
            return Some(KeysPress::Script(script));
        }
        Some(match id {
            FIRST_KEY => KeysPress::FirstKey,
            START_CHAIN_EVM => KeysPress::StartChainEvm,
            START_CHAIN_SOL => KeysPress::StartChainSol,
            START_CHAIN_BTC => KeysPress::StartChainBtc,
            START_NEXT => KeysPress::StartNext,
            START_CORRECT => KeysPress::StartCorrect,
            START_WRONG => KeysPress::StartWrong,
            SOL_IMPORT => KeysPress::SolImport,
            BTC_IMPORT => KeysPress::BtcImport,
            SOL_REVEAL => KeysPress::SolReveal,
            SOL_REMOVE => KeysPress::SolRemove,
            BTC_REVEAL => KeysPress::BtcReveal,
            BTC_REMOVE => KeysPress::BtcRemove,
            BTC_IMPORT_NEXT => KeysPress::BtcImportNext,
            BTC_IMPORT_CANCEL => KeysPress::BtcImportCancel,
            _ => return None,
        })
    }

    /// The control id of `press` (the inverse of [`press_of`]).
    #[must_use]
    pub const fn id_of(press: yw_engine::cmd::KeysPress) -> u16 {
        use yw_engine::cmd::KeysPress;
        match press {
            KeysPress::FirstKey => FIRST_KEY,
            KeysPress::StartChainEvm => START_CHAIN_EVM,
            KeysPress::StartChainSol => START_CHAIN_SOL,
            KeysPress::StartChainBtc => START_CHAIN_BTC,
            KeysPress::StartNext => START_NEXT,
            KeysPress::StartCorrect => START_CORRECT,
            KeysPress::StartWrong => START_WRONG,
            KeysPress::Script(script) => script_id(script),
            KeysPress::SolImport => SOL_IMPORT,
            KeysPress::BtcImport => BTC_IMPORT,
            KeysPress::SolReveal => SOL_REVEAL,
            KeysPress::SolRemove => SOL_REMOVE,
            KeysPress::BtcReveal => BTC_REVEAL,
            KeysPress::BtcRemove => BTC_REMOVE,
            KeysPress::BtcImportNext => BTC_IMPORT_NEXT,
            KeysPress::BtcImportCancel => BTC_IMPORT_CANCEL,
        }
    }
}
