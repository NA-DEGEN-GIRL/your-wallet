//! Screen contents S01–S15 (spec/04 §2) as [`Item`] lists, and the command ids of their
//! controls. Fixed sentences follow spec/04 §2.16; nothing from RPC or the OS is shown.
//!
//! Layout rules (spec/04 §2.0, design system §1.6): one primary button per screen (two on the
//! chain tabs: 보내기 / 받기), sections in cards with a heading, a plain-language help line under
//! technical fields, technical settings behind `고급 설정 보기`, flows with a step indicator.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): the builders, their helpers and texts moved to yw-engine
//! `screen::build::core` (bodies unchanged); this file keeps the control ids of its controls
//! (`ids`) and the tests' receive-gate id list `RECEIVE_IDS`, which only the Windows shell has.

/// Command ids (never 1/2, which `IsDialogMessageW` uses for Enter/Esc).
pub mod ids {
    /// S01 새 지갑 만들기.
    pub const FIRST_CREATE: u16 = 100;
    /// S01 기존 지갑 가져오기.
    pub const FIRST_IMPORT: u16 = 101;
    /// 데이터 폴더 열기.
    pub const OPEN_DATA_FOLDER: u16 = 102;
    /// 로그 폴더 열기.
    pub const OPEN_LOG_FOLDER: u16 = 103;
    /// S02 시작하기.
    pub const CREATE_NEXT: u16 = 110;
    /// S02/S05 취소.
    pub const INTRO_CANCEL: u16 = 111;
    /// S05 시작하기.
    pub const IMPORT_NEXT: u16 = 120;
    /// S06 맞습니다.
    pub const IMPORT_CORRECT: u16 = 130;
    /// S06 다릅니다.
    pub const IMPORT_WRONG: u16 = 131;
    /// S07 잠금 해제.
    pub const UNLOCK: u16 = 140;
    /// S04 복구 단어 보고 백업 확인.
    pub const BACKUP_CHECK: u16 = 150;
    /// 잠금.
    pub const LOCK: u16 = 151;
    /// S08 `RPC 설정 열기` (also `알케미·직접 입력은 설정에서 ▸`, `RPC 설정하기`).
    pub const DONE_RPC: u16 = 160;
    /// S08 `지갑 열기`.
    pub const DONE_CONTINUE: u16 = 161;
    /// S09 이전 사본으로 복구.
    pub const RECOVER: u16 = 170;
    /// S09 종료.
    pub const EXIT: u16 = 172;
    /// T-PASS-MISMATCH 다시 입력.
    pub const MISMATCH_RETRY: u16 = 180;
    /// T-PASS-MISMATCH 이 passphrase로 계속.
    pub const MISMATCH_CONTINUE: u16 = 181;
    /// T-PASS-MISMATCH checkbox.
    pub const MISMATCH_CHECK: u16 = 182;
    /// E-VLT-006 이전 사본 사용.
    pub const SIDECAR_PREV: u16 = 190;
    /// E-VLT-006 격리하고 새로 시작.
    pub const SIDECAR_FRESH: u16 = 191;
    /// 설정.
    pub const OPEN_SETTINGS: u16 = 200;
    /// ← 메인으로.
    pub const BACK_MAIN: u16 = 202;
    /// The send forms' `다른 계정으로 바꾸기 (메인)` link (same action as `BACK_MAIN`; a second
    /// control with the same id on one screen would not be drawn).
    pub const SWITCH_ACCOUNT: u16 = 201;
    /// A `네트워크(RPC) 설정으로` button inside a settings section (same action as the
    /// `SECTION_NETWORK` tab, which is on the same screen).
    pub const GO_NETWORK: u16 = 205;
    /// 알림 닫기.
    pub const DISMISS_BANNERS: u16 = 203;
    /// Settings-file banner: `파일 값 사용` (review M1/L15).
    pub const SETTINGS_ACCEPT_FILE: u16 = 206;
    /// Settings-file banner: `앱에 저장된 값으로 되돌리기`.
    pub const SETTINGS_RESTORE: u16 = 207;
    /// `고급 설정 보기 ▸` / `고급 설정 숨기기 ▾` (and the send form's `수수료 계산 보기`).
    pub const ADVANCED_TOGGLE: u16 = 204;
    /// Network chips base.
    pub const NETWORK_BASE: u16 = 210;
    /// Network chips span.
    pub const NETWORK_SPAN: u16 = 40;
    /// 계정 추가.
    pub const ADD_ACCOUNT: u16 = 260;
    /// 개인키 가져오기.
    pub const IMPORT_KEY: u16 = 261;
    /// Account selection radios (one id per row). Rows ≤ 115 (spec/02 §5.3: 100 derived + 15
    /// imported); the span covers the whole account-index range 0..=999 so no meta can spill
    /// into another range (`ui::command_ids`).
    pub const ACCOUNT_BASE: u16 = 11_000;
    /// Account selection span.
    pub const ACCOUNT_SPAN: u16 = 1_000;
    /// 이름 바꾸기.
    pub const RENAME: u16 = 420;
    /// 숨기기.
    pub const HIDE: u16 = 421;
    /// 개인키 계정 삭제.
    pub const REMOVE_KEY: u16 = 422;
    /// Rename save.
    pub const RENAME_SAVE: u16 = 423;
    /// Rename cancel.
    pub const RENAME_CANCEL: u16 = 424;
    /// Rename edit.
    pub const RENAME_EDIT: u16 = 425;
    /// Settings sections.
    pub const SECTION_SECURITY: u16 = 500;
    /// Settings network section.
    pub const SECTION_NETWORK: u16 = 501;
    /// Settings other section.
    pub const SECTION_OTHER: u16 = 502;
    /// Auto-lock edit.
    pub const AUTOLOCK_EDIT: u16 = 510;
    /// Auto-lock save.
    pub const AUTOLOCK_SAVE: u16 = 511;
    /// Copy toggle.
    pub const COPY_TOGGLE: u16 = 512;
    /// 복구 단어 보기.
    pub const REVEAL_MNEMONIC: u16 = 513;
    /// 개인키 보기.
    pub const REVEAL_KEY: u16 = 514;
    /// 비밀번호 변경.
    pub const CHANGE_PASSWORD: u16 = 515;
    /// `언어 · Language`: 한국어 (spec/04 §2.11, spec/14 §1).
    pub const LANG_KO: u16 = 516;
    /// `언어 · Language`: English.
    pub const LANG_EN: u16 = 517;
    /// Template radios.
    pub const TPL_QUICKNODE: u16 = 520;
    /// Alchemy radio.
    pub const TPL_ALCHEMY: u16 = 521;
    /// Manual radio.
    pub const TPL_MANUAL: u16 = 522;
    /// `QuickNode` endpoint name edit.
    pub const QN_NAME_EDIT: u16 = 523;
    /// `QuickNode` token edit (`ES_PASSWORD`).
    pub const QN_TOKEN_EDIT: u16 = 524;
    /// Alchemy key edit (`ES_PASSWORD`).
    pub const ALCHEMY_KEY_EDIT: u16 = 525;
    /// `자격 정보만 저장`.
    pub const TPL_SAVE: u16 = 526;
    /// Template delete.
    pub const TPL_DELETE: u16 = 527;
    /// `저장하고 RPC 주소 만들기`.
    pub const GENERATE: u16 = 528;
    /// 보관 항목 삭제 (`ApiKeys::prune_dormant`, spec/04 §6.6).
    pub const PRUNE_DORMANT: u16 = 529;
    /// `rpc.json에서 가져오기` (`app_rpc_import`).
    pub const RPC_IMPORT: u16 = 530;
    /// The import confirmation `덮어쓰기` / `가져오기`.
    pub const RPC_IMPORT_OVERWRITE: u16 = 531;
    /// The import confirmation `비어 있는 네트워크만`.
    pub const RPC_IMPORT_FILL: u16 = 532;
    /// The import confirmation `취소`.
    pub const RPC_IMPORT_CANCEL: u16 = 533;
    /// `rpc.json 지우기…` (asks first).
    pub const RPC_JSON_DELETE: u16 = 534;
    /// Its confirmation `지우기`.
    pub const RPC_JSON_DELETE_CONFIRM: u16 = 535;
    /// Its confirmation `취소`.
    pub const RPC_JSON_DELETE_CANCEL: u16 = 536;
    /// URL rows base (3 ids per row: 교체, 테스트, 삭제).
    pub const ROW_BASE: u16 = 540;
    /// URL rows span.
    pub const ROW_SPAN: u16 = 160;
    /// Replace edit (`ES_PASSWORD`).
    pub const REPLACE_EDIT: u16 = 700;
    /// Replace save.
    pub const REPLACE_SAVE: u16 = 701;
    /// Replace cancel.
    pub const REPLACE_CANCEL: u16 = 702;
    /// localhost toggle.
    pub const LOCALHOST_TOGGLE: u16 = 710;
    /// Auto-launch toggle.
    pub const AUTOLAUNCH_TOGGLE: u16 = 711;
    /// Log level radios.
    pub const LOG_ERROR: u16 = 712;
    /// Log level warn.
    pub const LOG_WARN: u16 = 713;
    /// Log level info.
    pub const LOG_INFO: u16 = 714;
    /// Log level debug.
    pub const LOG_DEBUG: u16 = 715;
    /// Overlay confirm.
    pub const CONFIRM_YES: u16 = 800;
    /// Overlay cancel.
    pub const CONFIRM_NO: u16 = 801;
    /// T-RPC-GENERATE `기존 주소 덮어쓰기`.
    pub const OVERWRITE_CHECK: u16 = 802;
    /// S08 '처음 설정' (2026-11-10, block 16,700–16,783): the whole `QuickNode` address
    /// (`ES_PASSWORD`).
    pub const DONE_QN_EDIT: u16 = 16_700;
    /// S08 `연결하기`.
    pub const DONE_CONNECT: u16 = 16_701;
    /// S08 `rpc.json이 있습니다 — 설정에서 가져오기 ▸`.
    pub const DONE_RPC_JSON: u16 = 16_702;
    /// S08 `Ethereum 메인넷으로 보기`.
    pub const DONE_MAINNET: u16 = 16_703;
    /// S08 `WalletConnect` `설정` (S13).
    pub const DONE_WC: u16 = 16_704;
    /// `← 처음 설정으로` (settings and S13 opened from S08).
    pub const BACK_DONE: u16 = 16_705;
    /// Settings → 네트워크(RPC) `모두 테스트`.
    pub const TEST_ALL: u16 = 16_706;
    /// The EVM tab's `RPC 설정하기` (that network's row, its field open).
    pub const EVM_RPC_OPEN: u16 = 16_707;
    /// The Solana tab's `RPC 설정하기`.
    pub const SOL_RPC_OPEN: u16 = 16_708;
    /// The Bitcoin tab's `RPC 설정하기`.
    pub const BTC_RPC_OPEN: u16 = 16_709;
    /// The Zcash tab's `RPC 설정하기`.
    pub const ZEC_RPC_OPEN: u16 = 16_710;
    /// The EVM network card's failure band: `RPC 테스트` (2026-11-10).
    pub const EVM_RPC_TEST: u16 = 16_711;
    /// The Solana network card's failure band: `RPC 테스트`.
    pub const SOL_RPC_TEST: u16 = 16_712;
    /// The EVM failure band's `RPC 설정` (that network's row, `open_rpc_row(_, false)`).
    pub const EVM_RPC_ROW: u16 = 16_713;
    /// The Solana failure band's `RPC 설정`.
    pub const SOL_RPC_ROW: u16 = 16_714;
    /// A failed network's link (S08 result lines, the RPC summary): `RPC_ROW_OPEN_BASE + row`
    /// of [`Wallet::url_networks`](crate::app::Wallet::url_networks) opens that row.
    pub const RPC_ROW_OPEN_BASE: u16 = 16_720;
    /// Span of [`RPC_ROW_OPEN_BASE`].
    pub const RPC_ROW_OPEN_SPAN: u16 = 64;

    /// Every fixed id of this module (`ui::command_ids` checks them against all ranges).
    pub const FIXED: &[u16] = &[
        FIRST_CREATE,
        FIRST_IMPORT,
        OPEN_DATA_FOLDER,
        OPEN_LOG_FOLDER,
        CREATE_NEXT,
        INTRO_CANCEL,
        IMPORT_NEXT,
        IMPORT_CORRECT,
        IMPORT_WRONG,
        UNLOCK,
        BACKUP_CHECK,
        LOCK,
        DONE_RPC,
        DONE_CONTINUE,
        RECOVER,
        EXIT,
        MISMATCH_RETRY,
        MISMATCH_CONTINUE,
        MISMATCH_CHECK,
        SIDECAR_PREV,
        SIDECAR_FRESH,
        OPEN_SETTINGS,
        BACK_MAIN,
        SWITCH_ACCOUNT,
        GO_NETWORK,
        DISMISS_BANNERS,
        SETTINGS_ACCEPT_FILE,
        SETTINGS_RESTORE,
        ADVANCED_TOGGLE,
        ADD_ACCOUNT,
        IMPORT_KEY,
        RENAME,
        HIDE,
        REMOVE_KEY,
        RENAME_SAVE,
        RENAME_CANCEL,
        RENAME_EDIT,
        SECTION_SECURITY,
        SECTION_NETWORK,
        SECTION_OTHER,
        AUTOLOCK_EDIT,
        AUTOLOCK_SAVE,
        COPY_TOGGLE,
        REVEAL_MNEMONIC,
        REVEAL_KEY,
        CHANGE_PASSWORD,
        LANG_KO,
        LANG_EN,
        TPL_QUICKNODE,
        TPL_ALCHEMY,
        TPL_MANUAL,
        QN_NAME_EDIT,
        QN_TOKEN_EDIT,
        ALCHEMY_KEY_EDIT,
        TPL_SAVE,
        TPL_DELETE,
        GENERATE,
        PRUNE_DORMANT,
        RPC_IMPORT,
        RPC_IMPORT_OVERWRITE,
        RPC_IMPORT_FILL,
        RPC_IMPORT_CANCEL,
        RPC_JSON_DELETE,
        RPC_JSON_DELETE_CONFIRM,
        RPC_JSON_DELETE_CANCEL,
        REPLACE_EDIT,
        REPLACE_SAVE,
        REPLACE_CANCEL,
        LOCALHOST_TOGGLE,
        AUTOLAUNCH_TOGGLE,
        LOG_ERROR,
        LOG_WARN,
        LOG_INFO,
        LOG_DEBUG,
        CONFIRM_YES,
        CONFIRM_NO,
        OVERWRITE_CHECK,
        DONE_QN_EDIT,
        DONE_CONNECT,
        DONE_RPC_JSON,
        DONE_MAINNET,
        DONE_WC,
        BACK_DONE,
        TEST_ALL,
        EVM_RPC_OPEN,
        SOL_RPC_OPEN,
        BTC_RPC_OPEN,
        ZEC_RPC_OPEN,
        EVM_RPC_TEST,
        SOL_RPC_TEST,
        EVM_RPC_ROW,
        SOL_RPC_ROW,
    ];

    /// The press control `id` stands for (2026-11-18, S3 C12: `ui::cmd_table`). `None` when
    /// `id` is not one of the core handler's (the `rpc.json` card is `RpcImportPress`, the
    /// edits are fields). The five check boxes carry their state (`controls.checked(id)` now);
    /// each row range is claimed whole, as the ids reached the handler before.
    #[must_use]
    #[expect(clippy::too_many_lines, reason = "one arm per control id")]
    pub fn press_of(
        id: u16,
        controls: &crate::ui::main_window::ControlSet,
    ) -> Option<yw_engine::cmd::CorePress> {
        use yw_core::lang::Lang;
        use yw_engine::cmd::{CorePress, Row, RpcRowAction};
        use yw_engine::logging::LogLevel;
        use yw_engine::settings::RpcTemplate;
        let within = |base: u16, span: u16| id.checked_sub(base).filter(|offset| *offset < span);
        Some(match id {
            FIRST_CREATE => CorePress::FirstCreate,
            FIRST_IMPORT => CorePress::FirstImport,
            OPEN_DATA_FOLDER => CorePress::OpenDataFolder,
            OPEN_LOG_FOLDER => CorePress::OpenLogFolder,
            CREATE_NEXT => CorePress::CreateNext,
            INTRO_CANCEL => CorePress::IntroCancel,
            IMPORT_NEXT => CorePress::ImportNext,
            IMPORT_CORRECT => CorePress::ImportCorrect,
            IMPORT_WRONG => CorePress::ImportWrong,
            UNLOCK => CorePress::Unlock,
            BACKUP_CHECK => CorePress::BackupCheck,
            LOCK => CorePress::Lock,
            DONE_RPC => CorePress::DoneRpc,
            DONE_CONTINUE => CorePress::DoneContinue,
            RECOVER => CorePress::Recover,
            EXIT => CorePress::Exit,
            MISMATCH_RETRY => CorePress::MismatchRetry,
            MISMATCH_CONTINUE => CorePress::MismatchContinue,
            MISMATCH_CHECK => CorePress::MismatchCheck(controls.checked(id)),
            SIDECAR_PREV => CorePress::SidecarPrev,
            SIDECAR_FRESH => CorePress::SidecarFresh,
            OPEN_SETTINGS => CorePress::OpenSettings,
            BACK_MAIN => CorePress::BackMain,
            SWITCH_ACCOUNT => CorePress::SwitchAccount,
            GO_NETWORK => CorePress::GoNetwork,
            DISMISS_BANNERS => CorePress::DismissBanners,
            SETTINGS_ACCEPT_FILE => CorePress::SettingsAcceptFile,
            SETTINGS_RESTORE => CorePress::SettingsRestore,
            ADVANCED_TOGGLE => CorePress::AdvancedToggle,
            ADD_ACCOUNT => CorePress::AddAccount,
            IMPORT_KEY => CorePress::ImportKey,
            RENAME => CorePress::Rename,
            HIDE => CorePress::Hide,
            REMOVE_KEY => CorePress::RemoveKey,
            RENAME_SAVE => CorePress::RenameSave,
            RENAME_CANCEL => CorePress::RenameCancel,
            SECTION_SECURITY => CorePress::SectionSecurity,
            SECTION_NETWORK => CorePress::SectionNetwork,
            SECTION_OTHER => CorePress::SectionOther,
            AUTOLOCK_SAVE => CorePress::AutolockSave,
            COPY_TOGGLE => CorePress::CopyToggle(controls.checked(id)),
            REVEAL_MNEMONIC => CorePress::RevealMnemonic,
            REVEAL_KEY => CorePress::RevealKey,
            CHANGE_PASSWORD => CorePress::ChangePassword,
            LANG_KO => CorePress::Lang(Lang::Ko),
            LANG_EN => CorePress::Lang(Lang::En),
            TPL_QUICKNODE => CorePress::Template(RpcTemplate::QuickNode),
            TPL_ALCHEMY => CorePress::Template(RpcTemplate::Alchemy),
            TPL_MANUAL => CorePress::Template(RpcTemplate::Manual),
            TPL_SAVE => CorePress::TemplateSave,
            TPL_DELETE => CorePress::TemplateDelete,
            GENERATE => CorePress::Generate,
            PRUNE_DORMANT => CorePress::PruneDormant,
            REPLACE_SAVE => CorePress::ReplaceSave,
            REPLACE_CANCEL => CorePress::ReplaceCancel,
            LOCALHOST_TOGGLE => CorePress::LocalhostToggle(controls.checked(id)),
            AUTOLAUNCH_TOGGLE => CorePress::AutolaunchToggle(controls.checked(id)),
            LOG_ERROR => CorePress::LogLevel(LogLevel::Error),
            LOG_WARN => CorePress::LogLevel(LogLevel::Warn),
            LOG_INFO => CorePress::LogLevel(LogLevel::Info),
            LOG_DEBUG => CorePress::LogLevel(LogLevel::Debug),
            CONFIRM_YES => CorePress::ConfirmYes,
            CONFIRM_NO => CorePress::ConfirmNo,
            OVERWRITE_CHECK => CorePress::OverwriteCheck(controls.checked(id)),
            DONE_CONNECT => CorePress::DoneConnect,
            DONE_RPC_JSON => CorePress::DoneRpcJson,
            DONE_MAINNET => CorePress::DoneMainnet,
            DONE_WC => CorePress::DoneWc,
            BACK_DONE => CorePress::BackDone,
            TEST_ALL => CorePress::TestAll,
            EVM_RPC_OPEN => CorePress::EvmRpcOpen,
            SOL_RPC_OPEN => CorePress::SolRpcOpen,
            BTC_RPC_OPEN => CorePress::BtcRpcOpen,
            ZEC_RPC_OPEN => CorePress::ZecRpcOpen,
            EVM_RPC_TEST => CorePress::EvmRpcTest,
            SOL_RPC_TEST => CorePress::SolRpcTest,
            EVM_RPC_ROW => CorePress::EvmRpcRow,
            SOL_RPC_ROW => CorePress::SolRpcRow,
            _ => {
                if let Some(row) = within(NETWORK_BASE, NETWORK_SPAN) {
                    CorePress::Network(Row(row))
                } else if let Some(row) = within(ACCOUNT_BASE, ACCOUNT_SPAN) {
                    CorePress::Account(Row(row))
                } else if let Some(row) = within(RPC_ROW_OPEN_BASE, RPC_ROW_OPEN_SPAN) {
                    CorePress::RpcRowOpen(Row(row))
                } else {
                    let offset = within(ROW_BASE, ROW_SPAN)?;
                    let action = match offset % 3 {
                        0 => RpcRowAction::Replace,
                        1 => RpcRowAction::Test,
                        _ => RpcRowAction::Delete,
                    };
                    CorePress::RpcRow(Row(offset / 3), action)
                }
            }
        })
    }

    /// The control id of `press` (the inverse of [`press_of`]; a check box's state is not part
    /// of it).
    /// A row past its span lands on another control's id (S3 C10–C12 review: listed in
    /// `ui::cmd_table`'s `c10_c12_payloads_round_trip_or_are_undrawn`; a press that arrives as
    /// data must refuse it).
    #[must_use]
    pub const fn id_of(press: yw_engine::cmd::CorePress) -> u16 {
        use yw_core::lang::Lang;
        use yw_engine::cmd::{CorePress, Row, RpcRowAction};
        use yw_engine::logging::LogLevel;
        use yw_engine::settings::RpcTemplate;
        match press {
            CorePress::FirstCreate => FIRST_CREATE,
            CorePress::FirstImport => FIRST_IMPORT,
            CorePress::OpenDataFolder => OPEN_DATA_FOLDER,
            CorePress::OpenLogFolder => OPEN_LOG_FOLDER,
            CorePress::CreateNext => CREATE_NEXT,
            CorePress::IntroCancel => INTRO_CANCEL,
            CorePress::ImportNext => IMPORT_NEXT,
            CorePress::ImportCorrect => IMPORT_CORRECT,
            CorePress::ImportWrong => IMPORT_WRONG,
            CorePress::Unlock => UNLOCK,
            CorePress::BackupCheck => BACKUP_CHECK,
            CorePress::Lock => LOCK,
            CorePress::DoneRpc => DONE_RPC,
            CorePress::DoneContinue => DONE_CONTINUE,
            CorePress::Recover => RECOVER,
            CorePress::Exit => EXIT,
            CorePress::MismatchRetry => MISMATCH_RETRY,
            CorePress::MismatchContinue => MISMATCH_CONTINUE,
            CorePress::MismatchCheck(_) => MISMATCH_CHECK,
            CorePress::SidecarPrev => SIDECAR_PREV,
            CorePress::SidecarFresh => SIDECAR_FRESH,
            CorePress::OpenSettings => OPEN_SETTINGS,
            CorePress::BackMain => BACK_MAIN,
            CorePress::SwitchAccount => SWITCH_ACCOUNT,
            CorePress::GoNetwork => GO_NETWORK,
            CorePress::DismissBanners => DISMISS_BANNERS,
            CorePress::SettingsAcceptFile => SETTINGS_ACCEPT_FILE,
            CorePress::SettingsRestore => SETTINGS_RESTORE,
            CorePress::AdvancedToggle => ADVANCED_TOGGLE,
            CorePress::AddAccount => ADD_ACCOUNT,
            CorePress::ImportKey => IMPORT_KEY,
            CorePress::Rename => RENAME,
            CorePress::Hide => HIDE,
            CorePress::RemoveKey => REMOVE_KEY,
            CorePress::RenameSave => RENAME_SAVE,
            CorePress::RenameCancel => RENAME_CANCEL,
            CorePress::SectionSecurity => SECTION_SECURITY,
            CorePress::SectionNetwork => SECTION_NETWORK,
            CorePress::SectionOther => SECTION_OTHER,
            CorePress::AutolockSave => AUTOLOCK_SAVE,
            CorePress::CopyToggle(_) => COPY_TOGGLE,
            CorePress::RevealMnemonic => REVEAL_MNEMONIC,
            CorePress::RevealKey => REVEAL_KEY,
            CorePress::ChangePassword => CHANGE_PASSWORD,
            CorePress::Lang(Lang::Ko) => LANG_KO,
            CorePress::Lang(Lang::En) => LANG_EN,
            CorePress::Template(RpcTemplate::QuickNode) => TPL_QUICKNODE,
            CorePress::Template(RpcTemplate::Alchemy) => TPL_ALCHEMY,
            CorePress::Template(RpcTemplate::Manual) => TPL_MANUAL,
            CorePress::TemplateSave => TPL_SAVE,
            CorePress::TemplateDelete => TPL_DELETE,
            CorePress::Generate => GENERATE,
            CorePress::PruneDormant => PRUNE_DORMANT,
            CorePress::ReplaceSave => REPLACE_SAVE,
            CorePress::ReplaceCancel => REPLACE_CANCEL,
            CorePress::LocalhostToggle(_) => LOCALHOST_TOGGLE,
            CorePress::AutolaunchToggle(_) => AUTOLAUNCH_TOGGLE,
            CorePress::LogLevel(LogLevel::Error) => LOG_ERROR,
            CorePress::LogLevel(LogLevel::Warn) => LOG_WARN,
            CorePress::LogLevel(LogLevel::Info) => LOG_INFO,
            CorePress::LogLevel(LogLevel::Debug) => LOG_DEBUG,
            CorePress::ConfirmYes => CONFIRM_YES,
            CorePress::ConfirmNo => CONFIRM_NO,
            CorePress::OverwriteCheck(_) => OVERWRITE_CHECK,
            CorePress::DoneConnect => DONE_CONNECT,
            CorePress::DoneRpcJson => DONE_RPC_JSON,
            CorePress::DoneMainnet => DONE_MAINNET,
            CorePress::DoneWc => DONE_WC,
            CorePress::BackDone => BACK_DONE,
            CorePress::TestAll => TEST_ALL,
            CorePress::EvmRpcOpen => EVM_RPC_OPEN,
            CorePress::SolRpcOpen => SOL_RPC_OPEN,
            CorePress::BtcRpcOpen => BTC_RPC_OPEN,
            CorePress::ZecRpcOpen => ZEC_RPC_OPEN,
            CorePress::EvmRpcTest => EVM_RPC_TEST,
            CorePress::SolRpcTest => SOL_RPC_TEST,
            CorePress::EvmRpcRow => EVM_RPC_ROW,
            CorePress::SolRpcRow => SOL_RPC_ROW,
            CorePress::Network(Row(row)) => NETWORK_BASE.wrapping_add(row),
            CorePress::Account(Row(row)) => ACCOUNT_BASE.wrapping_add(row),
            CorePress::RpcRowOpen(Row(row)) => RPC_ROW_OPEN_BASE.wrapping_add(row),
            CorePress::RpcRow(Row(row), action) => ROW_BASE
                .wrapping_add(row.wrapping_mul(3))
                .wrapping_add(match action {
                    RpcRowAction::Replace => 0,
                    RpcRowAction::Test => 1,
                    RpcRowAction::Delete => 2,
                }),
        }
    }
}

/// Every chain's `받기` (S12) command, and every `주소 복사` on S10 (2026-11-11: the account
/// cards' address line and the Zcash 받기 card) — an unverified passphrase's addresses belong
/// to another wallet, so they are not handed out from the main screen either. 2026-11-24 (spec/15
/// §11.4 S5-4): test-only — the screens turn these controls off by press
/// (`yw_engine::screen::model::disable_receive`: `Press::is_receive_gated`, which names the same
/// eight, table test `family_presses_keep_the_gate_and_the_observer`); the census and the tests
/// still send these ids.
#[cfg(test)]
pub const RECEIVE_IDS: [u16; 8] = [
    crate::ui::screens_evm::ids::RECEIVE_OPEN,
    crate::ui::screens_sol::ids::RECEIVE_OPEN,
    crate::ui::screens_btc::ids::RECEIVE_OPEN,
    crate::ui::screens_evm::ids::COPY_ADDRESS,
    crate::ui::screens_sol::ids::COPY_ADDRESS,
    crate::ui::screens_btc::ids::CARD_COPY,
    crate::ui::screens_zec::ids::COPY_ADDRESS,
    crate::ui::screens_zec::ids::CARD_COPY,
];
