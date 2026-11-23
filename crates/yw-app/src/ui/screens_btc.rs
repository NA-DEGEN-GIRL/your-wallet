//! Bitcoin screen contents (M8; spec/04 §2.6–§2.8, §2.11, §2.16, §3.3; spec/08 §2, §3.2, §3.4,
//! §4.7, §7.3, §7.6, §8.2–§8.3, §9, §11.3, §12.1–§12.2): the S10 Bitcoin tab, the BTC send form
//! and its result, the fee-bump form, S12 receive and the S15 Bitcoin section. Every text is a
//! fixed sentence or built by yw-core / the controller ([`yw_engine::wallet::app_btc`]); no
//! server string is shown. Addresses are shown in full in 4-character groups, the first and last
//! 6 characters bold (spec/04 §3.3); activity addresses have no copy or select buttons.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): the builders, their helpers and texts moved to yw-engine
//! `screen::build::btc` (bodies unchanged); this file keeps the control ids of its controls (`ids`)
//! and the tests that need an `App`, which only the Windows shell has.

/// Command ids of the Bitcoin screens (9000–9899; the whole map is `ui::command_ids`).
pub mod ids {
    /// Tab `Bitcoin`.
    pub const TAB_BTC: u16 = 9_000;
    /// Settings section `Bitcoin` (also `Bitcoin 설정` on the disabled tab).
    pub const SECTION_BTC: u16 = 9_001;
    /// 새로고침.
    pub const REFRESH: u16 = 9_002;
    /// 보내기.
    pub const SEND_OPEN: u16 = 9_003;
    /// 받기.
    pub const RECEIVE_OPEN: u16 = 9_004;
    /// 수수료 올리기 (the current bump target).
    pub const BUMP_OPEN: u16 = 9_005;
    /// Discovery [다시 시도].
    pub const DISCOVER_RETRY: u16 = 9_006;
    /// 더 찾기.
    pub const DISCOVER_MORE: u16 = 9_007;
    /// Discovery 취소.
    pub const DISCOVER_CANCEL: u16 = 9_008;
    /// [설정을 {`BtcMeta` 값}으로 되돌리기].
    pub const MISMATCH_KEEP_META: u16 = 9_009;
    /// [{settings 값}으로 바꾸기].
    pub const MISMATCH_USE_SETTINGS: u16 = 9_010;
    /// [블록 높이 기록 초기화] (shown while blocked by a tip regression).
    pub const RESET_TIP: u16 = 9_011;
    /// Send: recipient edit.
    pub const SEND_TO_EDIT: u16 = 9_020;
    /// Send: amount edit.
    pub const SEND_AMOUNT_EDIT: u16 = 9_021;
    /// Send: unit `BTC`.
    pub const UNIT_BTC: u16 = 9_022;
    /// Send: unit `sats`.
    pub const UNIT_SATS: u16 = 9_023;
    /// Send: `보내기 최대`.
    pub const SEND_MAX: u16 = 9_024;
    /// Send fee `빠름`.
    pub const FEE_FAST: u16 = 9_025;
    /// Send fee `보통`.
    pub const FEE_NORMAL: u16 = 9_026;
    /// Send fee `느림`.
    pub const FEE_SLOW: u16 = 9_027;
    /// Send fee `직접 입력`.
    pub const FEE_MANUAL: u16 = 9_028;
    /// Send: manual sat/vB edit.
    pub const FEE_MANUAL_EDIT: u16 = 9_029;
    /// Send: typed fee (sats) edit, shown only when the cap needs it.
    pub const TYPED_FEE_EDIT: u16 = 9_030;
    /// Send `검토`.
    pub const SEND_REVIEW: u16 = 9_031;
    /// Send `취소`.
    pub const SEND_CANCEL: u16 = 9_032;
    /// Send: `주소 전체를 직접 확인했습니다` (W-ADDR-3).
    pub const SEND_ADDR_ACK: u16 = 9_033;
    /// Result `해시 복사`.
    pub const RESULT_COPY: u16 = 9_040;
    /// Result [다시 시도] (pre-check communication failure).
    pub const RESULT_RETRY: u16 = 9_041;
    /// Result `보내기 화면으로` (pre-check rejection; inputs kept).
    pub const RESULT_TO_SEND: u16 = 9_042;
    /// Bump fee `빠름`.
    pub const BUMP_FEE_FAST: u16 = 9_050;
    /// Bump fee `보통`.
    pub const BUMP_FEE_NORMAL: u16 = 9_051;
    /// Bump fee `느림`.
    pub const BUMP_FEE_SLOW: u16 = 9_052;
    /// Bump fee `직접 입력`.
    pub const BUMP_FEE_MANUAL: u16 = 9_053;
    /// Bump: manual sat/vB edit.
    pub const BUMP_MANUAL_EDIT: u16 = 9_054;
    /// Bump: typed fee (sats) edit.
    pub const BUMP_TYPED_EDIT: u16 = 9_055;
    /// Bump `검토`.
    pub const BUMP_REVIEW: u16 = 9_056;
    /// Bump `취소`.
    pub const BUMP_CANCEL: u16 = 9_057;
    /// Receive `주소 복사`.
    pub const COPY_ADDRESS: u16 = 9_060;
    /// Receive `새 주소`.
    pub const NEW_ADDRESS: u16 = 9_061;
    /// Settings `Bitcoin 사용` check (켜기 / 끄기).
    pub const ENABLE: u16 = 9_100;
    /// Settings network `mainnet`.
    pub const SET_MAINNET: u16 = 9_101;
    /// Settings network `testnet4`.
    pub const SET_TESTNET4: u16 = 9_102;
    /// Settings indexer `Esplora`.
    pub const IDX_ESPLORA: u16 = 9_103;
    /// Settings indexer `bb-rpc`.
    pub const IDX_BB_RPC: u16 = 9_104;
    /// Settings indexer `bb-rest`.
    pub const IDX_BB_REST: u16 = 9_105;
    /// Esplora URL mainnet: edit.
    pub const ESPLORA_MAINNET_EDIT: u16 = 9_110;
    /// Esplora URL mainnet: `저장`.
    pub const ESPLORA_MAINNET_SAVE: u16 = 9_111;
    /// Esplora URL mainnet: `기본값으로`.
    pub const ESPLORA_MAINNET_DEFAULT: u16 = 9_112;
    /// Esplora URL mainnet: `테스트`.
    pub const ESPLORA_MAINNET_TEST: u16 = 9_113;
    /// Esplora URL testnet4: edit.
    pub const ESPLORA_TESTNET4_EDIT: u16 = 9_120;
    /// Esplora URL testnet4: `저장`.
    pub const ESPLORA_TESTNET4_SAVE: u16 = 9_121;
    /// Esplora URL testnet4: `기본값으로`.
    pub const ESPLORA_TESTNET4_DEFAULT: u16 = 9_122;
    /// Esplora URL testnet4: `테스트`.
    pub const ESPLORA_TESTNET4_TEST: u16 = 9_123;
    /// UTXO rows (`동결` / `해제`, one id per row).
    pub const UTXO_BASE: u16 = 9_200;
    /// UTXO rows shown (and id span).
    pub const UTXO_SPAN: u16 = 300;
    /// Activity rows ([`ACTIVITY_STRIDE`] ids per row: 해시 복사, 수수료 올리기, 같은 바이트 다시
    /// 전송, 포기, Esplora로 전송, 전송 계속 / 다시 시도, 취소).
    pub const ACTIVITY_BASE: u16 = 9_500;
    /// Ids per activity row.
    pub const ACTIVITY_STRIDE: u16 = 8;
    /// Activity id span (`BTC_MAX_ACTIVITY_ROWS` × stride).
    pub const ACTIVITY_SPAN: u16 = 400;
    /// Activity offset: 해시 복사.
    pub const ACT_COPY: u16 = 0;
    /// Activity offset: 수수료 올리기.
    pub const ACT_BUMP: u16 = 1;
    /// Activity offset: 같은 바이트 다시 전송.
    pub const ACT_REBROADCAST: u16 = 2;
    /// Activity offset: 포기.
    pub const ACT_ABANDON: u16 = 3;
    /// Activity offset: Esplora로 전송.
    pub const ACT_ESPLORA: u16 = 4;
    /// Activity offset: 전송 계속 / 다시 시도.
    pub const ACT_CONTINUE: u16 = 5;
    /// Activity offset: 취소 (a `Signed` record).
    pub const ACT_CANCEL: u16 = 6;
    /// Activity offset: 이 주소 저장 (address book).
    pub const ACT_SAVE: u16 = 7;
    /// `계정 추가` (opens the address-type chooser).
    pub const ACCOUNT_ADD: u16 = 9_012;
    /// The chooser's `취소`.
    pub const ACCOUNT_ADD_CANCEL: u16 = 9_013;
    /// The chooser's four address types, in `ScriptType::CHOICES` order (9,014–9,017).
    pub const ACCOUNT_ADD_TYPE: u16 = 9_014;
    /// The chooser's key source `BTC 표준 경로 (권장, 기본값)`.
    pub const ACCOUNT_SOURCE_STANDARD: u16 = 9_018;
    /// The chooser's key source `EVM 계정과 같은 키`.
    pub const ACCOUNT_SOURCE_EVM: u16 = 9_019;
    /// The selected account card's `주소 복사` (2026-11-11): the address that card shows
    /// (`Wallet::btc_card_address`), not the receive screen's.
    pub const CARD_COPY: u16 = 9_034;
    /// Address mode of the selected HD account: `고정 주소 하나만 사용`.
    pub const ADDRESS_MODE_SINGLE: u16 = 9_062;
    /// Address mode of the selected HD account: `받을 때마다 새 주소`.
    pub const ADDRESS_MODE_HD: u16 = 9_063;
    /// The chooser's EVM account radios: `EVM_ACCOUNT_BASE + row` (rows of meta `evm_accounts`).
    pub const EVM_ACCOUNT_BASE: u16 = 9_064;
    /// EVM account rows shown in the chooser (and id span, 9,064–9,095).
    pub const EVM_ACCOUNT_SPAN: u16 = 32;
    /// The selected account's `이름 바꾸기` (2026-11-15).
    pub const RENAME: u16 = 9_035;
    /// The selected account's `숨기기` (2026-11-15).
    pub const HIDE: u16 = 9_036;
    /// The name field of `이름 바꾸기`.
    pub const RENAME_EDIT: u16 = 9_037;
    /// Its `저장` (Enter).
    pub const RENAME_SAVE: u16 = 9_038;
    /// Its `취소` (Esc).
    pub const RENAME_CANCEL: u16 = 9_039;
    /// Account rows: `ACCOUNT_BASE + row` selects that account.
    pub const ACCOUNT_BASE: u16 = 9_130;
    /// Most account rows with a button (1 + `MAX_BTC_ACCOUNTS`).
    pub const ACCOUNT_SPAN: u16 = 65;

    const _: () = assert!(ACT_SAVE < ACTIVITY_STRIDE);
    const _: () = assert!(NEW_ADDRESS < ADDRESS_MODE_SINGLE);
    const _: () = assert!(EVM_ACCOUNT_BASE + EVM_ACCOUNT_SPAN <= ENABLE);
    const _: () = assert!(ACCOUNT_ADD_TYPE + 4 <= ESPLORA_MAINNET_EDIT);
    const _: () = assert!(ESPLORA_TESTNET4_TEST < ACCOUNT_BASE);
    const _: () = assert!(ACCOUNT_BASE + ACCOUNT_SPAN <= UTXO_BASE);
    const _: () = assert!(UTXO_BASE + UTXO_SPAN <= ACTIVITY_BASE);
    const _: () = assert!(ACTIVITY_BASE + ACTIVITY_SPAN <= 10_000);

    /// Every fixed id (tests check uniqueness and the range).
    pub const FIXED: [u16; 69] = [
        CARD_COPY,
        RENAME,
        HIDE,
        RENAME_EDIT,
        RENAME_SAVE,
        RENAME_CANCEL,
        ACCOUNT_SOURCE_STANDARD,
        ACCOUNT_SOURCE_EVM,
        ADDRESS_MODE_SINGLE,
        ADDRESS_MODE_HD,
        TAB_BTC,
        SECTION_BTC,
        REFRESH,
        SEND_OPEN,
        RECEIVE_OPEN,
        BUMP_OPEN,
        DISCOVER_RETRY,
        DISCOVER_MORE,
        DISCOVER_CANCEL,
        MISMATCH_KEEP_META,
        MISMATCH_USE_SETTINGS,
        RESET_TIP,
        ACCOUNT_ADD,
        ACCOUNT_ADD_CANCEL,
        ACCOUNT_ADD_TYPE,
        ACCOUNT_ADD_TYPE + 1,
        ACCOUNT_ADD_TYPE + 2,
        ACCOUNT_ADD_TYPE + 3,
        SEND_TO_EDIT,
        SEND_AMOUNT_EDIT,
        UNIT_BTC,
        UNIT_SATS,
        SEND_MAX,
        FEE_FAST,
        FEE_NORMAL,
        FEE_SLOW,
        FEE_MANUAL,
        FEE_MANUAL_EDIT,
        TYPED_FEE_EDIT,
        SEND_REVIEW,
        SEND_CANCEL,
        SEND_ADDR_ACK,
        RESULT_COPY,
        RESULT_RETRY,
        RESULT_TO_SEND,
        BUMP_FEE_FAST,
        BUMP_FEE_NORMAL,
        BUMP_FEE_SLOW,
        BUMP_FEE_MANUAL,
        BUMP_MANUAL_EDIT,
        BUMP_TYPED_EDIT,
        BUMP_REVIEW,
        BUMP_CANCEL,
        COPY_ADDRESS,
        NEW_ADDRESS,
        ENABLE,
        SET_MAINNET,
        SET_TESTNET4,
        IDX_ESPLORA,
        IDX_BB_RPC,
        IDX_BB_REST,
        ESPLORA_MAINNET_EDIT,
        ESPLORA_MAINNET_SAVE,
        ESPLORA_MAINNET_DEFAULT,
        ESPLORA_MAINNET_TEST,
        ESPLORA_TESTNET4_EDIT,
        ESPLORA_TESTNET4_SAVE,
        ESPLORA_TESTNET4_DEFAULT,
        ESPLORA_TESTNET4_TEST,
    ];

    /// The press control `id` stands for (2026-11-18, S3 C9: `ui::cmd_table`). `None` when `id`
    /// is not one of this module's presses (the nine edits are fields). An address-type radio
    /// carries its `ScriptType` (`ScriptType::CHOICES` order), an Esplora row button its
    /// network; each row range is claimed whole, as the ids reached the handler before.
    #[must_use]
    pub fn press_of(id: u16) -> Option<yw_engine::cmd::BtcPress> {
        use yw_core::btc::{BtcNetwork, ScriptType};
        use yw_engine::cmd::{BtcActivityAction, BtcPress, Row};
        let within = |base: u16, span: u16| id.checked_sub(base).filter(|offset| *offset < span);
        for net in BtcNetwork::ALL {
            let (_, save, default, test) = esplora_ids(net);
            if id == save {
                return Some(BtcPress::EsploraSave(net));
            }
            if id == default {
                return Some(BtcPress::EsploraDefault(net));
            }
            if id == test {
                return Some(BtcPress::EsploraTest(net));
            }
        }
        if let Some(choice) = within(ACCOUNT_ADD_TYPE, 4) {
            return ScriptType::CHOICES
                .get(usize::from(choice))
                .map(|script| BtcPress::AccountAddType(*script));
        }
        Some(match id {
            TAB_BTC => BtcPress::TabBtc,
            SECTION_BTC => BtcPress::SectionBtc,
            REFRESH => BtcPress::Refresh,
            SEND_OPEN => BtcPress::SendOpen,
            RECEIVE_OPEN => BtcPress::ReceiveOpen,
            BUMP_OPEN => BtcPress::BumpOpen,
            DISCOVER_RETRY => BtcPress::DiscoverRetry,
            DISCOVER_MORE => BtcPress::DiscoverMore,
            DISCOVER_CANCEL => BtcPress::DiscoverCancel,
            MISMATCH_KEEP_META => BtcPress::MismatchKeepMeta,
            MISMATCH_USE_SETTINGS => BtcPress::MismatchUseSettings,
            RESET_TIP => BtcPress::ResetTip,
            RENAME => BtcPress::Rename,
            RENAME_SAVE => BtcPress::RenameSave,
            RENAME_CANCEL => BtcPress::RenameCancel,
            HIDE => BtcPress::Hide,
            ACCOUNT_ADD => BtcPress::AccountAdd,
            ACCOUNT_ADD_CANCEL => BtcPress::AccountAddCancel,
            ACCOUNT_SOURCE_STANDARD => BtcPress::AccountSourceStandard,
            ACCOUNT_SOURCE_EVM => BtcPress::AccountSourceEvm,
            ADDRESS_MODE_SINGLE => BtcPress::AddressModeSingle,
            ADDRESS_MODE_HD => BtcPress::AddressModeHd,
            SEND_ADDR_ACK => BtcPress::SendAddrAck,
            UNIT_BTC => BtcPress::UnitBtc,
            UNIT_SATS => BtcPress::UnitSats,
            SEND_MAX => BtcPress::SendMax,
            FEE_FAST => BtcPress::FeeFast,
            FEE_NORMAL => BtcPress::FeeNormal,
            FEE_SLOW => BtcPress::FeeSlow,
            FEE_MANUAL => BtcPress::FeeManual,
            SEND_REVIEW => BtcPress::SendReview,
            SEND_CANCEL => BtcPress::SendCancel,
            RESULT_COPY => BtcPress::ResultCopy,
            RESULT_RETRY => BtcPress::ResultRetry,
            RESULT_TO_SEND => BtcPress::ResultToSend,
            BUMP_FEE_FAST => BtcPress::BumpFeeFast,
            BUMP_FEE_NORMAL => BtcPress::BumpFeeNormal,
            BUMP_FEE_SLOW => BtcPress::BumpFeeSlow,
            BUMP_FEE_MANUAL => BtcPress::BumpFeeManual,
            BUMP_REVIEW => BtcPress::BumpReview,
            BUMP_CANCEL => BtcPress::BumpCancel,
            COPY_ADDRESS => BtcPress::CopyAddress,
            CARD_COPY => BtcPress::CardCopy,
            NEW_ADDRESS => BtcPress::NewAddress,
            ENABLE => BtcPress::Enable,
            SET_MAINNET => BtcPress::SetMainnet,
            SET_TESTNET4 => BtcPress::SetTestnet4,
            IDX_ESPLORA => BtcPress::IdxEsplora,
            IDX_BB_RPC => BtcPress::IdxBbRpc,
            IDX_BB_REST => BtcPress::IdxBbRest,
            _ => {
                if let Some(row) = within(EVM_ACCOUNT_BASE, EVM_ACCOUNT_SPAN) {
                    BtcPress::EvmAccount(Row(row))
                } else if let Some(row) = within(ACCOUNT_BASE, ACCOUNT_SPAN) {
                    BtcPress::Account(Row(row))
                } else if let Some(row) = within(UTXO_BASE, UTXO_SPAN) {
                    BtcPress::Utxo(Row(row))
                } else {
                    let position = within(ACTIVITY_BASE, ACTIVITY_SPAN)?;
                    let action = match position % ACTIVITY_STRIDE {
                        ACT_COPY => BtcActivityAction::CopyHash,
                        ACT_BUMP => BtcActivityAction::Bump,
                        ACT_REBROADCAST => BtcActivityAction::Rebroadcast,
                        ACT_ABANDON => BtcActivityAction::Abandon,
                        ACT_ESPLORA => BtcActivityAction::Esplora,
                        ACT_CONTINUE => BtcActivityAction::Continue,
                        ACT_CANCEL => BtcActivityAction::Cancel,
                        _ => BtcActivityAction::SaveAddress,
                    };
                    BtcPress::Activity(Row(position / ACTIVITY_STRIDE), action)
                }
            }
        })
    }

    /// The control id of `press` (the inverse of [`press_of`]).
    #[must_use]
    pub const fn id_of(press: yw_engine::cmd::BtcPress) -> u16 {
        use yw_core::btc::ScriptType;
        use yw_engine::cmd::{BtcActivityAction, BtcPress, Row};
        match press {
            BtcPress::TabBtc => TAB_BTC,
            BtcPress::SectionBtc => SECTION_BTC,
            BtcPress::Refresh => REFRESH,
            BtcPress::SendOpen => SEND_OPEN,
            BtcPress::ReceiveOpen => RECEIVE_OPEN,
            BtcPress::BumpOpen => BUMP_OPEN,
            BtcPress::DiscoverRetry => DISCOVER_RETRY,
            BtcPress::DiscoverMore => DISCOVER_MORE,
            BtcPress::DiscoverCancel => DISCOVER_CANCEL,
            BtcPress::MismatchKeepMeta => MISMATCH_KEEP_META,
            BtcPress::MismatchUseSettings => MISMATCH_USE_SETTINGS,
            BtcPress::ResetTip => RESET_TIP,
            BtcPress::Rename => RENAME,
            BtcPress::RenameSave => RENAME_SAVE,
            BtcPress::RenameCancel => RENAME_CANCEL,
            BtcPress::Hide => HIDE,
            BtcPress::AccountAdd => ACCOUNT_ADD,
            BtcPress::AccountAddCancel => ACCOUNT_ADD_CANCEL,
            // `ScriptType::CHOICES` order.
            BtcPress::AccountAddType(script) => ACCOUNT_ADD_TYPE.wrapping_add(match script {
                ScriptType::P2wpkh => 0,
                ScriptType::P2tr => 1,
                ScriptType::P2shP2wpkh => 2,
                ScriptType::P2pkh => 3,
            }),
            BtcPress::AccountSourceStandard => ACCOUNT_SOURCE_STANDARD,
            BtcPress::AccountSourceEvm => ACCOUNT_SOURCE_EVM,
            BtcPress::AddressModeSingle => ADDRESS_MODE_SINGLE,
            BtcPress::AddressModeHd => ADDRESS_MODE_HD,
            BtcPress::SendAddrAck => SEND_ADDR_ACK,
            BtcPress::UnitBtc => UNIT_BTC,
            BtcPress::UnitSats => UNIT_SATS,
            BtcPress::SendMax => SEND_MAX,
            BtcPress::FeeFast => FEE_FAST,
            BtcPress::FeeNormal => FEE_NORMAL,
            BtcPress::FeeSlow => FEE_SLOW,
            BtcPress::FeeManual => FEE_MANUAL,
            BtcPress::SendReview => SEND_REVIEW,
            BtcPress::SendCancel => SEND_CANCEL,
            BtcPress::ResultCopy => RESULT_COPY,
            BtcPress::ResultRetry => RESULT_RETRY,
            BtcPress::ResultToSend => RESULT_TO_SEND,
            BtcPress::BumpFeeFast => BUMP_FEE_FAST,
            BtcPress::BumpFeeNormal => BUMP_FEE_NORMAL,
            BtcPress::BumpFeeSlow => BUMP_FEE_SLOW,
            BtcPress::BumpFeeManual => BUMP_FEE_MANUAL,
            BtcPress::BumpReview => BUMP_REVIEW,
            BtcPress::BumpCancel => BUMP_CANCEL,
            BtcPress::CopyAddress => COPY_ADDRESS,
            BtcPress::CardCopy => CARD_COPY,
            BtcPress::NewAddress => NEW_ADDRESS,
            BtcPress::Enable => ENABLE,
            BtcPress::SetMainnet => SET_MAINNET,
            BtcPress::SetTestnet4 => SET_TESTNET4,
            BtcPress::IdxEsplora => IDX_ESPLORA,
            BtcPress::IdxBbRpc => IDX_BB_RPC,
            BtcPress::IdxBbRest => IDX_BB_REST,
            BtcPress::EsploraSave(net) => esplora_ids(net).1,
            BtcPress::EsploraDefault(net) => esplora_ids(net).2,
            BtcPress::EsploraTest(net) => esplora_ids(net).3,
            BtcPress::EvmAccount(Row(row)) => EVM_ACCOUNT_BASE.wrapping_add(row),
            BtcPress::Account(Row(row)) => ACCOUNT_BASE.wrapping_add(row),
            BtcPress::Utxo(Row(row)) => UTXO_BASE.wrapping_add(row),
            BtcPress::Activity(Row(row), action) => ACTIVITY_BASE
                .wrapping_add(row.wrapping_mul(ACTIVITY_STRIDE))
                .wrapping_add(match action {
                    BtcActivityAction::CopyHash => ACT_COPY,
                    BtcActivityAction::Bump => ACT_BUMP,
                    BtcActivityAction::Rebroadcast => ACT_REBROADCAST,
                    BtcActivityAction::Abandon => ACT_ABANDON,
                    BtcActivityAction::Esplora => ACT_ESPLORA,
                    BtcActivityAction::Continue => ACT_CONTINUE,
                    BtcActivityAction::Cancel => ACT_CANCEL,
                    BtcActivityAction::SaveAddress => ACT_SAVE,
                }),
        }
    }

    /// The fee choices in radio order: the order of [`fee_ids`] (2026-11-24, spec/15 §11.4 S5-5:
    /// this id table's own copy; the screens, now yw-engine `screen::build::btc`, draw the fee
    /// radios in the same order from theirs — pinned by `fee_presses_match_the_drawn_radio_order`
    /// and `cmd_table`'s `computed_presses_are_the_ids_they_replaced`; before, one module-level
    /// const of this file served both).
    pub(crate) const FEE_CHOICES: [yw_engine::wallet::app_btc::BtcFeeChoice; 4] = [
        yw_engine::wallet::app_btc::BtcFeeChoice::Fast,
        yw_engine::wallet::app_btc::BtcFeeChoice::Normal,
        yw_engine::wallet::app_btc::BtcFeeChoice::Slow,
        yw_engine::wallet::app_btc::BtcFeeChoice::Manual,
    ];

    /// The fee radio ids of the send form (2026-11-24 S5-4: moved into `ids` with the other id
    /// tables; the screens draw `fee_presses`, yw-engine `screen::build::btc` since S5-5)
    /// (`bump = false`) or the fee-bump form, in [`FEE_CHOICES`] order.
    #[must_use]
    pub const fn fee_ids(bump: bool) -> [u16; 4] {
        if bump {
            [
                BUMP_FEE_FAST,
                BUMP_FEE_NORMAL,
                BUMP_FEE_SLOW,
                BUMP_FEE_MANUAL,
            ]
        } else {
            [FEE_FAST, FEE_NORMAL, FEE_SLOW, FEE_MANUAL]
        }
    }

    /// The fee choice of a radio id, with whether it belongs to the fee-bump form.
    #[must_use]
    pub fn fee_choice_of(id: u16) -> Option<(yw_engine::wallet::app_btc::BtcFeeChoice, bool)> {
        for bump in [false, true] {
            if let Some(position) = fee_ids(bump).iter().position(|known| *known == id) {
                return FEE_CHOICES.get(position).map(|choice| (*choice, bump));
            }
        }
        None
    }

    /// `(edit, 저장, 기본값으로, 테스트)` ids of a network's Esplora URL row.
    #[must_use]
    pub const fn esplora_ids(net: yw_core::btc::BtcNetwork) -> (u16, u16, u16, u16) {
        match net {
            yw_core::btc::BtcNetwork::Mainnet => (
                ESPLORA_MAINNET_EDIT,
                ESPLORA_MAINNET_SAVE,
                ESPLORA_MAINNET_DEFAULT,
                ESPLORA_MAINNET_TEST,
            ),
            yw_core::btc::BtcNetwork::Testnet4 => (
                ESPLORA_TESTNET4_EDIT,
                ESPLORA_TESTNET4_SAVE,
                ESPLORA_TESTNET4_DEFAULT,
                ESPLORA_TESTNET4_TEST,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use yw_core::btc::{BtcMeta, BtcNetwork, Sats};
    use yw_platform::http::HttpsUrl;

    use super::ids;
    use crate::app::{App, Paths};
    use crate::ui::main_window::{Ctl, Item};
    use yw_core::lang::Lang;
    use yw_engine::apikeys::ApiKeys;
    use yw_engine::errors::ErrorCode;
    use yw_engine::events::JournalView;
    use yw_engine::meta::{Meta, Tab};
    use yw_engine::network::{BtcNet, NetworkId};
    use yw_engine::screen::SettingsSection;
    use yw_engine::screen::Tone;
    use yw_engine::screen::address::address_spans;
    use yw_engine::settings::Settings;
    use yw_engine::testkit::ScreenTestExt;
    use yw_engine::testkit::screen::btc::{T_BTC_ESPLORA_NOTE, mismatch_labels, network_tone};
    use yw_engine::text::grouped;
    use yw_engine::wallet::app_btc::{BTC_IMPORT_NOTE, BTC_MAX_ACTIVITY_ROWS, BtcFeeChoice};
    use yw_engine::wallet::app_sol::ReviewBlocker;
    use yw_engine::wallet::{AppMode, Screen};

    /// A compressed account public key (the `meta.rs` test value; never derived from here).
    const TESTNET_ACCOUNT: &str =
        "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4";

    fn app(enabled: bool, settings_net: BtcNet, meta_net: Option<BtcNetwork>, url: bool) -> App {
        let mut settings = Settings::default();
        settings.bitcoin.enabled = enabled;
        settings.bitcoin.network = settings_net;
        let mut apikeys = ApiKeys::default();
        if url {
            apikeys.set_rpc(
                NetworkId::Bitcoin(settings_net),
                &HttpsUrl::parse("https://btc.example.test/").unwrap(),
            );
        }
        let dir = std::env::temp_dir().join(format!("yw-app-btc-screens-{}", std::process::id()));
        let mut app = App::new(
            Paths {
                data: dir.clone(),
                logs: dir.join("logs"),
            },
            true,
            settings,
            apikeys,
        );
        app.mode = AppMode::Unlocked {
            alt_passphrase: false,
        };
        let mut meta = Meta::default();
        meta.prefs.tab = Tab::Btc;
        meta.btc = meta_net.map(|net| {
            let account = yw_core::bip32::AccountXpub {
                pubkey: yw_core::hex::decode_array::<33>(TESTNET_ACCOUNT).unwrap(),
                chain_code: [7; 32],
            };
            Box::new(BtcMeta::new(net, account))
        });
        app.meta = Some(meta);
        app.evm.journal = Some(JournalView {
            room: true,
            sol_room: true,
            btc_room: true,
            ..JournalView::default()
        });
        app.screen = Screen::Main;
        app
    }

    fn controls(items: &[Item]) -> Vec<Ctl> {
        items
            .iter()
            .flat_map(|item| match item {
                Item::Row(ctls) | Item::LabeledRow(_, ctls) | Item::Menu(ctls) => ctls.clone(),
                Item::CopyLine { value, actions } => {
                    let mut all = vec![value.clone()];
                    all.extend(actions.iter().cloned());
                    all
                }
                _ => Vec::new(),
            })
            .collect()
    }

    fn has_text(items: &[Item], wanted: &str) -> bool {
        items.iter().any(|item| match item {
            Item::Title(text)
            | Item::Text(text)
            | Item::Muted(text)
            | Item::Mono(text)
            | Item::Help(text)
            | Item::Subtitle(text)
            | Item::Display(text)
            | Item::Banner(text, _)
            | Item::Pill(text, _) => text.contains(wanted),
            _ => false,
        })
    }

    fn control(items: &[Item], id: u16) -> Option<Ctl> {
        controls(items).into_iter().find(|ctl| ctl.id == id)
    }

    #[test]
    fn btc_ids_are_unique_in_their_own_range() {
        let mut seen = BTreeSet::new();
        for id in ids::FIXED {
            assert!((9_000..ids::UTXO_BASE).contains(&id), "{id}");
            assert!(seen.insert(id), "duplicate {id}");
        }
        let utxo_end = ids::UTXO_BASE + ids::UTXO_SPAN;
        assert!(utxo_end <= ids::ACTIVITY_BASE);
        let rows = u16::try_from(BTC_MAX_ACTIVITY_ROWS).unwrap();
        assert!(rows * ids::ACTIVITY_STRIDE <= ids::ACTIVITY_SPAN);
        // The other modules are checked against these ranges in `ui::command_ids`.
        // Fee radios map back to their form.
        for bump in [false, true] {
            let choices: Vec<_> = ids::fee_ids(bump)
                .into_iter()
                .map(|id| ids::fee_choice_of(id).unwrap())
                .collect();
            assert_eq!(
                choices,
                [
                    (BtcFeeChoice::Fast, bump),
                    (BtcFeeChoice::Normal, bump),
                    (BtcFeeChoice::Slow, bump),
                    (BtcFeeChoice::Manual, bump),
                ]
            );
        }
        assert_eq!(ids::fee_choice_of(ids::SEND_REVIEW), None);
    }

    #[test]
    fn btc_address_is_drawn_whole_with_four_after_the_prefix_and_the_last_four() {
        let address = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
        let text = grouped(address);
        assert_eq!(text, "bc1q cr8t e4kr 609g cawu tmrz a0j4 xv80 jy8z 306f yu");
        for line in [address, text.as_str()] {
            let spans = address_spans(line).unwrap();
            let joined: String = spans.iter().map(|(piece, _)| piece.as_str()).collect();
            assert_eq!(joined, address);
            let strong: Vec<&str> = spans
                .iter()
                .filter(|(_, strong)| *strong)
                .map(|(piece, _)| piece.as_str())
                .collect();
            assert_eq!(strong, ["cr8t", "6fyu"]);
        }
        assert!(address_spans("bc1q cr8t e4kr 609g cawu tmrz a0j4 xv80 jy8z 306f yv").is_none());
    }

    #[test]
    fn mismatch_shows_both_buttons_and_nothing_else_calls() {
        let mut app = app(true, BtcNet::Mainnet, Some(BtcNetwork::Testnet4), true);
        let items = app.items();
        assert!(has_text(
            &items,
            "BTC 네트워크 설정이 지갑 데이터와 다릅니다"
        ));
        assert_eq!(
            control(&items, ids::MISMATCH_KEEP_META).map(|ctl| ctl.text),
            Some("설정을 testnet4로 되돌리기".to_owned())
        );
        assert_eq!(
            control(&items, ids::MISMATCH_USE_SETTINGS).map(|ctl| ctl.text),
            Some("mainnet으로 바꾸기".to_owned())
        );
        assert_eq!(
            mismatch_labels(Lang::Ko, BtcNetwork::Mainnet, BtcNetwork::Testnet4),
            (
                "설정을 mainnet으로 되돌리기".to_owned(),
                "testnet4로 바꾸기".to_owned()
            )
        );
        // The tab row has Bitcoin selected; sending and refreshing are off.
        assert_eq!(
            control(&items, ids::TAB_BTC).and_then(|ctl| ctl.checked),
            Some(true)
        );
        assert_eq!(
            control(&items, ids::SEND_OPEN).map(|ctl| ctl.enabled),
            Some(false)
        );
        assert_eq!(
            control(&items, ids::REFRESH).map(|ctl| ctl.enabled),
            Some(false)
        );
        // The network card's tag (2026-11-11: no longer a full-width band on S10).
        assert!(items.iter().any(|item| matches!(
            item,
            Item::Pill(text, Tone::BtcMainnet) if text == "BITCOIN MAINNET"
        )));
        // The settings section shows the same pair.
        app.screen = Screen::Settings(SettingsSection::Bitcoin);
        let items = app.items();
        assert!(control(&items, ids::MISMATCH_KEEP_META).is_some());
        assert!(control(&items, ids::MISMATCH_USE_SETTINGS).is_some());
    }

    /// spec/04 §2.6 Bitcoin: the account card lists each account with its type and prefix, and
    /// `계정 추가` opens the four plain-Korean choices with the network's prefixes, native segwit
    /// first and recommended.
    #[test]
    fn account_card_and_type_chooser() {
        for (net, settings_net, labels) in [
            (
                BtcNetwork::Mainnet,
                BtcNet::Mainnet,
                [
                    "네이티브 세그윗 (bc1q…, 권장)",
                    "탭루트 (bc1p…)",
                    "호환 세그윗 (3…)",
                    "레거시 (1…)",
                ],
            ),
            (
                BtcNetwork::Testnet4,
                BtcNet::Testnet4,
                [
                    "네이티브 세그윗 (tb1q…, 권장)",
                    "탭루트 (tb1p…)",
                    "호환 세그윗 (2…)",
                    "레거시 (m·n…)",
                ],
            ),
        ] {
            let mut app = app(true, settings_net, Some(net), true);
            // The account drop-down (2026-11-11): its button names the selected account; open,
            // the list has one entry per account (the radio ids of before), the selected marked.
            // 2026-11-15: the shared card `내 Bitcoin 계정`; items `label · source` (one set of
            // recovery words only: the name alone), the default name `Bitcoin 1`; the type and
            // prefix are the selected card's line under the name, the address its copy line.
            let items = app.items();
            assert!(items.iter().any(
                |item| matches!(item, Item::CardStart(Some(title)) if title == "내 Bitcoin 계정")
            ));
            let picker = control(&items, crate::ui::screens_links::ids::PICKER_BTC)
                .expect("account drop-down");
            assert_eq!(picker.text, "Bitcoin 1");
            assert!(control(&items, ids::ACCOUNT_BASE).is_none());
            assert!(app.on_links_command(crate::ui::screens_links::ids::PICKER_BTC));
            let items = app.items();
            let row = control(&items, ids::ACCOUNT_BASE).expect("account row");
            assert_eq!(row.text, "Bitcoin 1");
            assert_eq!(row.checked, Some(true));
            assert!(app.on_links_command(crate::ui::screens_links::ids::PICKER_BTC));
            let items = app.items();
            assert!(control(&items, ids::ACCOUNT_ADD).is_some_and(|ctl| ctl.text == "계정 추가"));
            assert!(
                items
                    .iter()
                    .any(|item| matches!(item, Item::Subtitle(text) if text == "Bitcoin 1"))
            );
            let prefix = if net == BtcNetwork::Mainnet {
                "bc1q"
            } else {
                "tb1q"
            };
            assert!(has_text(&items, &format!("네이티브 세그윗 ({prefix}…)")));
            // The default account: `이름 바꾸기`, no `숨기기`.
            assert!(control(&items, ids::RENAME).is_some());
            assert!(control(&items, ids::HIDE).is_none());
            app.btc.add_account_open = true;
            let items = app.items();
            for (offset, label) in labels.iter().enumerate() {
                let id = ids::ACCOUNT_ADD_TYPE + u16::try_from(offset).unwrap();
                assert_eq!(
                    control(&items, id).map(|ctl| ctl.text),
                    Some((*label).to_owned())
                );
            }
            assert!(control(&items, ids::ACCOUNT_ADD_CANCEL).is_some());
            assert!(control(&items, ids::ACCOUNT_ADD).is_none());
            // Key source: the standard path is checked by default (spec/08 §3.5 (a)); the EVM
            // key needs the explicit choice and shows the warning and the EVM accounts.
            let standard = control(&items, ids::ACCOUNT_SOURCE_STANDARD).expect("standard");
            assert_eq!(standard.text, "BTC 표준 경로 (권장, 기본값)");
            assert_eq!(standard.checked, Some(true));
            let evm = control(&items, ids::ACCOUNT_SOURCE_EVM).expect("evm source");
            assert_eq!(evm.text, "EVM 계정과 같은 키");
            assert_eq!(evm.checked, Some(false));
            assert!(control(&items, ids::EVM_ACCOUNT_BASE).is_none());
            assert!(!has_text(
                &items,
                yw_engine::wallet::app_btc::T_BTC_EVM_SHARED.ko
            ));
            app.btc.add_source = yw_engine::wallet::app_btc::BtcAddSource::EvmShared;
            let items = app.items();
            assert_eq!(
                control(&items, ids::ACCOUNT_SOURCE_EVM).and_then(|ctl| ctl.checked),
                Some(true)
            );
            assert!(has_text(
                &items,
                yw_engine::wallet::app_btc::T_BTC_EVM_SHARED.ko
            ));
            let first = control(&items, ids::EVM_ACCOUNT_BASE).expect("EVM account 0");
            assert!(first.text.ends_with("m/44'/60'/0'/0/0"), "{}", first.text);
            assert_eq!(first.checked, Some(true));
            app.btc.add_source = yw_engine::wallet::app_btc::BtcAddSource::Standard;
        }
    }

    /// spec/08 §3.5: the selected HD account's address mode (fixed by default, the one-line
    /// trade-off) and the receive screen of each mode: fixed shows `…/0/0`, the explanation and
    /// no `새 주소`; HD shows the index and `새 주소`.
    #[test]
    fn address_mode_radios_and_receive_screen() {
        let mut app = app(true, BtcNet::Testnet4, Some(BtcNetwork::Testnet4), true);
        let items = app.items();
        let single = control(&items, ids::ADDRESS_MODE_SINGLE).expect("fixed radio");
        assert_eq!(single.text, "고정 주소 하나만 사용 (UniSat·Xverse 방식)");
        assert_eq!(single.checked, Some(true));
        let hd = control(&items, ids::ADDRESS_MODE_HD).expect("hd radio");
        assert_eq!(hd.text, "받을 때마다 새 주소 (HD, 프라이버시↑)");
        assert_eq!(hd.checked, Some(false));
        assert!(has_text(
            &items,
            yw_engine::wallet::app_btc::T_BTC_MODE_HELP.ko
        ));
        let meta = app.btc_ctx().btc_meta().cloned().unwrap();
        app.btc.receive = yw_engine::wallet::app_btc::BtcUi::receive_view(Lang::Ko, &meta, 0);
        app.screen = Screen::BtcReceive;
        let items = app.items();
        assert!(has_text(
            &items,
            yw_engine::wallet::app_btc::T_BTC_FIXED_RECEIVE.ko
        ));
        assert!(has_text(&items, "m/84'/1'/0'/0/0"));
        assert!(control(&items, ids::NEW_ADDRESS).is_none());
        assert!(control(&items, ids::COPY_ADDRESS).is_some());
        // HD mode.
        let mut hd_meta = meta;
        hd_meta.set_single_address(false).unwrap();
        if let Some(document) = app.meta.as_mut() {
            document.btc = Some(Box::new(hd_meta.clone()));
        }
        app.btc.receive = yw_engine::wallet::app_btc::BtcUi::receive_view(Lang::Ko, &hd_meta, 3);
        let items = app.items();
        assert!(!has_text(
            &items,
            yw_engine::wallet::app_btc::T_BTC_FIXED_RECEIVE.ko
        ));
        assert!(has_text(&items, "m/84'/1'/0'/0/3"));
        assert!(control(&items, ids::NEW_ADDRESS).is_some());
        // The address is one copy line before the QR (2026-11-12), whole (§3.3), with
        // `새 주소` on that line.
        let address = app.btc.receive.as_ref().unwrap().address.clone();
        assert_eq!(
            control(&items, ids::COPY_ADDRESS).and_then(|line| line.value_text()),
            Some(address)
        );
        let line = items
            .iter()
            .position(|item| matches!(item, Item::CopyLine { actions, .. } if actions.len() == 1));
        assert!(line.is_some() && line < items.iter().position(|item| matches!(item, Item::Qr(_))));
        app.screen = Screen::Main;
        let items = app.items();
        assert_eq!(
            control(&items, ids::ADDRESS_MODE_HD).and_then(|ctl| ctl.checked),
            Some(true)
        );
    }

    /// Same order as the other tabs: the selected account's `보내기`·`받기` come before the
    /// account list; `개인키 가져오기` opens its address-type chooser on demand.
    #[test]
    fn selected_account_first_and_import_chooser_on_demand() {
        use crate::ui::screens_keys::ids as key_ids;
        let mut app = app(true, BtcNet::Testnet4, Some(BtcNetwork::Testnet4), true);
        let items = app.items();
        let order: Vec<u16> = controls(&items).iter().map(|ctl| ctl.id).collect();
        let position = |id: u16| order.iter().position(|each| *each == id).unwrap();
        assert!(position(ids::SEND_OPEN) < position(crate::ui::screens_links::ids::PICKER_BTC));
        assert!(position(ids::RECEIVE_OPEN) < position(ids::ACCOUNT_ADD));
        // Closed: one line and the button, no radios.
        assert!(order.contains(&key_ids::BTC_IMPORT));
        assert!(!order.contains(&key_ids::BTC_IMPORT_NEXT));
        assert!(!order.contains(&key_ids::SCRIPT_BASE));
        assert!(has_text(&items, "누르면 주소 형식을 고릅니다"));
        assert!(app.on_keys_command(key_ids::BTC_IMPORT));
        let items = app.items();
        let open: Vec<Ctl> = controls(&items);
        assert!(open.iter().any(|ctl| ctl.id == key_ids::BTC_IMPORT_NEXT));
        assert!(open.iter().any(|ctl| ctl.id == key_ids::BTC_IMPORT_CANCEL));
        assert!(!open.iter().any(|ctl| ctl.id == key_ids::BTC_IMPORT));
        assert!(
            open.iter()
                .any(|ctl| ctl.text == "네이티브 세그윗 (bc1q…, P2WPKH)"
                    && ctl.checked == Some(true))
        );
        assert!(app.on_keys_command(key_ids::BTC_IMPORT_CANCEL));
        assert!(control(&app.items(), key_ids::BTC_IMPORT).is_some());
        // One Bitcoin network tag, not a second generic testnet band.
        assert_eq!(
            items
                .iter()
                .filter(|item| matches!(
                    item,
                    Item::Banner(_, Tone::BtcTestnet4 | Tone::Testnet)
                        | Item::Pill(_, Tone::BtcTestnet4 | Tone::Testnet)
                ))
                .count(),
            1
        );
    }

    #[test]
    fn gate_texts_of_the_tab() {
        // Disabled: the fixed text and a way to the settings section, no banner.
        let app_off = app(false, BtcNet::Testnet4, None, false);
        let items = app_off.items();
        assert!(has_text(&items, "Bitcoin이 꺼져 있습니다"));
        assert!(control(&items, ids::SECTION_BTC).is_some());
        assert!(control(&items, ids::SEND_OPEN).is_none());
        assert!(!has_text(&items, "BITCOIN TESTNET4"));
        // No endpoint: E-KEY-005 and `RPC 설정하기` (that network's row).
        let app_no_url = app(true, BtcNet::Testnet4, Some(BtcNetwork::Testnet4), false);
        let items = app_no_url.items();
        assert!(has_text(
            &items,
            &ErrorCode::Key005.text_in(yw_core::lang::Lang::Ko)
        ));
        assert!(control(&items, crate::ui::screens::ids::BTC_RPC_OPEN).is_some());
        assert!(items.iter().any(|item| matches!(
            item,
            Item::Pill(text, Tone::BtcTestnet4) if text == "BITCOIN TESTNET4 — 가치 없음"
        )));
        assert!(!items.iter().any(|item| matches!(
            item,
            Item::Banner(_, Tone::Testnet) | Item::Pill(_, Tone::Testnet)
        )));
        // Usable but discovery not done: "주소 검색 미완료" + [다시 시도]; sending blocked.
        let ready = app(true, BtcNet::Testnet4, Some(BtcNetwork::Testnet4), true);
        let items = ready.items();
        assert!(has_text(&items, "주소 검색 미완료"));
        assert_eq!(
            control(&items, ids::DISCOVER_RETRY).map(|ctl| ctl.enabled),
            Some(true)
        );
        assert_eq!(
            control(&items, ids::SEND_OPEN).map(|ctl| ctl.enabled),
            Some(false)
        );
        assert!(has_text(&items, "보내기: 주소 검색 미완료"));
        assert_eq!(
            control(&items, ids::RECEIVE_OPEN).map(|ctl| ctl.enabled),
            Some(true)
        );
        assert!(has_text(&items, "Core RPC (bitcoin:testnet4): 확인 전"));
        assert_eq!(network_tone(BtcNetwork::Mainnet), Tone::BtcMainnet);
    }

    #[test]
    fn send_form_shows_the_typed_fee_field_only_when_needed() {
        let mut app = app(true, BtcNet::Testnet4, Some(BtcNetwork::Testnet4), true);
        app.screen = Screen::BtcSend;
        let items = app.items();
        for id in [
            ids::SEND_TO_EDIT,
            ids::SEND_AMOUNT_EDIT,
            ids::UNIT_BTC,
            ids::UNIT_SATS,
            ids::SEND_MAX,
            ids::FEE_FAST,
            ids::FEE_NORMAL,
            ids::FEE_SLOW,
            ids::FEE_MANUAL,
            ids::SEND_REVIEW,
            ids::SEND_CANCEL,
        ] {
            assert!(control(&items, id).is_some(), "{id}");
        }
        assert_eq!(
            control(&items, ids::FEE_NORMAL).and_then(|ctl| ctl.checked),
            Some(true)
        );
        assert!(control(&items, ids::TYPED_FEE_EDIT).is_none());
        assert!(control(&items, ids::FEE_MANUAL_EDIT).is_none());
        assert_eq!(
            control(&items, ids::SEND_REVIEW).map(|ctl| ctl.enabled),
            Some(false)
        );
        // The line under it says why: the address search has not run (the band at the top).
        assert_eq!(
            app.screen_view(&app.facts()).btc_review_blocker(),
            Some(ReviewBlocker::Held)
        );
        assert!(has_text(
            &items,
            ReviewBlocker::Held.text_in(yw_core::lang::Lang::Ko)
        ));
        app.btc.send.fee.choice = BtcFeeChoice::Manual;
        app.btc.send.fee.needs_typed = Sats::new(600_000);
        let items = app.items();
        assert!(control(&items, ids::FEE_MANUAL_EDIT).is_some());
        assert!(control(&items, ids::TYPED_FEE_EDIT).is_some());
        assert!(has_text(&items, "수수료(sats)를 정확히 입력해 상한 해제"));
        // The fee-bump form has its own ids.
        app.screen = Screen::BtcBump;
        let items = app.items();
        assert!(control(&items, ids::BUMP_FEE_NORMAL).is_some());
        assert!(control(&items, ids::FEE_NORMAL).is_none());
        assert_eq!(
            control(&items, ids::BUMP_REVIEW).map(|ctl| ctl.enabled),
            Some(false)
        );
    }

    #[test]
    fn settings_section_import_note_and_url_list() {
        let mut app = app(false, BtcNet::Mainnet, None, true);
        app.screen = Screen::Settings(SettingsSection::Bitcoin);
        let items = app.items();
        for id in [
            ids::ENABLE,
            ids::SET_MAINNET,
            ids::SET_TESTNET4,
            ids::IDX_ESPLORA,
            ids::IDX_BB_RPC,
            ids::IDX_BB_REST,
            ids::ESPLORA_MAINNET_EDIT,
            ids::ESPLORA_MAINNET_SAVE,
            ids::ESPLORA_MAINNET_DEFAULT,
            ids::ESPLORA_MAINNET_TEST,
            ids::ESPLORA_TESTNET4_EDIT,
            ids::ESPLORA_TESTNET4_SAVE,
            ids::ESPLORA_TESTNET4_DEFAULT,
            ids::ESPLORA_TESTNET4_TEST,
        ] {
            assert!(control(&items, id).is_some(), "{id}");
        }
        assert_eq!(
            control(&items, ids::ENABLE).and_then(|ctl| ctl.checked),
            Some(false)
        );
        assert!(has_text(&items, T_BTC_ESPLORA_NOTE.ko));
        assert!(has_text(&items, "https://mempool.space/testnet4/api"));
        assert_eq!(
            control(&items, ids::ESPLORA_MAINNET_EDIT).map(|ctl| ctl.text),
            Some("https://mempool.space/api".to_owned())
        );
        assert!(has_text(&items, "Core RPC 주소 bitcoin:mainnet: 설정됨"));
        assert!(has_text(
            &items,
            "Core RPC 주소 bitcoin:testnet4: 없음 — E-KEY-005"
        ));
        // The selected settings tab is drawn selected (Ctl::tab).
        assert_eq!(
            control(&items, ids::SECTION_BTC).and_then(|ctl| ctl.checked),
            Some(true)
        );
        app.screen = Screen::ImportIntro;
        assert!(has_text(&app.items(), BTC_IMPORT_NOTE.ko));
        app.screen = Screen::Settings(SettingsSection::Network);
        let items = app.items();
        assert!(!has_text(&items, "M8"));
        assert!(has_text(&items, "(bitcoin:testnet4)"));
    }

    /// Every text of an item and its controls (labels, values, tooltips are not drawn here).
    fn all_texts(items: &[Item]) -> Vec<String> {
        let mut out: Vec<String> = items
            .iter()
            .filter_map(|item| match item {
                Item::Title(text)
                | Item::Text(text)
                | Item::Muted(text)
                | Item::Help(text)
                | Item::Subtitle(text)
                | Item::Display(text)
                | Item::Banner(text, _)
                | Item::Pill(text, _)
                | Item::LabeledRow(text, _) => Some(text.clone()),
                Item::Field(label, value) => Some(format!("{label} {value}")),
                Item::CardStart(Some(title)) => Some(title.clone()),
                _ => None,
            })
            .collect();
        out.extend(controls(items).into_iter().map(|ctl| ctl.text));
        out
    }

    /// spec/14 (Step 3): the Bitcoin screens built in English show none of the Bitcoin
    /// catalogues' Korean texts, and every Bitcoin control (ids 9000–9899) has a Hangul-free label.
    #[test]
    fn english_bitcoin_screens_have_no_korean_btc_text() {
        use yw_core::lang::has_hangul;
        let korean: Vec<&str> = yw_engine::testkit::screen::btc::text::ALL
            .iter()
            .chain(yw_engine::wallet::app_btc::text::ALL)
            .chain(yw_engine::btc::text::ALL)
            .map(|entry| entry.ko)
            .filter(|ko| has_hangul(ko) && ko.chars().count() >= 4 && !ko.contains("{0}"))
            .collect();
        let check = |items: &[Item], screen: &str| {
            for text in all_texts(items) {
                for ko in &korean {
                    assert!(!text.contains(ko), "{screen}: {text}");
                }
            }
            for ctl in controls(items) {
                if (9_000..9_900).contains(&ctl.id) {
                    assert!(!has_hangul(&ctl.text), "{screen}: {}", ctl.text);
                }
            }
        };
        // Disabled tab, mismatch, the normal tab and its forms, receive, settings.
        let mut off = app(false, BtcNet::Mainnet, None, true);
        off.settings.language = Lang::En;
        check(&off.items(), "disabled");
        let mut mismatch = app(true, BtcNet::Mainnet, Some(BtcNetwork::Testnet4), true);
        mismatch.settings.language = Lang::En;
        let items = mismatch.items();
        check(&items, "mismatch");
        assert_eq!(
            control(&items, ids::MISMATCH_KEEP_META).map(|ctl| ctl.text),
            Some("Set the setting back to testnet4".to_owned())
        );
        let mut app = app(true, BtcNet::Testnet4, Some(BtcNetwork::Testnet4), true);
        app.settings.language = Lang::En;
        app.btc.add_account_open = true;
        app.btc.verify_failures = 1;
        app.btc.auto_frozen = 2;
        let items = app.items();
        check(&items, "tab");
        assert!(items.iter().any(|item| matches!(
            item,
            Item::Pill(text, Tone::BtcTestnet4) if text == "BITCOIN TESTNET4 — NO VALUE"
        )));
        for screen in [
            Screen::BtcSend,
            Screen::BtcBump,
            Screen::BtcSendResult,
            Screen::Settings(SettingsSection::Bitcoin),
        ] {
            let name = format!("{screen:?}");
            app.screen = screen;
            check(&app.items(), &name);
        }
        let meta = app.btc_ctx().btc_meta().cloned().unwrap();
        app.btc.receive = yw_engine::wallet::app_btc::BtcUi::receive_view(Lang::En, &meta, 0);
        app.screen = Screen::BtcReceive;
        let items = app.items();
        check(&items, "receive");
        let view = app.btc.receive.as_ref().unwrap();
        assert!(!has_hangul(&view.note) && !has_hangul(&view.kind) && !has_hangul(&view.account));
    }

    /// spec/14: every confirmation overlay, the fee radios, statuses and the W-ADDR-3 ends in
    /// English are Hangul-free; the Korean ones keep their text.
    #[test]
    fn english_bitcoin_confirmations_and_statuses() {
        use yw_core::lang::has_hangul;
        use yw_engine::wallet::app_btc::BtcConfirm;
        let txid = yw_core::btc::Txid::from_bytes([1; 32]);
        for confirm in [
            BtcConfirm::NetworkChange {
                to: BtcNetwork::Mainnet,
            },
            BtcConfirm::IndexerOptIn {
                indexer: yw_engine::settings::BtcIndexer::BbRpc,
            },
            BtcConfirm::GapWarning { unused: 20 },
            BtcConfirm::Abandon { txid },
            BtcConfirm::CancelSigned {
                txid,
                disclosed: false,
            },
            BtcConfirm::CancelSigned {
                txid,
                disclosed: true,
            },
            BtcConfirm::EsploraBroadcast { txid },
            BtcConfirm::ResetTip,
            BtcConfirm::AddEvmShared {
                script_type: yw_core::btc::ScriptType::P2tr,
                evm_index: 3,
            },
        ] {
            let (title, body, yes) = confirm.texts(Lang::En);
            assert!(
                !has_hangul(title) && !has_hangul(&body) && !has_hangul(yes),
                "{body}"
            );
            assert!(!has_hangul(confirm.no_label(Lang::En)));
            let (_, korean, _) = confirm.texts(Lang::Ko);
            assert!(has_hangul(&korean));
        }
        for choice in ids::FEE_CHOICES {
            assert!(!has_hangul(choice.label(Lang::En)));
        }
        for confirmations in [0, 1, 6] {
            assert!(!has_hangul(
                &yw_engine::wallet::app_btc::confirmations_text(Lang::En, confirmations)
            ));
        }
        assert_eq!(
            yw_engine::wallet::app_btc::ends_text(Lang::En, (4, 4)),
            "first 4 and last 4 characters"
        );
        assert_eq!(
            yw_engine::wallet::app_btc::ends_text(Lang::Ko, (0, 5)),
            "끝 5자"
        );
    }

    /// spec/14: the screen catalogue keeps the catalogue invariants.
    #[test]
    fn bitcoin_screen_catalogues_are_well_formed() {
        use yw_core::lang::{has_hangul, placeholders};
        for entry in yw_engine::testkit::screen::btc::text::ALL
            .iter()
            .chain(yw_engine::wallet::app_btc::text::ALL)
            .chain(yw_engine::btc::text::ALL)
            .chain(yw_engine::received::btc::text::ALL)
            .chain(yw_engine::workers::journal::btc::text::ALL)
        {
            let expected: Vec<usize> = (0..entry.args).collect();
            for template in [entry.ko, entry.en] {
                let mut found = placeholders(template);
                found.sort_unstable();
                found.dedup();
                assert_eq!(found, expected, "{}", entry.name);
            }
            assert!(!has_hangul(entry.en), "{}", entry.name);
        }
    }
}
