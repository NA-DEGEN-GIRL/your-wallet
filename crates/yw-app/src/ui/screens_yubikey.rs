//! `YubiKey` screens (spec/04 §2.19, spec/10 §7): the S01 card `YubiKey에 키 보관`, S20 (the new
//! `YubiKey` wallet), S21 the enrolment wizard (keys and slots, confirmation with every path and
//! address, credentials, result with "다시 확인" and the defaults change), settings → `YubiKey`
//! (the enrolled cards, their slots, which cards hold each account, `삭제`) and the removal
//! overlay. Fixed sentences are the T-YK-* rows of spec/04 §2.16.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): the builders, their helpers and texts moved to yw-engine
//! `screen::build::yubikey` (bodies unchanged); this file keeps the control ids of its controls
//! (`ids`), which only the Windows shell has (the tests' `T_YK_MNEMONIC_WALLET` went; they name
//! the text in the engine's catalogue).

/// Command ids (block 13,200–13,399, and 13,500–13,506 and 13,720–13,927 for "`YubiKey` 연결하기",
/// 13,524–13,537 for the card names; `ui::command_ids`).
pub mod ids {
    use yw_core::btc::ScriptType;
    use yw_core::yubikey::plan::{PgpKey, TouchPolicy};
    use yw_core::zec::ZecNetwork;

    use yw_engine::wallet::app_yubikey::manage::{Chain, Preset, ReslotAction};
    use yw_engine::wallet::app_yubikey::{CARD_SCRIPTS, PGP_TOUCH, PgpAction, PgpKind};

    /// Settings tab `YubiKey`.
    pub const SECTION_YUBIKEY: u16 = 13_200;
    /// `YubiKey 등록` (settings, a key-only wallet's chain card).
    pub const ENROL_START: u16 = 13_201;
    /// S01 `YubiKey 지갑 만들기`.
    pub const NEW_WALLET: u16 = 13_202;
    /// S20 `시작하기`.
    pub const NEW_WALLET_START: u16 = 13_203;
    /// S20 `취소`.
    pub const NEW_WALLET_CANCEL: u16 = 13_204;
    /// `OpenPGP` SIG controls: `SIG_BASE + offset` (kind 0–3, index edit 4, scripts 5–7,
    /// touch 8–11, kind Zcash 12, Zcash network mainnet 13 / testnet 14).
    pub const SIG_BASE: u16 = 13_210;
    /// `OpenPGP` AUT controls (same offsets).
    pub const AUT_BASE: u16 = 13_230;
    /// SIG index edit.
    pub const SIG_INDEX_EDIT: u16 = SIG_BASE + 4;
    /// AUT index edit.
    pub const AUT_INDEX_EDIT: u16 = AUT_BASE + 4;
    /// PIV Solana account count edit.
    pub const SOL_COUNT_EDIT: u16 = 13_250;
    /// PIV first Solana index edit.
    pub const SOL_START_EDIT: u16 = 13_251;
    /// PIV touch "항상".
    pub const PIV_TOUCH_ALWAYS: u16 = 13_252;
    /// PIV touch "15초 유지".
    pub const PIV_TOUCH_CACHED: u16 = 13_253;
    /// The §3.2 checkbox of the shared key.
    pub const SHARED_ACK: u16 = 13_254;
    /// "백업 복사본" checkbox.
    pub const BACKUP_TOGGLE: u16 = 13_255;
    /// (a) `다음`.
    pub const PLAN_NEXT: u16 = 13_256;
    /// Wizard `취소`.
    pub const WIZARD_CANCEL: u16 = 13_257;
    /// "백업 복사본" source radios: `BACKUP_BASE + row` (≤ 8 cards).
    pub const BACKUP_BASE: u16 = 13_260;
    /// Rows of [`BACKUP_BASE`].
    pub const BACKUP_SPAN: u16 = 8;
    /// Settings `삭제` of card row: `REMOVE_BASE + row`.
    pub const REMOVE_BASE: u16 = 13_270;
    /// Rows of [`REMOVE_BASE`].
    pub const REMOVE_SPAN: u16 = 8;
    /// (c) the same-mnemonic checkbox.
    pub const SAME_ACK: u16 = 13_280;
    /// (c) `다음`.
    pub const CONFIRM_NEXT: u16 = 13_281;
    /// (c) `← 슬롯 다시 고르기`.
    pub const CONFIRM_BACK: u16 = 13_282;
    /// (d) "기본 관리 키 사용".
    pub const MGMT_DEFAULT: u16 = 13_283;
    /// (d) "관리 키 직접 입력".
    pub const MGMT_CUSTOM: u16 = 13_284;
    /// (d) `가져오기`.
    pub const IMPORT: u16 = 13_285;
    /// (d) `가져오기 없이 등록`.
    pub const ADOPT: u16 = 13_286;
    /// (e) `다시 확인`.
    pub const RECHECK: u16 = 13_287;
    /// (e) `다른 YubiKey 등록(백업)`.
    pub const ANOTHER: u16 = 13_288;
    /// (e) `완료`.
    pub const FINISH: u16 = 13_289;
    /// (e) `OpenPGP PIN 바꾸기`.
    pub const CHANGE_PW1: u16 = 13_290;
    /// (e) `OpenPGP 관리자 PIN 바꾸기`.
    pub const CHANGE_PW3: u16 = 13_291;
    /// (e) `PIV PIN 바꾸기`.
    pub const CHANGE_PIV_PIN: u16 = 13_292;
    /// (e) `PIV PUK 바꾸기`.
    pub const CHANGE_PUK: u16 = 13_293;
    /// (e) `PIV 관리 키 자동 보호` (generated, stored PIN-protected).
    pub const CHANGE_MGMT: u16 = 13_294;
    /// (d) `← 이전`.
    pub const CRED_BACK: u16 = 13_295;
    /// (e) `다시 시도` after a failure.
    pub const RETRY: u16 = 13_296;
    /// "PIN 설정" `PIN 설정하기` ("8자리 하나로 통일").
    pub const SET_PINS: u16 = 13_297;
    /// "PIN 설정" mode radio "8자리 하나로 통일" (default).
    pub const PINS_UNIFIED: u16 = 13_298;
    /// "PIN 설정" mode radio "하나씩 따로".
    pub const PINS_SEPARATE: u16 = 13_299;
    /// Settings `PIN 설정 / 기본값 변경` of card row: `PINS_BASE + row`.
    pub const PINS_BASE: u16 = 13_300;
    /// Rows of [`PINS_BASE`].
    pub const PINS_SPAN: u16 = 8;

    /// `슬롯 구성 바꾸기` of card row: `RESLOT_BASE + row` (spec/10 §15.1).
    pub const RESLOT_BASE: u16 = 13_310;
    /// Rows of [`RESLOT_BASE`].
    pub const RESLOT_SPAN: u16 = 8;
    /// `YubiKey 비우기` of card row: `CLEAR_BASE + row` (spec/10 §15.2).
    pub const CLEAR_BASE: u16 = 13_320;
    /// Rows of [`CLEAR_BASE`].
    pub const CLEAR_SPAN: u16 = 8;
    /// Re-slot preset radios: `PRESET_BASE + position` of [`Preset::ALL`].
    pub const PRESET_BASE: u16 = 13_330;
    /// Re-slot SIG controls: `RESLOT_SIG_BASE + offset` (chain 0–3, index edit 4, scripts 5–7).
    pub const RESLOT_SIG_BASE: u16 = 13_340;
    /// Re-slot AUT controls (same offsets).
    pub const RESLOT_AUT_BASE: u16 = 13_350;
    /// Re-slot SIG index edit.
    pub const RESLOT_SIG_INDEX_EDIT: u16 = RESLOT_SIG_BASE + 4;
    /// Re-slot AUT index edit.
    pub const RESLOT_AUT_INDEX_EDIT: u16 = RESLOT_AUT_BASE + 4;
    /// Re-slot Zcash network "메인넷".
    pub const RESLOT_ZEC_MAIN: u16 = 13_358;
    /// Re-slot Zcash network "테스트넷".
    pub const RESLOT_ZEC_TEST: u16 = 13_359;
    /// Re-slot "고급: EVM 공유 키도 보이기".
    pub const RESLOT_ADVANCED: u16 = 13_360;
    /// Re-slot §3.2 checkbox of the shared key.
    pub const RESLOT_SHARED_ACK: u16 = 13_361;
    /// Re-slot "이해했습니다" of the removed chains.
    pub const RESLOT_REMOVED_ACK: u16 = 13_362;
    /// Re-slot `다음`.
    pub const RESLOT_NEXT: u16 = 13_363;
    /// Re-slot `← 다시 고르기`.
    pub const RESLOT_BACK: u16 = 13_364;
    /// Re-slot `YubiKey에 넣기` (admin PIN).
    pub const RESLOT_IMPORT: u16 = 13_365;
    /// Card action `취소`.
    pub const MANAGE_CANCEL: u16 = 13_366;
    /// Re-slot `다시 시도`.
    pub const RESLOT_RETRY: u16 = 13_367;
    /// Card action `완료`.
    pub const MANAGE_DONE: u16 = 13_368;
    /// "백업 `YubiKey`에도 같은 구성 적용" of card row: `RESLOT_BACKUP_BASE + row`.
    pub const RESLOT_BACKUP_BASE: u16 = 13_370;
    /// Rows of [`RESLOT_BACKUP_BASE`].
    pub const RESLOT_BACKUP_SPAN: u16 = 8;
    /// Clear: `OpenPGP` wallet keys checkbox.
    pub const CLEAR_PGP_TOGGLE: u16 = 13_380;
    /// Clear: PIV Solana slots checkbox.
    pub const CLEAR_PIV_TOGGLE: u16 = 13_381;
    /// Clear: `OpenPGP` "우리 슬롯만 지우기".
    pub const CLEAR_PGP_OURS: u16 = 13_382;
    /// Clear: `OpenPGP` "애플릿 초기화".
    pub const CLEAR_PGP_RESET: u16 = 13_383;
    /// Clear: PIV "우리 슬롯만 지우기".
    pub const CLEAR_PIV_OURS: u16 = 13_384;
    /// Clear: PIV "애플릿 초기화".
    pub const CLEAR_PIV_RESET: u16 = 13_385;
    /// Clear: the confirmation word edit.
    pub const CLEAR_CONFIRM_EDIT: u16 = 13_386;
    /// Clear: `비우기`.
    pub const CLEAR_RUN: u16 = 13_387;
    /// Wizard (c)/(d): `다시 읽기` of the inserted card.
    pub const IDENTIFY_AGAIN: u16 = 13_388;
    /// Main window: `PIN 설정` after a signing refused for factory PINs.
    pub const PIN_NEEDED_OPEN: u16 = 13_389;
    /// `PIN 설정` of the band of an account card or send form whose card is still on its
    /// factory PINs (2026-11-10): `PIN_GATE_BASE + card row`.
    pub const PIN_GATE_BASE: u16 = 13_510;
    /// Rows of [`PIN_GATE_BASE`].
    pub const PIN_GATE_SPAN: u16 = 8;
    /// Clear: '어떻게 지우나요 ▸' (2026-11-10).
    pub const CLEAR_HOW: u16 = 13_520;
    /// Result screen: '슬롯·주소 자세히 ▸' (2026-11-10).
    pub const RESULT_DETAILS: u16 = 13_521;
    /// "PIN 설정": 'PIN 안내 ▸' (2026-11-10).
    pub const PIN_GUIDE: u16 = 13_522;
    /// Re-slot result: `PIN 설정하기` of a card left on its factory PINs (2026-11-10).
    pub const RESLOT_PIN_NOW: u16 = 13_523;
    /// Card name edit (2026-11-15): `저장`.
    pub const CARD_NAME_SAVE: u16 = 13_524;
    /// Card name edit: `취소`.
    pub const CARD_NAME_CANCEL: u16 = 13_525;
    /// Card name edit: the name field (a label, not a secret).
    pub const CARD_NAME_EDIT: u16 = 13_526;
    /// Card name edit: `이름 지우기`.
    pub const CARD_NAME_CLEAR: u16 = 13_527;
    /// `이름 바꾸기` of card row: `RENAME_CARD_BASE + row` (2026-11-15).
    pub const RENAME_CARD_BASE: u16 = 13_530;
    /// Rows of [`RENAME_CARD_BASE`].
    pub const RENAME_CARD_SPAN: u16 = 8;
    /// Re-slot: the T-YK-KEY-LOST checkbox (a key without recovery words is overwritten).
    pub const RESLOT_LOSS_ACK: u16 = 13_390;
    /// Re-slot: the typed `영구 삭제`.
    pub const RESLOT_LOSS_EDIT: u16 = 13_391;
    /// Clear: the T-YK-KEY-LOST checkbox (a key without recovery words is cleared).
    pub const CLEAR_LOSS_ACK: u16 = 13_392;
    /// Clear: the typed `영구 삭제`.
    pub const CLEAR_LOSS_EDIT: u16 = 13_393;
    /// Re-slot: the T-YK-SAME checkbox (a card connected without recovery words gets words this
    /// PC also holds).
    pub const RESLOT_SAME_ACK: u16 = 13_394;
    /// Wizard step (d): the T-YK-OCCUPIED checkbox (a planned slot holds a key the words do not
    /// derive, spec/10 §7.4).
    pub const OVERWRITE_ACK: u16 = 13_395;
    /// Wizard step (d): the typed `영구 삭제` of that key.
    pub const OVERWRITE_EDIT: u16 = 13_396;

    const KINDS: [PgpKind; 4] = [PgpKind::None, PgpKind::Evm, PgpKind::Btc, PgpKind::Shared];
    const ZEC_NETWORKS: [ZecNetwork; 2] = [ZecNetwork::Mainnet, ZecNetwork::Testnet];

    /// The id of a control of `key`'s re-slot form.
    #[must_use]
    pub fn reslot_id(key: PgpKey, action: ReslotAction) -> u16 {
        let base = match key {
            PgpKey::Sig => RESLOT_SIG_BASE,
            PgpKey::Aut => RESLOT_AUT_BASE,
        };
        let offset = match action {
            ReslotAction::Chain(chain) => Chain::ALL.iter().position(|other| *other == chain),
            ReslotAction::Script(script) => CARD_SCRIPTS
                .iter()
                .position(|other| *other == script)
                .map(|position| position + 5),
        };
        base.saturating_add(
            offset
                .and_then(|offset| u16::try_from(offset).ok())
                .unwrap_or(4),
        )
    }

    /// The form and action of a re-slot slot control id.
    #[must_use]
    pub fn reslot_action(id: u16) -> Option<(PgpKey, ReslotAction)> {
        let (key, offset) = if (RESLOT_SIG_BASE..RESLOT_SIG_BASE + 8).contains(&id) {
            (PgpKey::Sig, id - RESLOT_SIG_BASE)
        } else if (RESLOT_AUT_BASE..RESLOT_AUT_BASE + 8).contains(&id) {
            (PgpKey::Aut, id - RESLOT_AUT_BASE)
        } else {
            return None;
        };
        let offset = usize::from(offset);
        let action = match offset {
            0..=3 => ReslotAction::Chain(*Chain::ALL.get(offset)?),
            5..=7 => ReslotAction::Script(*CARD_SCRIPTS.get(offset - 5)?),
            _ => return None,
        };
        Some((key, action))
    }

    /// The id of a preset radio.
    #[must_use]
    pub fn preset_id(preset: Preset) -> u16 {
        let position = Preset::ALL
            .iter()
            .position(|other| *other == preset)
            .and_then(|position| u16::try_from(position).ok())
            .unwrap_or(0);
        PRESET_BASE.saturating_add(position)
    }

    /// The preset of a preset radio id.
    #[must_use]
    pub fn preset(id: u16) -> Option<Preset> {
        let offset = id.checked_sub(PRESET_BASE)?;
        Preset::ALL.get(usize::from(offset)).copied()
    }

    fn row_of(id: u16, base: u16, span: u16) -> Option<usize> {
        id.checked_sub(base)
            .filter(|offset| *offset < span)
            .map(usize::from)
    }

    /// The card row of a `슬롯 구성 바꾸기` id.
    #[must_use]
    pub fn reslot_row(id: u16) -> Option<usize> {
        row_of(id, RESLOT_BASE, RESLOT_SPAN)
    }

    /// The card row of a `YubiKey 비우기` id.
    #[must_use]
    pub fn clear_row(id: u16) -> Option<usize> {
        row_of(id, CLEAR_BASE, CLEAR_SPAN)
    }

    /// The card row of a "백업 `YubiKey`에도 같은 구성 적용" id.
    #[must_use]
    pub fn reslot_backup_row(id: u16) -> Option<usize> {
        row_of(id, RESLOT_BACKUP_BASE, RESLOT_BACKUP_SPAN)
    }

    /// The id of a control of `key`'s form.
    #[must_use]
    pub fn pgp_id(key: PgpKey, action: PgpAction) -> u16 {
        let base = match key {
            PgpKey::Sig => SIG_BASE,
            PgpKey::Aut => AUT_BASE,
        };
        let offset = match action {
            PgpAction::Kind(PgpKind::Zec) => Some(12),
            PgpAction::Zec(network) => ZEC_NETWORKS
                .iter()
                .position(|other| *other == network)
                .map(|position| position + 13),
            PgpAction::Kind(kind) => KINDS.iter().position(|other| *other == kind),
            PgpAction::Script(script) => CARD_SCRIPTS
                .iter()
                .position(|other| *other == script)
                .map(|position| position + 5),
            PgpAction::Touch(touch) => PGP_TOUCH
                .iter()
                .position(|other| *other == touch)
                .map(|position| position + 8),
        };
        base.saturating_add(
            offset
                .and_then(|offset| u16::try_from(offset).ok())
                .unwrap_or(4),
        )
    }

    /// The form and action of an `OpenPGP` slot control id.
    #[must_use]
    pub fn pgp_action(id: u16) -> Option<(PgpKey, PgpAction)> {
        let (key, offset) = if (SIG_BASE..SIG_BASE + 15).contains(&id) {
            (PgpKey::Sig, id - SIG_BASE)
        } else if (AUT_BASE..AUT_BASE + 15).contains(&id) {
            (PgpKey::Aut, id - AUT_BASE)
        } else {
            return None;
        };
        let offset = usize::from(offset);
        let action = match offset {
            0..=3 => PgpAction::Kind(*KINDS.get(offset)?),
            5..=7 => PgpAction::Script(*CARD_SCRIPTS.get(offset - 5)?),
            8..=11 => PgpAction::Touch(*PGP_TOUCH.get(offset - 8)?),
            12 => PgpAction::Kind(PgpKind::Zec),
            13..=14 => PgpAction::Zec(*ZEC_NETWORKS.get(offset - 13)?),
            _ => return None,
        };
        Some((key, action))
    }

    /// The card row of a `삭제` id.
    #[must_use]
    pub fn remove_row(id: u16) -> Option<usize> {
        id.checked_sub(REMOVE_BASE)
            .filter(|offset| *offset < REMOVE_SPAN)
            .map(usize::from)
    }

    /// The card row of an `이름 바꾸기` id.
    #[must_use]
    pub fn rename_card_row(id: u16) -> Option<usize> {
        row_of(id, RENAME_CARD_BASE, RENAME_CARD_SPAN)
    }

    /// The card row of a `PIN 설정 / 기본값 변경` id.
    #[must_use]
    pub fn pins_row(id: u16) -> Option<usize> {
        id.checked_sub(PINS_BASE)
            .filter(|offset| *offset < PINS_SPAN)
            .map(usize::from)
    }

    /// The card row of a "백업 복사본" source id.
    #[must_use]
    pub fn backup_row(id: u16) -> Option<usize> {
        id.checked_sub(BACKUP_BASE)
            .filter(|offset| *offset < BACKUP_SPAN)
            .map(usize::from)
    }

    /// "`YubiKey` 연결하기 (복구 단어 없이)" in settings and the chain cards (spec/10 §7.6).
    pub const CONNECT_START: u16 = 13_500;
    /// The S01 entry of "`YubiKey` 연결하기" (a new `YubiKey` wallet).
    pub const CONNECT_NEW_WALLET: u16 = 13_501;
    /// `다시 읽기` of the connect scan.
    pub const CONNECT_RESCAN: u16 = 13_502;
    /// `다음` (choices → addresses).
    pub const CONNECT_NEXT: u16 = 13_503;
    /// `← 다시 고르기`.
    pub const CONNECT_BACK: u16 = 13_504;
    /// `PIN으로 소유 확인 (선택)`.
    pub const CONNECT_PIN: u16 = 13_505;
    /// `저장`.
    pub const CONNECT_SAVE: u16 = 13_506;
    /// Choice radios: row (found key) × [`CONNECT_CHOICES`] column.
    pub const CONNECT_CHOICE_BASE: u16 = 13_720;
    /// Ids per row.
    pub const CONNECT_CHOICE_STRIDE: u16 = 8;
    /// Rows: `OpenPGP` SIG + AUT and the 24 PIV slots.
    pub const CONNECT_CHOICE_ROWS: u16 = 26;
    /// Span of the choice radios.
    pub const CONNECT_CHOICE_SPAN: u16 = CONNECT_CHOICE_STRIDE * CONNECT_CHOICE_ROWS;
    /// The columns of a choice row.
    pub const CONNECT_CHOICES: [yw_engine::wallet::app_yubikey::connect::Choice; 7] = [
        yw_engine::wallet::app_yubikey::connect::Choice::Evm,
        yw_engine::wallet::app_yubikey::connect::Choice::Btc(ScriptType::P2wpkh),
        yw_engine::wallet::app_yubikey::connect::Choice::Btc(ScriptType::P2shP2wpkh),
        yw_engine::wallet::app_yubikey::connect::Choice::Btc(ScriptType::P2pkh),
        yw_engine::wallet::app_yubikey::connect::Choice::Zec,
        yw_engine::wallet::app_yubikey::connect::Choice::Sol,
        yw_engine::wallet::app_yubikey::connect::Choice::Skip,
    ];

    /// The id of `choice` on row `row`.
    #[must_use]
    pub fn connect_choice_id(
        row: usize,
        choice: yw_engine::wallet::app_yubikey::connect::Choice,
    ) -> u16 {
        let column = CONNECT_CHOICES
            .iter()
            .position(|other| *other == choice)
            .and_then(|column| u16::try_from(column).ok())
            .unwrap_or(0);
        let row = u16::try_from(row).unwrap_or(u16::MAX);
        CONNECT_CHOICE_BASE
            .saturating_add(row.saturating_mul(CONNECT_CHOICE_STRIDE))
            .saturating_add(column)
    }

    /// The row and choice of a choice radio id.
    #[must_use]
    pub fn connect_choice(
        id: u16,
    ) -> Option<(usize, yw_engine::wallet::app_yubikey::connect::Choice)> {
        let offset = id
            .checked_sub(CONNECT_CHOICE_BASE)
            .filter(|offset| *offset < CONNECT_CHOICE_SPAN)?;
        let choice = CONNECT_CHOICES
            .get(usize::from(offset % CONNECT_CHOICE_STRIDE))
            .copied()?;
        Some((usize::from(offset / CONNECT_CHOICE_STRIDE), choice))
    }

    /// Every fixed id of this module.
    pub const FIXED: &[u16] = &[
        SECTION_YUBIKEY,
        ENROL_START,
        NEW_WALLET,
        NEW_WALLET_START,
        NEW_WALLET_CANCEL,
        SIG_BASE,
        SIG_BASE + 1,
        SIG_BASE + 2,
        SIG_BASE + 3,
        SIG_INDEX_EDIT,
        SIG_BASE + 5,
        SIG_BASE + 6,
        SIG_BASE + 7,
        SIG_BASE + 8,
        SIG_BASE + 9,
        SIG_BASE + 10,
        SIG_BASE + 11,
        SIG_BASE + 12,
        SIG_BASE + 13,
        SIG_BASE + 14,
        AUT_BASE,
        AUT_BASE + 1,
        AUT_BASE + 2,
        AUT_BASE + 3,
        AUT_INDEX_EDIT,
        AUT_BASE + 5,
        AUT_BASE + 6,
        AUT_BASE + 7,
        AUT_BASE + 8,
        AUT_BASE + 9,
        AUT_BASE + 10,
        AUT_BASE + 11,
        AUT_BASE + 12,
        AUT_BASE + 13,
        AUT_BASE + 14,
        SOL_COUNT_EDIT,
        SOL_START_EDIT,
        PIV_TOUCH_ALWAYS,
        PIV_TOUCH_CACHED,
        SHARED_ACK,
        BACKUP_TOGGLE,
        PLAN_NEXT,
        WIZARD_CANCEL,
        SAME_ACK,
        CONFIRM_NEXT,
        CONFIRM_BACK,
        MGMT_DEFAULT,
        MGMT_CUSTOM,
        IMPORT,
        ADOPT,
        RECHECK,
        ANOTHER,
        FINISH,
        CHANGE_PW1,
        CHANGE_PW3,
        CHANGE_PIV_PIN,
        CHANGE_PUK,
        CHANGE_MGMT,
        CRED_BACK,
        RETRY,
        SET_PINS,
        PINS_UNIFIED,
        PINS_SEPARATE,
        PRESET_BASE,
        PRESET_BASE + 1,
        PRESET_BASE + 2,
        PRESET_BASE + 3,
        PRESET_BASE + 4,
        RESLOT_SIG_BASE,
        RESLOT_SIG_BASE + 1,
        RESLOT_SIG_BASE + 2,
        RESLOT_SIG_BASE + 3,
        RESLOT_SIG_INDEX_EDIT,
        RESLOT_SIG_BASE + 5,
        RESLOT_SIG_BASE + 6,
        RESLOT_SIG_BASE + 7,
        RESLOT_AUT_BASE,
        RESLOT_AUT_BASE + 1,
        RESLOT_AUT_BASE + 2,
        RESLOT_AUT_BASE + 3,
        RESLOT_AUT_INDEX_EDIT,
        RESLOT_AUT_BASE + 5,
        RESLOT_AUT_BASE + 6,
        RESLOT_AUT_BASE + 7,
        RESLOT_ZEC_MAIN,
        RESLOT_ZEC_TEST,
        RESLOT_ADVANCED,
        RESLOT_SHARED_ACK,
        RESLOT_REMOVED_ACK,
        RESLOT_NEXT,
        RESLOT_BACK,
        RESLOT_IMPORT,
        MANAGE_CANCEL,
        RESLOT_RETRY,
        MANAGE_DONE,
        CLEAR_PGP_TOGGLE,
        CLEAR_PIV_TOGGLE,
        CLEAR_PGP_OURS,
        CLEAR_PGP_RESET,
        CLEAR_PIV_OURS,
        CLEAR_PIV_RESET,
        CLEAR_CONFIRM_EDIT,
        CLEAR_RUN,
        IDENTIFY_AGAIN,
        PIN_NEEDED_OPEN,
        RESLOT_LOSS_ACK,
        RESLOT_LOSS_EDIT,
        CLEAR_LOSS_ACK,
        CLEAR_LOSS_EDIT,
        RESLOT_SAME_ACK,
        OVERWRITE_ACK,
        OVERWRITE_EDIT,
        CONNECT_START,
        CONNECT_NEW_WALLET,
        CONNECT_RESCAN,
        CONNECT_NEXT,
        CONNECT_BACK,
        CONNECT_PIN,
        CONNECT_SAVE,
        CLEAR_HOW,
        RESULT_DETAILS,
        PIN_GUIDE,
        RESLOT_PIN_NOW,
        CARD_NAME_SAVE,
        CARD_NAME_CANCEL,
        CARD_NAME_EDIT,
        CARD_NAME_CLEAR,
    ];

    /// The wizard and settings-tab press control `id` stands for (2026-11-18, S3 C11:
    /// `ui::cmd_table`). `None` when `id` is not one of `Wallet::on_yk`'s (the card actions' and
    /// the connect flow's ids are theirs, the edits are fields). An `OpenPGP` radio carries its
    /// slot and choice; each row range is claimed whole, as the ids reached the handler before.
    #[must_use]
    pub fn press_of(id: u16) -> Option<yw_engine::cmd::YkPress> {
        use yw_engine::cmd::{Row, YkPress};
        if let Some((key, action)) = pgp_action(id) {
            return Some(match action {
                PgpAction::Kind(kind) => YkPress::Pgp(key, kind),
                PgpAction::Script(script) => YkPress::PgpScript(key, script),
                PgpAction::Touch(touch) => YkPress::PgpTouch(key, touch),
                PgpAction::Zec(network) => YkPress::PgpZecNetwork(key, network),
            });
        }
        let row = |found: Option<usize>| found.and_then(|row| u16::try_from(row).ok()).map(Row);
        if let Some(row) = row(remove_row(id)) {
            return Some(YkPress::Remove(row));
        }
        if let Some(row) = row(rename_card_row(id)) {
            return Some(YkPress::RenameCard(row));
        }
        if let Some(row) = row(pins_row(id)) {
            return Some(YkPress::Pins(row));
        }
        if let Some(row) = row(backup_row(id)) {
            return Some(YkPress::Backup(row));
        }
        if let Some(row) = row(row_of(id, PIN_GATE_BASE, PIN_GATE_SPAN)) {
            return Some(YkPress::PinGate(row));
        }
        Some(match id {
            SECTION_YUBIKEY => YkPress::SectionYubikey,
            CARD_NAME_SAVE => YkPress::CardNameSave,
            CARD_NAME_CLEAR => YkPress::CardNameClear,
            CARD_NAME_CANCEL => YkPress::CardNameCancel,
            ENROL_START => YkPress::EnrolStart,
            NEW_WALLET => YkPress::NewWallet,
            NEW_WALLET_START => YkPress::NewWalletStart,
            NEW_WALLET_CANCEL => YkPress::NewWalletCancel,
            PIV_TOUCH_ALWAYS => YkPress::PivTouchAlways,
            PIV_TOUCH_CACHED => YkPress::PivTouchCached,
            SHARED_ACK => YkPress::SharedAck,
            BACKUP_TOGGLE => YkPress::BackupToggle,
            OVERWRITE_ACK => YkPress::OverwriteAck,
            PLAN_NEXT => YkPress::PlanNext,
            FINISH => YkPress::Finish,
            ANOTHER => YkPress::Another,
            WIZARD_CANCEL => YkPress::WizardCancel,
            RESULT_DETAILS => YkPress::ResultDetails,
            PIN_GUIDE => YkPress::PinGuide,
            IDENTIFY_AGAIN => YkPress::IdentifyAgain,
            PIN_NEEDED_OPEN => YkPress::PinNeededOpen,
            SAME_ACK => YkPress::SameAck,
            CONFIRM_BACK => YkPress::ConfirmBack,
            CONFIRM_NEXT => YkPress::ConfirmNext,
            RETRY => YkPress::Retry,
            CRED_BACK => YkPress::CredBack,
            MGMT_DEFAULT => YkPress::MgmtDefault,
            MGMT_CUSTOM => YkPress::MgmtCustom,
            IMPORT => YkPress::Import,
            ADOPT => YkPress::Adopt,
            RECHECK => YkPress::Recheck,
            CHANGE_PW1 => YkPress::ChangePw1,
            CHANGE_PW3 => YkPress::ChangePw3,
            CHANGE_PIV_PIN => YkPress::ChangePivPin,
            CHANGE_PUK => YkPress::ChangePuk,
            CHANGE_MGMT => YkPress::ChangeMgmt,
            SET_PINS => YkPress::SetPins,
            PINS_UNIFIED => YkPress::PinsUnified,
            PINS_SEPARATE => YkPress::PinsSeparate,
            _ => return None,
        })
    }

    /// The offset of a card-script radio in a slot's controls (`CARD_SCRIPTS` order, 5–7); a
    /// script the wizard does not draw falls on the index edit (4), as [`pgp_id`] and
    /// [`reslot_id`] place it.
    const fn script_offset(script: ScriptType) -> u16 {
        match script {
            ScriptType::P2wpkh => 5,
            ScriptType::P2shP2wpkh => 6,
            ScriptType::P2pkh => 7,
            ScriptType::P2tr => 4,
        }
    }

    /// The control id of a wizard press (the inverse of [`press_of`]).
    /// A value no screen draws (a Taproot radio, the `Never` touch radio, a row past its span)
    /// lands on another control's id (S3 C10–C12 review: listed in `ui::cmd_table`'s
    /// `c10_c12_payloads_round_trip_or_are_undrawn`; a press that arrives as data must refuse it).
    #[must_use]
    pub const fn id_of(press: yw_engine::cmd::YkPress) -> u16 {
        use yw_engine::cmd::{Row, YkPress};
        const fn pgp(key: PgpKey, offset: u16) -> u16 {
            match key {
                PgpKey::Sig => SIG_BASE.wrapping_add(offset),
                PgpKey::Aut => AUT_BASE.wrapping_add(offset),
            }
        }
        match press {
            YkPress::SectionYubikey => SECTION_YUBIKEY,
            YkPress::CardNameSave => CARD_NAME_SAVE,
            YkPress::CardNameClear => CARD_NAME_CLEAR,
            YkPress::CardNameCancel => CARD_NAME_CANCEL,
            YkPress::EnrolStart => ENROL_START,
            YkPress::NewWallet => NEW_WALLET,
            YkPress::NewWalletStart => NEW_WALLET_START,
            YkPress::NewWalletCancel => NEW_WALLET_CANCEL,
            YkPress::PivTouchAlways => PIV_TOUCH_ALWAYS,
            YkPress::PivTouchCached => PIV_TOUCH_CACHED,
            YkPress::SharedAck => SHARED_ACK,
            YkPress::BackupToggle => BACKUP_TOGGLE,
            YkPress::OverwriteAck => OVERWRITE_ACK,
            YkPress::PlanNext => PLAN_NEXT,
            YkPress::Finish => FINISH,
            YkPress::Another => ANOTHER,
            YkPress::WizardCancel => WIZARD_CANCEL,
            YkPress::ResultDetails => RESULT_DETAILS,
            YkPress::PinGuide => PIN_GUIDE,
            YkPress::IdentifyAgain => IDENTIFY_AGAIN,
            YkPress::PinNeededOpen => PIN_NEEDED_OPEN,
            YkPress::SameAck => SAME_ACK,
            YkPress::ConfirmBack => CONFIRM_BACK,
            YkPress::ConfirmNext => CONFIRM_NEXT,
            YkPress::Retry => RETRY,
            YkPress::CredBack => CRED_BACK,
            YkPress::MgmtDefault => MGMT_DEFAULT,
            YkPress::MgmtCustom => MGMT_CUSTOM,
            YkPress::Import => IMPORT,
            YkPress::Adopt => ADOPT,
            YkPress::Recheck => RECHECK,
            YkPress::ChangePw1 => CHANGE_PW1,
            YkPress::ChangePw3 => CHANGE_PW3,
            YkPress::ChangePivPin => CHANGE_PIV_PIN,
            YkPress::ChangePuk => CHANGE_PUK,
            YkPress::ChangeMgmt => CHANGE_MGMT,
            YkPress::SetPins => SET_PINS,
            YkPress::PinsUnified => PINS_UNIFIED,
            YkPress::PinsSeparate => PINS_SEPARATE,
            // `KINDS` order, Zcash at 12 (see `pgp_id`).
            YkPress::Pgp(key, PgpKind::None) => pgp(key, 0),
            YkPress::Pgp(key, PgpKind::Evm) => pgp(key, 1),
            YkPress::Pgp(key, PgpKind::Btc) => pgp(key, 2),
            YkPress::Pgp(key, PgpKind::Shared) => pgp(key, 3),
            YkPress::Pgp(key, PgpKind::Zec) => pgp(key, 12),
            YkPress::PgpScript(key, script) => pgp(key, script_offset(script)),
            // `PGP_TOUCH` order at 8–11; `Never` is not drawn (the index edit, as `pgp_id`).
            YkPress::PgpTouch(key, touch) => pgp(
                key,
                match touch {
                    TouchPolicy::Always => 8,
                    TouchPolicy::Cached => 9,
                    TouchPolicy::AlwaysFixed => 10,
                    TouchPolicy::CachedFixed => 11,
                    TouchPolicy::Never => 4,
                },
            ),
            YkPress::PgpZecNetwork(key, network) => pgp(
                key,
                match network {
                    ZecNetwork::Mainnet => 13,
                    ZecNetwork::Testnet => 14,
                },
            ),
            YkPress::Backup(Row(row)) => BACKUP_BASE.wrapping_add(row),
            YkPress::Remove(Row(row)) => REMOVE_BASE.wrapping_add(row),
            YkPress::RenameCard(Row(row)) => RENAME_CARD_BASE.wrapping_add(row),
            YkPress::Pins(Row(row)) => PINS_BASE.wrapping_add(row),
            YkPress::PinGate(Row(row)) => PIN_GATE_BASE.wrapping_add(row),
        }
    }

    /// The card-action press control `id` stands for (2026-11-18, S3 C11). `None` when `id` is
    /// not one of `Wallet::on_yk_manage_press`'s (the edits are fields); each row range is claimed whole.
    #[must_use]
    pub fn manage_press_of(id: u16) -> Option<yw_engine::cmd::YkManagePress> {
        use yw_engine::cmd::{Row, YkManagePress};
        let row = |found: Option<usize>| found.and_then(|row| u16::try_from(row).ok()).map(Row);
        if let Some(row) = row(reslot_row(id)) {
            return Some(YkManagePress::Reslot(row));
        }
        if let Some(row) = row(clear_row(id)) {
            return Some(YkManagePress::Clear(row));
        }
        if let Some(row) = row(reslot_backup_row(id)) {
            return Some(YkManagePress::ReslotBackup(row));
        }
        if let Some((key, action)) = reslot_action(id) {
            return Some(match action {
                ReslotAction::Chain(chain) => YkManagePress::ReslotChain(key, chain),
                ReslotAction::Script(script) => YkManagePress::ReslotScript(key, script),
            });
        }
        if let Some(preset) = preset(id) {
            return Some(YkManagePress::Preset(preset));
        }
        Some(match id {
            RESLOT_ZEC_MAIN => YkManagePress::ZecMain,
            RESLOT_ZEC_TEST => YkManagePress::ZecTest,
            RESLOT_ADVANCED => YkManagePress::Advanced,
            RESLOT_SHARED_ACK => YkManagePress::SharedAck,
            RESLOT_REMOVED_ACK => YkManagePress::RemovedAck,
            RESLOT_LOSS_ACK => YkManagePress::LossAck,
            RESLOT_SAME_ACK => YkManagePress::SameAck,
            CLEAR_LOSS_ACK => YkManagePress::ClearLossAck,
            RESLOT_NEXT => YkManagePress::Next,
            RESLOT_BACK => YkManagePress::Back,
            RESLOT_IMPORT => YkManagePress::Import,
            RESLOT_RETRY => YkManagePress::Retry,
            MANAGE_DONE => YkManagePress::Done,
            MANAGE_CANCEL => YkManagePress::Cancel,
            RESLOT_PIN_NOW => YkManagePress::PinNow,
            CLEAR_PGP_TOGGLE => YkManagePress::ClearPgpToggle,
            CLEAR_PIV_TOGGLE => YkManagePress::ClearPivToggle,
            CLEAR_PGP_OURS => YkManagePress::ClearPgpOurs,
            CLEAR_PGP_RESET => YkManagePress::ClearPgpReset,
            CLEAR_PIV_OURS => YkManagePress::ClearPivOurs,
            CLEAR_PIV_RESET => YkManagePress::ClearPivReset,
            CLEAR_RUN => YkManagePress::ClearRun,
            CLEAR_HOW => YkManagePress::ClearHow,
            _ => return None,
        })
    }

    /// The control id of a card-action press (the inverse of [`manage_press_of`]).
    /// A value no screen draws (a Taproot radio, the `Never` touch radio, a row past its span)
    /// lands on another control's id (S3 C10–C12 review: listed in `ui::cmd_table`'s
    /// `c10_c12_payloads_round_trip_or_are_undrawn`; a press that arrives as data must refuse it).
    #[must_use]
    pub const fn manage_id_of(press: yw_engine::cmd::YkManagePress) -> u16 {
        use yw_engine::cmd::{Row, YkManagePress};
        const fn slot(key: PgpKey, offset: u16) -> u16 {
            match key {
                PgpKey::Sig => RESLOT_SIG_BASE.wrapping_add(offset),
                PgpKey::Aut => RESLOT_AUT_BASE.wrapping_add(offset),
            }
        }
        match press {
            YkManagePress::Reslot(Row(row)) => RESLOT_BASE.wrapping_add(row),
            YkManagePress::Clear(Row(row)) => CLEAR_BASE.wrapping_add(row),
            YkManagePress::ReslotBackup(Row(row)) => RESLOT_BACKUP_BASE.wrapping_add(row),
            // `Chain::ALL` order.
            YkManagePress::ReslotChain(key, Chain::Evm) => slot(key, 0),
            YkManagePress::ReslotChain(key, Chain::Btc) => slot(key, 1),
            YkManagePress::ReslotChain(key, Chain::Zec) => slot(key, 2),
            YkManagePress::ReslotChain(key, Chain::Shared) => slot(key, 3),
            YkManagePress::ReslotScript(key, script) => slot(key, script_offset(script)),
            // `Preset::ALL` order.
            YkManagePress::Preset(Preset::EvmBtc) => PRESET_BASE,
            YkManagePress::Preset(Preset::EvmZec) => PRESET_BASE + 1,
            YkManagePress::Preset(Preset::BtcZec) => PRESET_BASE + 2,
            YkManagePress::Preset(Preset::EvmEvm) => PRESET_BASE + 3,
            YkManagePress::Preset(Preset::Custom) => PRESET_BASE + 4,
            YkManagePress::ZecMain => RESLOT_ZEC_MAIN,
            YkManagePress::ZecTest => RESLOT_ZEC_TEST,
            YkManagePress::Advanced => RESLOT_ADVANCED,
            YkManagePress::SharedAck => RESLOT_SHARED_ACK,
            YkManagePress::RemovedAck => RESLOT_REMOVED_ACK,
            YkManagePress::LossAck => RESLOT_LOSS_ACK,
            YkManagePress::SameAck => RESLOT_SAME_ACK,
            YkManagePress::ClearLossAck => CLEAR_LOSS_ACK,
            YkManagePress::Next => RESLOT_NEXT,
            YkManagePress::Back => RESLOT_BACK,
            YkManagePress::Import => RESLOT_IMPORT,
            YkManagePress::Retry => RESLOT_RETRY,
            YkManagePress::Done => MANAGE_DONE,
            YkManagePress::Cancel => MANAGE_CANCEL,
            YkManagePress::PinNow => RESLOT_PIN_NOW,
            YkManagePress::ClearPgpToggle => CLEAR_PGP_TOGGLE,
            YkManagePress::ClearPivToggle => CLEAR_PIV_TOGGLE,
            YkManagePress::ClearPgpOurs => CLEAR_PGP_OURS,
            YkManagePress::ClearPgpReset => CLEAR_PGP_RESET,
            YkManagePress::ClearPivOurs => CLEAR_PIV_OURS,
            YkManagePress::ClearPivReset => CLEAR_PIV_RESET,
            YkManagePress::ClearRun => CLEAR_RUN,
            YkManagePress::ClearHow => CLEAR_HOW,
        }
    }

    /// The connect-flow press control `id` stands for (2026-11-18, S3 C11). `None` when `id` is
    /// not one of `Wallet::on_yk_connect`'s; a choice radio carries its row and choice (the
    /// eighth id of a row is no radio and stays unclaimed, as before).
    #[must_use]
    pub fn connect_press_of(id: u16) -> Option<yw_engine::cmd::YkConnectPress> {
        use yw_engine::cmd::{Row, YkConnectPress};
        if let Some((row, choice)) = connect_choice(id) {
            let row = Row(u16::try_from(row).ok()?);
            return Some(YkConnectPress::Choice(row, choice));
        }
        Some(match id {
            CONNECT_START => YkConnectPress::Start,
            CONNECT_NEW_WALLET => YkConnectPress::NewWallet,
            CONNECT_RESCAN => YkConnectPress::Rescan,
            CONNECT_NEXT => YkConnectPress::Next,
            CONNECT_BACK => YkConnectPress::Back,
            CONNECT_PIN => YkConnectPress::Pin,
            CONNECT_SAVE => YkConnectPress::Save,
            _ => return None,
        })
    }

    /// The control id of a connect-flow press (the inverse of [`connect_press_of`]).
    /// A value no screen draws (a Taproot radio, the `Never` touch radio, a row past its span)
    /// lands on another control's id (S3 C10–C12 review: listed in `ui::cmd_table`'s
    /// `c10_c12_payloads_round_trip_or_are_undrawn`; a press that arrives as data must refuse it).
    #[must_use]
    pub const fn connect_id_of(press: yw_engine::cmd::YkConnectPress) -> u16 {
        use yw_engine::cmd::{Row, YkConnectPress};
        use yw_engine::wallet::app_yubikey::connect::Choice;
        // `CONNECT_CHOICES` order; a Bitcoin type the flow does not offer is column 0, as
        // `connect_choice_id` places it.
        const fn choice(Row(row): Row, column: u16) -> u16 {
            CONNECT_CHOICE_BASE
                .wrapping_add(row.wrapping_mul(CONNECT_CHOICE_STRIDE))
                .wrapping_add(column)
        }
        match press {
            YkConnectPress::Start => CONNECT_START,
            YkConnectPress::NewWallet => CONNECT_NEW_WALLET,
            YkConnectPress::Rescan => CONNECT_RESCAN,
            YkConnectPress::Next => CONNECT_NEXT,
            YkConnectPress::Back => CONNECT_BACK,
            YkConnectPress::Pin => CONNECT_PIN,
            YkConnectPress::Save => CONNECT_SAVE,
            YkConnectPress::Choice(row, Choice::Evm) => choice(row, 0),
            YkConnectPress::Choice(row, Choice::Btc(script)) => choice(
                row,
                match script {
                    ScriptType::P2wpkh => 1,
                    ScriptType::P2shP2wpkh => 2,
                    ScriptType::P2pkh => 3,
                    ScriptType::P2tr => 0,
                },
            ),
            YkConnectPress::Choice(row, Choice::Zec) => choice(row, 4),
            YkConnectPress::Choice(row, Choice::Sol) => choice(row, 5),
            YkConnectPress::Choice(row, Choice::Skip) => choice(row, 6),
        }
    }
}
