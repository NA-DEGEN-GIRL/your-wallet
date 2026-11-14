//! `YubiKey` screens (spec/04 §2.19, spec/10 §7): the S01 card `YubiKey에 키 보관`, S20 (the new
//! `YubiKey` wallet), S21 the enrolment wizard (keys and slots, confirmation with every path and
//! address, credentials, result with "다시 확인" and the defaults change), settings → `YubiKey`
//! (the enrolled cards, their slots, which cards hold each account, `삭제`) and the removal
//! overlay. Fixed sentences are the T-YK-* rows of spec/04 §2.16.

use yw_core::btc::ScriptType;
use yw_core::lang::{Lang, Text};
use yw_core::yubikey::plan::{
    CardSlot, KeyRole, MAX_CARDS, PgpKey, PinPolicy, TouchPolicy, accounts, address_texts,
};
use yw_core::yubikey::record::HwKeyRecord;
use yw_core::zec::ZecNetwork;

use crate::app::{App, AppMode};
use crate::app_yubikey::text as yk;
use crate::app_yubikey::{
    CARD_SCRIPTS, MAX_ACCOUNT_INDEX, PGP_TOUCH, PIV_TOUCH, PgpKind, WizardOrigin, WizardStep,
    YkWizard,
};
use crate::ui::main_window::{Ctl, Item, Tone};
use text as t;

mod connect;
mod manage;
pub mod text;

/// Command ids (block 13,200–13,399, and 13,500–13,506 and 13,720–13,927 for "`YubiKey` 연결하기";
/// `ui::command_ids`).
pub mod ids {
    use yw_core::btc::ScriptType;
    use yw_core::yubikey::plan::{PgpKey, TouchPolicy};
    use yw_core::zec::ZecNetwork;

    use crate::app_yubikey::manage::{Chain, Preset};
    use crate::app_yubikey::{CARD_SCRIPTS, PGP_TOUCH, PgpKind};

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

    /// What an `OpenPGP` slot control sets.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PgpAction {
        /// The kind radio.
        Kind(PgpKind),
        /// The address-type radio.
        Script(ScriptType),
        /// The touch radio.
        Touch(TouchPolicy),
        /// The Zcash network radio.
        Zec(ZecNetwork),
    }

    /// What a re-slot slot control sets.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ReslotAction {
        /// The chain radio.
        Chain(Chain),
        /// The address-type radio.
        Script(ScriptType),
    }

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
    pub const CONNECT_CHOICES: [crate::app_yubikey::connect::Choice; 7] = [
        crate::app_yubikey::connect::Choice::Evm,
        crate::app_yubikey::connect::Choice::Btc(ScriptType::P2wpkh),
        crate::app_yubikey::connect::Choice::Btc(ScriptType::P2shP2wpkh),
        crate::app_yubikey::connect::Choice::Btc(ScriptType::P2pkh),
        crate::app_yubikey::connect::Choice::Zec,
        crate::app_yubikey::connect::Choice::Sol,
        crate::app_yubikey::connect::Choice::Skip,
    ];

    /// The id of `choice` on row `row`.
    #[must_use]
    pub fn connect_choice_id(row: usize, choice: crate::app_yubikey::connect::Choice) -> u16 {
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
    pub fn connect_choice(id: u16) -> Option<(usize, crate::app_yubikey::connect::Choice)> {
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
    ];
}

/// T-YK-MNEMONIC-WALLET, Korean (tests).
#[cfg(test)]
pub const T_YK_MNEMONIC_WALLET: &str = t::YK_MNEMONIC_WALLET.ko;

/// The wizard's step labels (S21).
pub const WIZARD_STEPS: [Text; 4] = [
    t::STEP_PLAN,
    t::STEP_CONFIRM,
    t::STEP_CREDENTIALS,
    t::STEP_RESULT,
];
/// The new `YubiKey` wallet's five steps (S20, its secret windows' head, the wizard's head and
/// the result's PIN card; 2026-11-10 — it said n/3 and seemed to end at the backup check).
pub const YK_WALLET_STEPS: [Text; 5] = [
    t::STEP_PASSWORD,
    t::STEP_WRITE_WORDS,
    t::STEP_BACKUP_CHECK,
    t::STEP_PUT_ON_CARD,
    t::STEP_SET_PIN,
];
/// T-YK-PIN-GUIDE (spec/10 §9.3): what each card secret is for.
pub const T_YK_PIN_GUIDE: [Text; 5] = [
    t::PIN_GUIDE_PW1,
    t::PIN_GUIDE_PW3,
    t::PIN_GUIDE_PIV_PIN,
    t::PIN_GUIDE_PUK,
    t::PIN_GUIDE_MANAGEMENT,
];

/// A step indicator of `labels` in `lang` (`current` 1-based, 0 for none).
fn steps_item(lang: Lang, labels: &[Text], current: usize) -> Item {
    Item::Steps(
        labels
            .iter()
            .map(|label| label.get(lang).to_owned())
            .collect(),
        current,
    )
}

const fn touch_label(lang: Lang, touch: TouchPolicy) -> &'static str {
    match touch {
        TouchPolicy::Never => t::TOUCH_NEVER,
        TouchPolicy::Always => t::TOUCH_ALWAYS,
        TouchPolicy::Cached => t::TOUCH_CACHED,
        TouchPolicy::AlwaysFixed => t::TOUCH_ALWAYS_FIXED,
        TouchPolicy::CachedFixed => t::TOUCH_CACHED_FIXED,
    }
    .get(lang)
}

const fn kind_label(lang: Lang, kind: PgpKind) -> &'static str {
    match kind {
        PgpKind::None => t::KIND_NONE,
        PgpKind::Evm => t::KIND_EVM,
        PgpKind::Btc => t::KIND_BTC,
        PgpKind::Shared => t::KIND_SHARED,
        PgpKind::Zec => t::KIND_ZEC,
    }
    .get(lang)
}

/// "메인넷 (t1…)" / "테스트넷 (tm…)".
#[must_use]
pub const fn zec_network_label(lang: Lang, network: ZecNetwork) -> &'static str {
    match network {
        ZecNetwork::Mainnet => t::ZEC_MAINNET,
        ZecNetwork::Testnet => t::ZEC_TESTNET,
    }
    .get(lang)
}

fn script_label(lang: Lang, script: ScriptType) -> String {
    format!("{} ({})", script.name_in(lang), script.technical())
}

/// One slot's lines: label and title, path, address(es), policies.
/// A slot address in 4-character groups like every other screen (spec/04 §3.3): an EVM address
/// in its checksum groups, a Bitcoin or Solana address as encoded, every character shown.
fn grouped_address(address: &str) -> String {
    yw_core::evm::address::parse_address(address).map_or_else(
        |_| crate::ui::screens_btc::grouped(address),
        |parsed| yw_core::evm::display::format_address(&parsed),
    )
}

fn slot_items(
    lang: Lang,
    (slot, role): (CardSlot, KeyRole),
    touch: TouchPolicy,
    pin: PinPolicy,
    addresses: &[String],
    items: &mut Vec<Item>,
) {
    items.push(Item::Subtitle(format!(
        "{} — {}",
        slot.label_in(lang),
        role.title_in(lang)
    )));
    items.push(Item::Field(
        t::FIELD_PATH.get(lang).to_owned(),
        role.path_text_in(lang),
    ));
    for address in addresses {
        items.push(Item::Mono(grouped_address(address)));
    }
    let touch = touch_label(lang, touch);
    let policy = match pin {
        PinPolicy::NotApplicable => t::POLICY_TOUCH.fill(lang, [touch]),
        PinPolicy::Once => t::POLICY_TOUCH_SESSION.fill(lang, [touch]),
        PinPolicy::Always => t::POLICY_TOUCH_EVERY.fill(lang, [touch]),
    };
    items.push(Item::Field(t::FIELD_POLICY.get(lang).to_owned(), policy));
}

impl App {
    /// S20: what the new `YubiKey` wallet is, before W01.
    pub fn yk_wallet_intro(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Title(t::TITLE_YK_WALLET.get(lang).to_owned()));
        items.push(steps_item(lang, &YK_WALLET_STEPS, 0));
        items.push(Item::CardStart(Some(t::BEFORE_START.get(lang).to_owned())));
        for line in [
            t::INTRO_PAPER,
            t::INTRO_NOT_STORED,
            t::INTRO_CHECK,
            t::INTRO_BACKUP,
            t::INTRO_ADMIN_PIN,
            t::INTRO_TIME,
        ] {
            items.push(Item::Text(line.get(lang).to_owned()));
        }
        items.push(Item::Banner(t::INTRO_WARN.get(lang).to_owned(), Tone::Warn));
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::primary(ids::NEW_WALLET_START, t::BTN_START.get(lang)),
            Ctl::button(ids::NEW_WALLET_CANCEL, t::BTN_CANCEL.get(lang)),
        ]));
    }

    /// Settings → `YubiKey`.
    #[expect(
        clippy::too_many_lines,
        reason = "one card per enrolled YubiKey / slot form"
    )]
    pub fn yk_settings_section(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        if unlocked && let Some(manage) = self.card.manage.as_ref() {
            self.yk_manage_items(manage, items);
            return;
        }
        let records = &self.card.records;
        items.push(Item::CardStart(Some(
            t::CARD_YK_ACCOUNTS.get(lang).to_owned(),
        )));
        items.push(Item::Text(t::YK_LIST.get(lang).to_owned()));
        if self.keys.has_mnemonic {
            items.push(Item::Help(t::YK_MNEMONIC_WALLET.get(lang).to_owned()));
        }
        items.push(Item::Row(vec![
            Ctl::primary(ids::ENROL_START, t::BTN_ENROL.get(lang))
                .enabled(unlocked && records.len() < MAX_CARDS),
            Ctl::button(ids::CONNECT_START, t::BTN_CONNECT.get(lang))
                .enabled(unlocked && records.len() < MAX_CARDS),
        ]));
        items.push(Item::Help(
            crate::app_yubikey::connect::text::YK_CONNECT
                .get(lang)
                .to_owned(),
        ));
        if !unlocked {
            items.push(Item::Help(t::UNLOCK_TO_USE.get(lang).to_owned()));
        }
        items.push(Item::CardEnd);
        let defaults = self
            .meta
            .as_ref()
            .map(|meta| meta.hw_accounts.defaults.clone())
            .unwrap_or_default();
        for (row, record) in records.iter().enumerate() {
            items.push(Item::CardStart(Some(format!("YubiKey #{}", record.serial))));
            // A card on its factory PINs does not sign: said first, and `PIN 설정` is the card's
            // main button (2026-11-10).
            let factory = defaults.contains(&record.serial);
            if factory {
                items.push(Item::Banner(
                    t::FACTORY_BAND.get(lang).to_owned(),
                    Tone::Warn,
                ));
            }
            items.push(Item::Field(
                t::FIELD_FIRMWARE.get(lang).to_owned(),
                record.firmware.to_string(),
            ));
            items.push(Item::Field(
                t::FIELD_SLOTS.get(lang).to_owned(),
                t::COUNT.fill(lang, [&record.slots.len().to_string()]),
            ));
            for slot in &record.slots {
                slot_items(
                    lang,
                    (slot.slot, slot.role),
                    slot.touch,
                    slot.pin,
                    &address_texts(slot.role, &slot.public).unwrap_or_default(),
                    items,
                );
            }
            let row_id = u16::try_from(row).unwrap_or(u16::MAX);
            let open = self.card.pin_serial == Some(record.serial);
            let pins_label = match (open, factory) {
                (true, _) => t::BTN_PINS_CLOSE,
                (false, true) => t::BTN_SET_PIN,
                (false, false) => t::BTN_PINS_CHANGE,
            }
            .get(lang);
            // Everyday actions first; the two destructive ones on their own row, named by what
            // they erase (2026-11-08: `삭제` / `YubiKey 비우기` did not say which one touches
            // the card).
            items.push(Item::Row(vec![
                if factory && !open {
                    Ctl::primary(ids::PINS_BASE.saturating_add(row_id), pins_label)
                } else {
                    Ctl::button(ids::PINS_BASE.saturating_add(row_id), pins_label)
                }
                .enabled(unlocked),
                Ctl::button(
                    ids::RESLOT_BASE.saturating_add(row_id),
                    t::BTN_RESLOT.get(lang),
                )
                .enabled(unlocked),
            ]));
            items.push(Item::Help(t::DANGER.get(lang).to_owned()));
            let removable = self.yk_can_remove();
            items.push(Item::Row(vec![
                Ctl::danger(
                    ids::REMOVE_BASE.saturating_add(row_id),
                    t::BTN_REMOVE_RECORD.get(lang),
                )
                .enabled(unlocked && removable),
                Ctl::danger(
                    ids::CLEAR_BASE.saturating_add(row_id),
                    t::BTN_ERASE_KEYS.get(lang),
                )
                .enabled(unlocked),
            ]));
            if unlocked && !removable {
                items.push(Item::Help(t::LAST_KEY.get(lang).to_owned()));
            }
            items.push(Item::CardEnd);
            if open && unlocked {
                self.yk_pin_items(record.serial, items);
            }
        }
        if !records.is_empty() {
            items.push(Item::CardStart(Some(
                t::CARD_PER_ACCOUNT.get(lang).to_owned(),
            )));
            for account in accounts(records) {
                let holders: Vec<String> = account
                    .holders
                    .iter()
                    .enumerate()
                    .map(|(position, holder)| {
                        let name = match holder.slot {
                            CardSlot::OpenPgp(PgpKey::Sig) => "SIG".to_owned(),
                            CardSlot::OpenPgp(PgpKey::Aut) => "AUT".to_owned(),
                            CardSlot::Piv(slot) => format!("PIV {:02x}", slot.id()),
                        };
                        if position == 0 {
                            format!("#{} {name}", holder.serial)
                        } else {
                            t::HOLDER_BACKUP.fill(lang, [&holder.serial.to_string(), &name])
                        }
                    })
                    .collect();
                items.push(Item::Text(format!(
                    "{} ({}) — {}",
                    account.role.title_in(lang),
                    account.role.path_text_in(lang),
                    holders.join(", ")
                )));
            }
            items.push(Item::CardEnd);
        }
    }

    /// S21: the wizard at its step.
    pub fn yk_wizard_screen(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let Some(wizard) = self.card.wizard.as_ref() else {
            items.push(Item::Muted(t::WIZARD_DONE.get(lang).to_owned()));
            items.push(crate::ui::screens::back_main(lang));
            return;
        };
        if let Some(form) = wizard.connect.as_deref() {
            self.yk_connect_screen(wizard, form, items);
            return;
        }
        if wizard.origin == WizardOrigin::NewWallet && !wizard.created {
            // Steps 1–3 were the secret windows (2026-11-10).
            items.push(Item::Help(t::STEP_4_OF_5.get(lang).to_owned()));
        }
        items.push(Item::Title(
            match wizard.origin {
                WizardOrigin::NewWallet => t::TITLE_NEW_WALLET_ENROL,
                WizardOrigin::Vault => t::BTN_ENROL,
            }
            .get(lang)
            .to_owned(),
        ));
        let current = match wizard.step {
            WizardStep::Plan => 1,
            WizardStep::Confirm => 2,
            WizardStep::Credentials | WizardStep::Running => 3,
            WizardStep::Result => 4,
        };
        items.push(steps_item(lang, &WIZARD_STEPS, current));
        match wizard.step {
            WizardStep::Plan => self.yk_plan_items(wizard, items),
            WizardStep::Confirm => self.yk_confirm_items(wizard, items),
            WizardStep::Credentials => self.yk_credentials_items(wizard, items),
            WizardStep::Running => {
                items.push(Item::CardStart(None));
                items.push(Item::Subtitle(t::RUNNING_IMPORT.get(lang).to_owned()));
                items.push(Item::Text(t::RUNNING_KEEP.get(lang).to_owned()));
                items.push(Item::CardEnd);
            }
            WizardStep::Result => self.yk_result_items(wizard, items),
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one card per enrolled YubiKey / slot form"
    )]
    fn yk_pgp_items(&self, wizard: &YkWizard, key: PgpKey, items: &mut Vec<Item>) {
        use ids::PgpAction;
        let lang = self.settings.language;
        let form = wizard.pgp(key);
        items.push(Item::CardStart(Some(CardSlot::OpenPgp(key).label_in(lang))));
        items.push(Item::LabeledRow(
            t::LABEL_KEY.get(lang).to_owned(),
            [
                PgpKind::None,
                PgpKind::Evm,
                PgpKind::Btc,
                PgpKind::Zec,
                PgpKind::Shared,
            ]
            .into_iter()
            .enumerate()
            .map(|(position, kind)| {
                Ctl::radio(
                    ids::pgp_id(key, PgpAction::Kind(kind)),
                    kind_label(lang, kind),
                    form.kind == kind,
                    position == 0,
                )
            })
            .collect(),
        ));
        if form.kind == PgpKind::None {
            items.push(Item::CardEnd);
            return;
        }
        let edit = match key {
            PgpKey::Sig => ids::SIG_INDEX_EDIT,
            PgpKey::Aut => ids::AUT_INDEX_EDIT,
        };
        let max = MAX_ACCOUNT_INDEX.to_string();
        items.push(Item::LabeledRow(
            if matches!(form.kind, PgpKind::Btc | PgpKind::Zec) {
                t::LABEL_ADDRESS_INDEX.fill(lang, [&max])
            } else {
                t::LABEL_ACCOUNT_INDEX.fill(lang, [&max])
            },
            vec![Ctl::edit(edit, &form.index_text, 80, false, 3)],
        ));
        if matches!(form.kind, PgpKind::Btc | PgpKind::Shared) {
            items.push(Item::LabeledRow(
                t::LABEL_ADDRESS_TYPE.fill(lang, [self.yk_network().display_name_in(lang)]),
                CARD_SCRIPTS
                    .into_iter()
                    .enumerate()
                    .map(|(position, script)| {
                        Ctl::radio(
                            ids::pgp_id(key, PgpAction::Script(script)),
                            &script_label(lang, script),
                            form.script == script,
                            position == 0,
                        )
                    })
                    .collect(),
            ));
        }
        if form.kind == PgpKind::Zec {
            items.push(Item::LabeledRow(
                t::LABEL_ZEC_NETWORK.get(lang).to_owned(),
                [ZecNetwork::Mainnet, ZecNetwork::Testnet]
                    .into_iter()
                    .enumerate()
                    .map(|(position, network)| {
                        Ctl::radio(
                            ids::pgp_id(key, PgpAction::Zec(network)),
                            zec_network_label(lang, network),
                            form.zec == network,
                            position == 0,
                        )
                    })
                    .collect(),
            ));
        }
        items.push(Item::LabeledRow(
            t::LABEL_TOUCH.get(lang).to_owned(),
            PGP_TOUCH
                .into_iter()
                .enumerate()
                .map(|(position, touch)| {
                    Ctl::radio(
                        ids::pgp_id(key, PgpAction::Touch(touch)),
                        touch_label(lang, touch),
                        form.touch == touch,
                        position == 0,
                    )
                })
                .collect(),
        ));
        if let Ok(Some(slot)) = YkWizard::pgp_preview(lang, form, key, self.yk_network()) {
            items.push(Item::Help(
                t::PATH_LINE.fill(lang, [&slot.role.path_text_in(lang)]),
            ));
            if let KeyRole::Btc { index, .. } = slot.role
                && index >= 20
            {
                items.push(Item::Help(t::GAP_LIMIT.get(lang).to_owned()));
            }
        }
        items.push(Item::Help(t::FIXED_TOUCH.get(lang).to_owned()));
        if form.kind == PgpKind::Shared {
            items.push(Item::Banner(yk::YK_SHARED.get(lang).to_owned(), Tone::Warn));
        }
        items.push(Item::CardEnd);
    }

    /// The "백업 복사본" card of the plan screen (the enrolled cards to copy).
    fn yk_backup_items(&self, wizard: &YkWizard, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let records = &self.card.records;
        if !records.is_empty() {
            items.push(Item::CardStart(Some(t::BACKUP_COPY.get(lang).to_owned())));
            items.push(Item::Row(vec![Ctl::check(
                ids::BACKUP_TOGGLE,
                t::CHECK_BACKUP.get(lang),
                wizard.backup_of.is_some(),
            )]));
            items.push(Item::Help(t::BACKUP_HELP.get(lang).to_owned()));
            if let Some(serial) = wizard.backup_of {
                // Only cards with a known path can be copied from words (spec/10 §7.6); the
                // radio keeps the record's row as its id.
                items.push(Item::LabeledRow(
                    t::LABEL_COPY_FROM.get(lang).to_owned(),
                    records
                        .iter()
                        .enumerate()
                        .filter(|(_, record)| record.has_known_path())
                        .enumerate()
                        .map(|(position, (row, record))| {
                            Ctl::radio(
                                ids::BACKUP_BASE
                                    .saturating_add(u16::try_from(row).unwrap_or(u16::MAX)),
                                &t::BACKUP_OPTION.fill(
                                    lang,
                                    [&record.serial.to_string(), &record.slots.len().to_string()],
                                ),
                                record.serial == serial,
                                position == 0,
                            )
                        })
                        .collect(),
                ));
                if records.iter().any(|record| !record.has_known_path()) {
                    items.push(Item::Help(yk::YK_BACKUP_UNKNOWN.get(lang).to_owned()));
                }
                if let Some(record) = records.iter().find(|record| record.serial == serial) {
                    for slot in record.slots.iter().filter(|slot| slot.path_known) {
                        items.push(Item::Text(format!(
                            "{} — {} ({})",
                            slot.slot.label_in(lang),
                            slot.role.title_in(lang),
                            slot.role.path_text_in(lang)
                        )));
                    }
                    let skipped: Vec<String> = record
                        .slots
                        .iter()
                        .filter(|slot| !slot.path_known)
                        .map(|slot| {
                            format!(
                                "{} — {}",
                                slot.slot.label_in(lang),
                                slot.role.title_in(lang)
                            )
                        })
                        .collect();
                    if !skipped.is_empty() {
                        items.push(Item::Help(
                            t::SKIPPED_UNKNOWN.fill(lang, [&skipped.join(", ")]),
                        ));
                    }
                }
                items.push(Item::Help(t::BACKUP_SAME.get(lang).to_owned()));
            }
            items.push(Item::CardEnd);
        }
    }

    fn yk_plan_items(&self, wizard: &YkWizard, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        if wizard.origin == WizardOrigin::NewWallet {
            items.push(Item::Banner(
                t::WORDS_CHECKED.get(lang).to_owned(),
                Tone::Success,
            ));
        }
        if self.card.records.is_empty() {
            // The defaults of a first card (`YkWizard::new`, spec/10 §3.1), 2026-11-10.
            items.push(Item::Text(
                t::FIRST_DEFAULTS.fill(lang, [self.yk_network().display_name_in(lang)]),
            ));
        }
        self.yk_backup_items(wizard, items);
        if wizard.backup_of.is_none() {
            self.yk_pgp_items(wizard, PgpKey::Sig, items);
            self.yk_pgp_items(wizard, PgpKey::Aut, items);
            if wizard.uses_shared() {
                items.push(Item::Row(vec![Ctl::check(
                    ids::SHARED_ACK,
                    t::SHARED_ACK.get(lang),
                    wizard.shared_ack,
                )]));
            }
            items.push(Item::CardStart(Some(t::CARD_PIV_SOL.get(lang).to_owned())));
            items.push(Item::LabeledRow(
                t::LABEL_SOL_COUNT.get(lang).to_owned(),
                vec![Ctl::edit(
                    ids::SOL_COUNT_EDIT,
                    &wizard.sol_count_text,
                    80,
                    false,
                    2,
                )],
            ));
            items.push(Item::LabeledRow(
                t::LABEL_FIRST_INDEX.get(lang).to_owned(),
                vec![Ctl::edit(
                    ids::SOL_START_EDIT,
                    &wizard.sol_start_text,
                    80,
                    false,
                    3,
                )],
            ));
            items.push(Item::LabeledRow(
                t::LABEL_TOUCH.get(lang).to_owned(),
                PIV_TOUCH
                    .into_iter()
                    .enumerate()
                    .map(|(position, touch)| {
                        Ctl::radio(
                            if position == 0 {
                                ids::PIV_TOUCH_ALWAYS
                            } else {
                                ids::PIV_TOUCH_CACHED
                            },
                            touch_label(lang, touch),
                            wizard.piv_touch == touch,
                            position == 0,
                        )
                    })
                    .collect(),
            ));
            items.push(Item::Help(t::PIV_HELP.get(lang).to_owned()));
            items.push(Item::Help(yk::YK_PIV_FIRMWARE.get(lang).to_owned()));
            items.push(Item::CardEnd);
        }
        if let Some(error) = &wizard.error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        items.push(Item::Row(vec![
            Ctl::primary(
                ids::PLAN_NEXT,
                if wizard.seed_held {
                    t::BTN_NEXT_CONFIRM
                } else {
                    t::BTN_NEXT_WORDS
                }
                .get(lang),
            ),
            Ctl::button(ids::WIZARD_CANCEL, t::BTN_CANCEL.get(lang)),
        ]));
    }

    fn yk_confirm_items(&self, wizard: &YkWizard, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let Some(preview) = wizard.preview.as_ref() else {
            items.push(Item::CardStart(None));
            items.push(Item::Subtitle(t::CHECKING.get(lang).to_owned()));
            items.push(Item::Text(t::COMPUTING.get(lang).to_owned()));
            items.push(Item::CardEnd);
            items.push(Item::Row(vec![
                Ctl::button(ids::CONFIRM_BACK, t::BTN_BACK_SLOTS.get(lang)),
                Ctl::button(ids::WIZARD_CANCEL, t::BTN_CANCEL.get(lang)),
            ]));
            return;
        };
        if preview.same_as_vault {
            items.push(Item::Banner(
                if preview.words_only {
                    yk::YK_SAME_WORDS
                } else {
                    yk::YK_SAME
                }
                .get(lang)
                .to_owned(),
                Tone::HighRisk,
            ));
            items.push(Item::Row(vec![Ctl::check(
                ids::SAME_ACK,
                t::SAME_ACK.get(lang),
                wizard.same_ack,
            )]));
        }
        if let Err(error) = preview.plan {
            items.push(Item::Banner(error.text_in(lang), Tone::Danger));
        }
        items.push(Item::CardStart(Some(
            t::CARD_CHECK_IMPORT.get(lang).to_owned(),
        )));
        items.push(Item::Text(t::CONFIRM_TEXT.get(lang).to_owned()));
        for line in &preview.lines {
            let planned = line.planned;
            slot_items(
                lang,
                (planned.slot, planned.role),
                planned.touch,
                planned.pin,
                &line.addresses,
                items,
            );
            let holders = crate::yubikey::holders(&self.card.records, planned.role);
            let relation = if holders.is_empty() {
                t::RELATION_NEW.get(lang).to_owned()
            } else {
                let list: Vec<String> = holders.iter().map(|serial| format!("#{serial}")).collect();
                let kind = if planned.backup_copy {
                    t::BACKUP_COPY
                } else {
                    t::RELATION_ALREADY
                };
                t::RELATION.fill(lang, [kind.get(lang), &list.join(", ")])
            };
            items.push(Item::Field(
                t::FIELD_RELATION.get(lang).to_owned(),
                relation,
            ));
        }
        Self::yk_card_items(lang, wizard, items);
        items.push(Item::CardEnd);
        if wizard.applets().1 {
            items.push(Item::Help(yk::YK_PIV_FIRMWARE.get(lang).to_owned()));
        }
        items.push(Item::Help(yk::YK_OVERWRITE.get(lang).to_owned()));
        items.push(Item::Row(vec![
            Ctl::primary(ids::CONFIRM_NEXT, t::BTN_NEXT.get(lang)).enabled(wizard.can_continue()),
            Ctl::button(ids::CONFIRM_BACK, t::BTN_BACK_SLOTS.get(lang)),
            Ctl::button(ids::WIZARD_CANCEL, t::BTN_CANCEL.get(lang)),
        ]));
    }

    /// The card the wizard enrols (spec/10 §7.3: one card only, identified read-only).
    fn yk_card_items(lang: Lang, wizard: &YkWizard, items: &mut Vec<Item>) {
        let line = match (&wizard.card, &wizard.card_error) {
            (Some(card), _) => {
                t::CARD_LINE.fill(lang, [&card.serial.to_string(), &card.firmware.to_string()])
            }
            (None, Some(error)) => error.clone(),
            (None, None) => t::READING_CARD.get(lang).to_owned(),
        };
        items.push(Item::Field(t::CONNECTED_CARD.get(lang).to_owned(), line));
        if wizard.card.is_none() && wizard.card_error.is_some() {
            items.push(Item::Row(vec![Ctl::button(
                ids::IDENTIFY_AGAIN,
                t::BTN_READ_AGAIN.get(lang),
            )]));
        }
    }

    /// The keys of the identified card's planned slots an import would destroy (spec/10 §7.4):
    /// each slot with its key's addresses (a secp256k1 key as an EVM and a Bitcoin P2WPKH
    /// address, an Ed25519 key as a Solana address), T-YK-OCCUPIED, its checkbox and the typed
    /// `영구 삭제`.
    fn yk_occupied_items(&self, wizard: &YkWizard, items: &mut Vec<Item>) {
        use yw_core::yubikey::record::HwPublicKey;
        let lang = self.settings.language;
        match &wizard.occupied {
            None if wizard.card.is_some() => {
                items.push(Item::Help(t::READING_SLOTS.get(lang).to_owned()));
            }
            Some(Err(error)) => {
                items.push(Item::Help(t::SLOTS_UNREADABLE.fill(lang, [error])));
            }
            Some(Ok(occupants)) if !occupants.is_empty() => {
                items.push(Item::Banner(
                    yk::YK_OCCUPIED.get(lang).to_owned(),
                    Tone::HighRisk,
                ));
                let shared = KeyRole::Evm {
                    index: yw_core::bip32::path::AccountIndex::ZERO,
                    btc: Some(yw_core::yubikey::plan::BtcUse {
                        network: self.yk_network(),
                        script: ScriptType::P2wpkh,
                    }),
                };
                for occupant in occupants {
                    let (kind, addresses) = match occupant.public {
                        Some(public @ HwPublicKey::Secp256k1(_)) => (
                            t::OCCUPANT_SECP.get(lang),
                            address_texts(shared, &public).unwrap_or_default(),
                        ),
                        Some(public @ HwPublicKey::Ed25519(_)) => (
                            t::OCCUPANT_ED.get(lang),
                            address_texts(
                                KeyRole::Sol {
                                    index: yw_core::bip32::path::AccountIndex::ZERO,
                                },
                                &public,
                            )
                            .unwrap_or_default(),
                        ),
                        None => (t::OCCUPANT_UNKNOWN.get(lang), Vec::new()),
                    };
                    items.push(Item::Subtitle(format!(
                        "{} — {kind}",
                        occupant.slot.label_in(lang)
                    )));
                    for address in addresses {
                        items.push(Item::Mono(grouped_address(&address)));
                    }
                }
                items.push(Item::Row(vec![Ctl::check(
                    ids::OVERWRITE_ACK,
                    yk::YK_OCCUPIED_ACK.get(lang),
                    wizard.overwrite_ack,
                )]));
                items.push(Item::LabeledRow(
                    t::TYPE_WORD.fill(
                        lang,
                        [crate::app_yubikey::manage::text::LOSS_WORD.get(lang)],
                    ),
                    vec![Ctl::edit(
                        ids::OVERWRITE_EDIT,
                        &wizard.overwrite_typed,
                        120,
                        false,
                        8,
                    )],
                ));
            }
            _ => {}
        }
    }

    fn yk_credentials_items(&self, wizard: &YkWizard, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let (pgp, piv) = wizard.applets();
        items.push(Item::CardStart(Some(
            t::CARD_CREDENTIALS.get(lang).to_owned(),
        )));
        items.push(Item::Text(t::CREDENTIALS_TEXT.get(lang).to_owned()));
        Self::yk_card_items(lang, wizard, items);
        if pgp {
            items.push(Item::Field(
                "OpenPGP".to_owned(),
                t::CREDENTIALS_PW3.get(lang).to_owned(),
            ));
        }
        if let Some(card) = wizard.card {
            let mut kinds = Vec::new();
            if pgp {
                kinds.push(crate::yubikey::PinKind::OpenPgpAdmin);
            }
            if piv && wizard.management_protected() {
                kinds.push(crate::yubikey::PinKind::PivPin);
            }
            for line in card.counters.lines(lang, &kinds) {
                items.push(Item::Help(line));
            }
        }
        if piv && wizard.management_protected() {
            items.push(Item::Field(
                t::FIELD_PIV_MANAGEMENT.get(lang).to_owned(),
                t::MANAGEMENT_PROTECTED.get(lang).to_owned(),
            ));
        } else if piv {
            items.push(Item::LabeledRow(
                t::FIELD_PIV_MANAGEMENT.get(lang).to_owned(),
                vec![
                    Ctl::radio(
                        ids::MGMT_DEFAULT,
                        t::MANAGEMENT_DEFAULT.get(lang),
                        wizard.default_management,
                        true,
                    ),
                    Ctl::radio(
                        ids::MGMT_CUSTOM,
                        t::MANAGEMENT_CUSTOM.get(lang),
                        !wizard.default_management,
                        false,
                    ),
                ],
            ));
            if wizard.management.is_none() {
                items.push(Item::Help(t::MANAGEMENT_UNREAD.get(lang).to_owned()));
            }
        }
        items.push(Item::CardEnd);
        let ready = wizard.can_continue() && wizard.card.is_some();
        items.push(Item::CardStart(Some(t::CARD_HOW.get(lang).to_owned())));
        self.yk_occupied_items(wizard, items);
        if let Some(error) = &wizard.error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        items.push(Item::Row(vec![
            Ctl::primary(ids::IMPORT, t::BTN_IMPORT.get(lang))
                .enabled(ready && wizard.can_import()),
        ]));
        items.push(Item::Help(t::YK_IMPORT.get(lang).to_owned()));
        items.push(Item::Row(vec![
            Ctl::button(ids::ADOPT, t::BTN_ADOPT.get(lang)).enabled(ready),
        ]));
        items.push(Item::Help(t::YK_ADOPT.get(lang).to_owned()));
        items.push(Item::Banner(
            yk::YK_OVERWRITE.get(lang).to_owned(),
            Tone::Warn,
        ));
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::button(ids::CRED_BACK, t::BTN_BACK.get(lang)),
            Ctl::button(ids::WIZARD_CANCEL, t::BTN_CANCEL.get(lang)),
        ]));
    }

    fn yk_result_items(&self, wizard: &YkWizard, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        if let Some(failure) = &wizard.failure {
            items.push(Item::Banner(failure.clone(), Tone::Danger));
            items.push(Item::Row(vec![
                Ctl::primary(ids::RETRY, t::BTN_RETRY.get(lang)),
                Ctl::button(ids::CONFIRM_BACK, t::BTN_BACK_SLOTS.get(lang)),
                Ctl::button(ids::WIZARD_CANCEL, t::BTN_CANCEL.get(lang)),
            ]));
            return;
        }
        let Some(enrolled) = wizard.enrolled.as_ref() else {
            return;
        };
        let record: &HwKeyRecord = &enrolled.record;
        let done = if wizard.adopt {
            t::ADOPTED
        } else {
            t::IMPORTED
        };
        items.push(Item::Banner(
            done.fill(
                lang,
                [&record.serial.to_string(), &record.slots.len().to_string()],
            ),
            Tone::Success,
        ));
        if wizard.created && wizard.connect.is_some() {
            items.push(Item::Banner(
                t::CREATED_CONNECTED.get(lang).to_owned(),
                Tone::Info,
            ));
        } else if wizard.created {
            items.push(Item::Banner(t::CREATED.get(lang).to_owned(), Tone::Info));
        }
        // "가져오기" and "가져오기 없이 등록" both end here (spec/10 §9.3): the PIN card right
        // under the completion band (2026-11-10), the slots already checked in 2/4 folded.
        self.yk_pin_items(record.serial, items);
        for note in &wizard.notes {
            items.push(Item::Banner(note.clone(), Tone::Info));
        }
        let open = self.card.result_details_open;
        items.push(Item::Row(vec![Ctl::link(
            ids::RESULT_DETAILS,
            if open {
                t::DETAILS_OPEN
            } else {
                t::DETAILS_CLOSED
            }
            .get(lang),
        )]));
        if open {
            items.push(Item::CardStart(Some(format!("YubiKey #{}", record.serial))));
            items.push(Item::Field(
                t::FIELD_FIRMWARE.get(lang).to_owned(),
                record.firmware.to_string(),
            ));
            items.push(Item::Help(t::REREAD.get(lang).to_owned()));
            for slot in &record.slots {
                slot_items(
                    lang,
                    (slot.slot, slot.role),
                    slot.touch,
                    slot.pin,
                    &address_texts(slot.role, &slot.public).unwrap_or_default(),
                    items,
                );
            }
            items.push(Item::Row(vec![Ctl::button(
                ids::RECHECK,
                t::BTN_RECHECK.get(lang),
            )]));
            if let Some(lines) = &wizard.check {
                for line in lines {
                    items.push(Item::Text(line.clone()));
                }
            }
            items.push(Item::CardEnd);
        }
        // spec/10 §9.3: a new YubiKey wallet ends with its PIN setup (it cannot be skipped; the
        // PIN card's first line says why `완료` is off).
        let pins_first = wizard.created && wizard.connect.is_none() && !wizard.pins_done();
        items.push(Item::Row(vec![
            Ctl::primary(ids::FINISH, t::BTN_FINISH.get(lang)).enabled(!pins_first),
            Ctl::button(
                ids::ANOTHER,
                if wizard.connect.is_some() {
                    t::BTN_ANOTHER_CONNECT
                } else {
                    t::BTN_ANOTHER_ENROL
                }
                .get(lang),
            )
            .enabled(self.card.records.len() < MAX_CARDS && !pins_first),
        ]));
    }

    /// The main-window note after a card signing refused for factory PINs (spec/10 §9.3), with
    /// `PIN 설정` (the card's "PIN 설정" card in the `YubiKey` list).
    pub fn yk_pin_needed_items(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        if let Some(serial) = self.card.pin_needed {
            items.push(Item::Banner(
                format!("{} (YubiKey #{serial})", t::YK_PIN_NEEDED.get(lang)),
                Tone::Warn,
            ));
            items.push(Item::Row(vec![Ctl::primary(
                ids::PIN_NEEDED_OPEN,
                t::BTN_SET_PIN.get(lang),
            )]));
        }
    }

    /// "기본값 변경 / PIN 설정" of card `serial` (spec/10 §9.3): the defaults still seen, the
    /// PIN guide, and the two modes — "8자리 하나로 통일" (default: one W12 window sets the four
    /// PINs and protects the management key) or one secret at a time.
    #[expect(
        clippy::too_many_lines,
        reason = "the PIN card's first line, defaults, modes and guide in order"
    )]
    pub fn yk_pin_items(&self, serial: u32, items: &mut Vec<Item>) {
        use crate::yubikey::PinTarget;
        let lang = self.settings.language;
        let seen = self.yk_pin_defaults(serial);
        // The mode follows the factory values seen this run until the user picks one
        // (2026-11-10): all three factory → 통일, some → 하나씩 따로, unknown → 통일.
        let factory = [seen.openpgp_admin, seen.piv_pin, seen.piv_management];
        let separate = if self.card.pins_chosen {
            self.card.pins_separate
        } else {
            factory.iter().any(|seen| *seen) && !factory.iter().all(|seen| *seen)
        };
        items.push(Item::CardStart(Some(
            t::PIN_CARD_TITLE.fill(lang, [&serial.to_string()]),
        )));
        // The first line: why `완료` waits (a new YubiKey wallet), or that the card does not
        // sign yet (2026-11-10).
        let new_wallet = self.card.wizard.as_ref().is_some_and(|wizard| {
            wizard.created
                && wizard.connect.is_none()
                && wizard
                    .enrolled
                    .as_ref()
                    .is_some_and(|enrolled| enrolled.record.serial == serial)
        });
        if new_wallet && self.yk_pins_first() {
            items.push(Item::Banner(
                t::YK_PINS_FIRST.get(lang).to_owned(),
                Tone::Warn,
            ));
        } else if self.yk_card_on_defaults(serial) {
            items.push(Item::Banner(
                t::NO_SIGN_BEFORE_PIN.get(lang).to_owned(),
                Tone::Warn,
            ));
        }
        if new_wallet {
            items.push(Item::Help(t::STEP_5_OF_5.get(lang).to_owned()));
        }
        // One line of the factory values seen (only those).
        let mut names = Vec::new();
        if seen.openpgp_admin {
            names.push(PinTarget::OpenPgpAdmin.name(lang));
        }
        if seen.piv_pin {
            names.push("PIV PIN");
        }
        if seen.piv_management {
            names.push(t::FIELD_PIV_MANAGEMENT.get(lang));
        }
        if !names.is_empty() {
            let how = if separate {
                t::FACTORY_SEPARATE
            } else {
                t::FACTORY_UNIFIED
            };
            items.push(Item::Banner(
                t::FACTORY_SEEN.fill(lang, [&names.join(" · "), how.get(lang)]),
                Tone::Warn,
            ));
        }
        items.push(Item::LabeledRow(
            t::LABEL_MODE.get(lang).to_owned(),
            vec![
                Ctl::radio(
                    ids::PINS_UNIFIED,
                    t::MODE_UNIFIED.get(lang),
                    !separate,
                    true,
                ),
                Ctl::radio(
                    ids::PINS_SEPARATE,
                    t::MODE_SEPARATE.get(lang),
                    separate,
                    false,
                ),
            ],
        ));
        if separate {
            // The secrets still at their factory values say so (this run's changes count).
            let label = |target: PinTarget, factory: bool| {
                let name = target.name(lang);
                if factory && !self.card.list_changed.contains(&(serial, target)) {
                    t::FACTORY_MARK.fill(lang, [name])
                } else {
                    name.to_owned()
                }
            };
            items.push(Item::Row(vec![
                Ctl::button(
                    ids::CHANGE_PW1,
                    &label(PinTarget::OpenPgpUser, seen.openpgp_admin),
                ),
                Ctl::button(
                    ids::CHANGE_PW3,
                    &label(PinTarget::OpenPgpAdmin, seen.openpgp_admin),
                ),
            ]));
            items.push(Item::Row(vec![
                Ctl::button(ids::CHANGE_PIV_PIN, &label(PinTarget::PivPin, seen.piv_pin)),
                Ctl::button(ids::CHANGE_PUK, &label(PinTarget::PivPuk, seen.piv_pin)),
            ]));
            let protect = t::BTN_PROTECT_MANAGEMENT.get(lang);
            let protect = if seen.piv_management && !self.card.list_protected.contains(&serial) {
                t::FACTORY_MARK.fill(lang, [protect])
            } else {
                protect.to_owned()
            };
            items.push(Item::Row(vec![Ctl::button(ids::CHANGE_MGMT, &protect)]));
            items.push(Item::Help(t::YK_PROTECT_MGMT.get(lang).to_owned()));
        } else {
            items.push(Item::Row(vec![Ctl::primary(
                ids::SET_PINS,
                t::BTN_SET_PINS.get(lang),
            )]));
        }
        // The guide and the order behind a link (2026-11-10).
        let open = self.card.pin_guide_open;
        items.push(Item::Row(vec![Ctl::link(
            ids::PIN_GUIDE,
            if open {
                t::PIN_GUIDE_OPEN
            } else {
                t::PIN_GUIDE_CLOSED
            }
            .get(lang),
        )]));
        if open {
            for line in T_YK_PIN_GUIDE {
                items.push(Item::Text(format!("· {}", line.get(lang))));
            }
            items.push(Item::Help(t::YK_PIN_LOCKS.get(lang).to_owned()));
            items.push(Item::Text(t::YK_PIN_EASY.get(lang).to_owned()));
            items.push(Item::Help(t::YK_PIN_TRADEOFF.get(lang).to_owned()));
        }
        items.push(Item::CardEnd);
    }

    /// The removal overlay's text (spec/10 §7.5).
    #[must_use]
    pub fn yk_remove_text(&self) -> String {
        let lang = self.settings.language;
        let position = self
            .card
            .remove_target
            .and_then(|id| self.card.record_ids.iter().position(|other| *other == id));
        let Some(record) = position.and_then(|position| self.card.records.get(position)) else {
            return t::REMOVE_SELECTED.get(lang).to_owned();
        };
        // One sentence here; the accounts follow as the "지워지는 계정" block (2026-11-10).
        t::REMOVE_TEXT.fill(lang, [&record.serial.to_string()])
    }

    /// The removal overlay's accounts (2026-11-10): each key of the card with its addresses and
    /// last-read balance, what still signs for it ("`YubiKey` #m(으)로 계속 서명" / "이 지갑에서 서명
    /// 불가") and how it comes back, then what to do about a lost card.
    pub fn yk_remove_items(&self, items: &mut Vec<Item>) {
        let position = self
            .card
            .remove_target
            .and_then(|id| self.card.record_ids.iter().position(|other| *other == id));
        let Some(record) = position.and_then(|position| self.card.records.get(position)) else {
            return;
        };
        let others: Vec<HwKeyRecord> = self
            .card
            .records
            .iter()
            .filter(|other| other.serial != record.serial)
            .cloned()
            .collect();
        let lang = self.settings.language;
        items.push(Item::Subtitle(
            t::REMOVE_ACCOUNTS.fill(lang, [&record.serial.to_string()]),
        ));
        let accounts: Vec<crate::ui::removed::RemovedAccount> = record
            .slots
            .iter()
            .map(|slot| {
                let mut account = self.card_removed(slot, &others, false);
                if crate::yubikey::holders(&others, slot.role).is_empty() {
                    // Only on this card: how the account comes back after the record goes.
                    let back = if yw_core::yubikey::plan::is_unknown_index(slot.role.index()) {
                        t::BACK_UNKNOWN
                    } else {
                        t::BACK_WORDS
                    };
                    account.note = Some(back.get(lang).to_owned());
                }
                account
            })
            .collect();
        let _ = crate::ui::removed::removed_items(lang, &accounts, items);
        items.push(Item::Help(t::LOST_CARD.get(lang).to_owned()));
    }
}
