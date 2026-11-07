//! `YubiKey` screens (spec/04 §2.19, spec/10 §7): the S01 card `YubiKey에 키 보관`, S20 (the new
//! `YubiKey` wallet), S21 the enrolment wizard (keys and slots, confirmation with every path and
//! address, credentials, result with "다시 확인" and the defaults change), settings → `YubiKey`
//! (the enrolled cards, their slots, which cards hold each account, `삭제`) and the removal
//! overlay. Fixed sentences are the T-YK-* rows of spec/04 §2.16.

use yw_core::btc::ScriptType;
use yw_core::yubikey::plan::{
    CardSlot, KeyRole, MAX_CARDS, PgpKey, PinPolicy, TouchPolicy, accounts, address_texts,
};
use yw_core::yubikey::record::HwKeyRecord;
use yw_core::zec::ZecNetwork;

use crate::app::{App, AppMode};
use crate::app_yubikey::{
    CARD_SCRIPTS, PGP_TOUCH, PIV_TOUCH, PgpKind, T_YK_OVERWRITE, T_YK_PIV_FIRMWARE, T_YK_SAME,
    T_YK_SHARED, T_YK_WALLET, WizardOrigin, WizardStep, YkWizard,
};
use crate::ui::main_window::{Ctl, Item, Tone};

mod manage;

/// Command ids (block 13,200–13,399, `ui::command_ids`).
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
    ];
}

/// T-YK-PINS-FIRST: a new `YubiKey` wallet's result screen until "PIN 설정" is done.
pub const T_YK_PINS_FIRST: &str = "YubiKey 지갑은 PIN 설정을 마쳐야 끝납니다. 공장 기본 PIN(123456 / 12345678)으로는 서명하지 않습니다 — 아래 'PIN 설정하기'로 PIN을 바꾸세요.";
/// T-YK-PIN-NEEDED: the main-window note after a signing refused for factory PINs.
pub const T_YK_PIN_NEEDED: &str =
    "이 YubiKey는 공장 기본 PIN을 쓰고 있어 서명하지 않았습니다. PIN을 설정한 뒤 다시 서명하세요.";

/// The wizard's step labels (S21).
pub const WIZARD_STEPS: [&str; 4] = ["키·슬롯 고르기", "확인", "자격 정보", "결과"];
/// T-YK-LIST (settings → `YubiKey`).
pub const T_YK_LIST: &str = "YubiKey 계정은 복구 단어에서 만든 키를 YubiKey에 넣어 두고, 서명할 때마다 YubiKey에서 PIN과 터치로 서명합니다. 이 PC에는 공개키·주소·슬롯 표만 있습니다. 같은 키를 여러 YubiKey에 넣어 서로의 백업으로 쓸 수 있습니다(최대 8개).";
/// T-YK-MNEMONIC-WALLET: the recommendation in a wallet that stores its words.
pub const T_YK_MNEMONIC_WALLET: &str = "이 지갑의 복구 단어로 등록하면 그 단어가 이 PC에도 있으므로 보안 이득이 없습니다. 다른 복구 단어로 등록하거나, 키를 PC 밖에 두려면 첫 화면의 'YubiKey 지갑'(복구 단어를 저장하지 않는 지갑)을 새로 만드세요.";
/// T-YK-PIN-GUIDE (spec/10 §9.3): what each card secret is for.
pub const T_YK_PIN_GUIDE: [&str; 5] = [
    "OpenPGP PIN: EVM·Bitcoin 서명할 때마다 입력 (기본 123456, 6자 이상)",
    "OpenPGP 관리자 PIN: 키를 넣을 때, OpenPGP PIN이 잠겼을 때 (기본 12345678, 8자 이상)",
    "PIV PIN: Solana 서명할 때 (기본 123456, 6–8자)",
    "PIV PUK: PIV PIN이 잠겼을 때 풀기 (기본 12345678, 6–8자)",
    "PIV 관리 키: 앱이 자동으로 만들어 PIN으로 잠가 보관 (입력할 필요 없음)",
];
/// T-YK-PIN-LOCKS.
pub const T_YK_PIN_LOCKS: &str = "각각 3번 틀리면 따로 잠깁니다. 하나가 잠겨도 다른 쪽(OpenPGP/PIV)은 그대로이고, FIDO2·패스키 로그인은 이 중 어느 것과도 관계없습니다.";
/// T-YK-PIN-EASY.
pub const T_YK_PIN_EASY: &str = "편하게 쓰려면: 8자리 하나로 통일하세요 (네 개 모두 같은 값). 기본값 그대로 두면 YubiKey를 가진 사람이 서명할 수 있습니다.";
/// T-YK-PIN-TRADEOFF (the unified mode).
pub const T_YK_PIN_TRADEOFF: &str = "순서: PIV PIN → PIV PUK → PIV 관리 키(새로 만들어 PIN으로 보호) → OpenPGP 관리자 PIN → OpenPGP PIN. 하나로 통일하면 잠기기 전까지 맞혀 볼 기회가 늘고(네 곳 각 3번), 서명 PIN을 아는 사람이 관리자 권한도 갖습니다. 개인용으로는 괜찮은 선택입니다.";
/// T-YK-PROTECT-MGMT (the separate mode).
pub const T_YK_PROTECT_MGMT: &str = "PIV 관리 키 자동 보호: 새 관리 키를 이 PC에서 무작위로 만들어 YubiKey에 PIN으로 잠가 둡니다('ykman piv access change-management-key --generate --protect'와 같음). 현재 PIV PIN만 묻고, 관리 키는 보여 주지도 묻지도 않습니다.";
/// T-YK-IMPORT: the "가져오기" choice.
pub const T_YK_IMPORT: &str =
    "복구 단어에서 고른 키를 YubiKey에 씁니다. 그 슬롯에 있던 키는 덮어씁니다.";
/// T-YK-ADOPT (spec/10 §7.5).
pub const T_YK_ADOPT: &str = "YubiKey에 이미 같은 복구 단어의 키가 들어 있을 때 씁니다. 카드에는 아무것도 쓰지 않고, 카드의 공개키가 복구 단어와 맞는지만 확인해 지갑에 연결합니다(재설치·새 PC·지갑 초기화 후).";

const fn touch_label(touch: TouchPolicy) -> &'static str {
    match touch {
        TouchPolicy::Never => "터치 없음",
        TouchPolicy::Always => "항상",
        TouchPolicy::Cached => "15초 유지",
        TouchPolicy::AlwaysFixed => "항상(고정)",
        TouchPolicy::CachedFixed => "15초 유지(고정)",
    }
}

const fn kind_label(kind: PgpKind) -> &'static str {
    match kind {
        PgpKind::None => "없음",
        PgpKind::Evm => "EVM 계정",
        PgpKind::Btc => "Bitcoin 주소",
        PgpKind::Shared => "EVM 공유 키",
        PgpKind::Zec => "Zcash 주소",
    }
}

/// "메인넷 (t1…)" / "테스트넷 (tm…)".
#[must_use]
pub const fn zec_network_label(network: ZecNetwork) -> &'static str {
    match network {
        ZecNetwork::Mainnet => "메인넷 (t1…)",
        ZecNetwork::Testnet => "테스트넷 (tm…)",
    }
}

fn script_label(script: ScriptType) -> String {
    format!("{} ({})", script.name(), script.technical())
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
    slot: CardSlot,
    role: KeyRole,
    touch: TouchPolicy,
    pin: PinPolicy,
    addresses: &[String],
    items: &mut Vec<Item>,
) {
    items.push(Item::Subtitle(format!(
        "{} — {}",
        slot.label(),
        role.title()
    )));
    items.push(Item::Field("경로".to_owned(), role.path_text()));
    for address in addresses {
        items.push(Item::Mono(grouped_address(address)));
    }
    let policy = match pin {
        PinPolicy::NotApplicable => format!("터치: {}", touch_label(touch)),
        PinPolicy::Once => format!("터치: {} · PIN: 세션마다", touch_label(touch)),
        PinPolicy::Always => format!("터치: {} · PIN: 서명마다", touch_label(touch)),
    };
    items.push(Item::Field("정책".to_owned(), policy));
}

impl App {
    /// The S01 card `YubiKey에 키 보관`.
    pub fn first_run_yubikey_card(&self, items: &mut Vec<Item>) {
        items.push(Item::CardStart(Some("YubiKey에 키 보관".to_owned())));
        items.push(Item::Text(T_YK_WALLET.to_owned()));
        items.push(Item::Help(
            "YubiKey 5(펌웨어 5.2.3 이상, Solana 계정은 5.7 이상)와 종이·펜이 필요합니다. 복구 단어가 유일한 백업이며 이 PC에는 남지 않습니다."
                .to_owned(),
        ));
        items.push(Item::Row(vec![
            Ctl::button(ids::NEW_WALLET, "YubiKey 지갑 새로 만들기").enabled(!self.leftover),
        ]));
        items.push(Item::Help(
            "새 복구 단어 24개를 만들어 종이에만 적고, 그 키를 YubiKey에 넣습니다. 이 PC에는 복구 단어가 남지 않습니다."
                .to_owned(),
        ));
        items.push(Item::CardEnd);
    }

    /// S20: what the new `YubiKey` wallet is, before W01.
    pub fn yk_wallet_intro(items: &mut Vec<Item>) {
        items.push(Item::Title("YubiKey 지갑 만들기".to_owned()));
        items.push(crate::ui::screens::steps(
            crate::ui::screens::CREATE_STEPS,
            0,
        ));
        items.push(Item::CardStart(Some("시작하기 전에".to_owned())));
        for line in [
            "· 종이와 펜, YubiKey를 준비하세요. 새 복구 단어 24개를 한 번 보여 드립니다.",
            "· 복구 단어는 이 PC에 저장하지 않습니다. 적은 종이가 이 지갑의 유일한 백업입니다.",
            "· 단어 4개로 바르게 적었는지 확인한 뒤, YubiKey에 넣을 키를 고르고 가져옵니다.",
            "· 같은 단어로 백업 YubiKey를 바로 더 등록할 수 있습니다(마칠 때까지 메모리에만 있음).",
        ] {
            items.push(Item::Text(line.to_owned()));
        }
        items.push(Item::Banner(
            "복구 단어를 아는 사람은 누구든 YubiKey 없이 자산을 옮길 수 있습니다. 사진·클라우드에 남기지 마세요."
                .to_owned(),
            Tone::Warn,
        ));
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::primary(ids::NEW_WALLET_START, "시작하기"),
            Ctl::button(ids::NEW_WALLET_CANCEL, "취소"),
        ]));
    }

    /// Settings → `YubiKey`.
    #[expect(
        clippy::too_many_lines,
        reason = "one card per enrolled YubiKey / slot form"
    )]
    pub fn yk_settings_section(&self, items: &mut Vec<Item>) {
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        if unlocked && let Some(manage) = self.card.manage.as_ref() {
            self.yk_manage_items(manage, items);
            return;
        }
        let records = &self.card.records;
        items.push(Item::CardStart(Some("YubiKey 계정".to_owned())));
        items.push(Item::Text(T_YK_LIST.to_owned()));
        if self.keys.has_mnemonic {
            items.push(Item::Help(T_YK_MNEMONIC_WALLET.to_owned()));
        }
        items.push(Item::Row(vec![
            Ctl::primary(ids::ENROL_START, "YubiKey 등록")
                .enabled(unlocked && records.len() < MAX_CARDS),
        ]));
        if !unlocked {
            items.push(Item::Help("잠금을 해제하면 쓸 수 있습니다.".to_owned()));
        }
        items.push(Item::CardEnd);
        let defaults = self
            .meta
            .as_ref()
            .map(|meta| meta.hw_accounts.defaults.clone())
            .unwrap_or_default();
        for (row, record) in records.iter().enumerate() {
            items.push(Item::CardStart(Some(format!("YubiKey #{}", record.serial))));
            items.push(Item::Field(
                "펌웨어".to_owned(),
                record.firmware.to_string(),
            ));
            items.push(Item::Field(
                "슬롯".to_owned(),
                format!("{}개", record.slots.len()),
            ));
            for slot in &record.slots {
                slot_items(
                    slot.slot,
                    slot.role,
                    slot.touch,
                    slot.pin,
                    &address_texts(slot.role, &slot.public).unwrap_or_default(),
                    items,
                );
            }
            if defaults.contains(&record.serial) {
                items.push(Item::Banner(
                    "기본 PIN·관리 키를 쓰고 있을 수 있습니다. 'PIN 설정 / 기본값 변경'에서 바꾸세요."
                        .to_owned(),
                    Tone::Warn,
                ));
            }
            let row_id = u16::try_from(row).unwrap_or(u16::MAX);
            let open = self.card.pin_serial == Some(record.serial);
            items.push(Item::Row(vec![
                Ctl::button(
                    ids::PINS_BASE.saturating_add(row_id),
                    if open {
                        "PIN 설정 닫기"
                    } else {
                        "PIN 설정 / 기본값 변경 (PIN 안내)"
                    },
                )
                .enabled(unlocked),
                Ctl::danger(ids::REMOVE_BASE.saturating_add(row_id), "삭제")
                    .enabled(unlocked && self.yk_can_remove()),
            ]));
            items.push(Item::Row(vec![
                Ctl::button(ids::RESLOT_BASE.saturating_add(row_id), "슬롯 구성 바꾸기")
                    .enabled(unlocked),
                Ctl::danger(ids::CLEAR_BASE.saturating_add(row_id), "YubiKey 비우기")
                    .enabled(unlocked),
            ]));
            items.push(Item::CardEnd);
            if open && unlocked {
                self.yk_pin_items(record.serial, items);
            }
        }
        if !records.is_empty() {
            items.push(Item::CardStart(Some("계정별 YubiKey".to_owned())));
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
                            format!("#{} {name}(백업)", holder.serial)
                        }
                    })
                    .collect();
                items.push(Item::Text(format!(
                    "{} ({}) — {}",
                    account.role.title(),
                    account.role.path_text(),
                    holders.join(", ")
                )));
            }
            items.push(Item::CardEnd);
        }
    }

    /// S21: the wizard at its step.
    pub fn yk_wizard_screen(&self, items: &mut Vec<Item>) {
        let Some(wizard) = self.card.wizard.as_ref() else {
            items.push(Item::Muted("YubiKey 등록이 끝났습니다.".to_owned()));
            items.push(crate::ui::screens::back_main());
            return;
        };
        items.push(Item::Title(match wizard.origin {
            WizardOrigin::NewWallet => "YubiKey 지갑 만들기 — YubiKey 등록".to_owned(),
            WizardOrigin::Vault => "YubiKey 등록".to_owned(),
        }));
        let current = match wizard.step {
            WizardStep::Plan => 1,
            WizardStep::Confirm => 2,
            WizardStep::Credentials | WizardStep::Running => 3,
            WizardStep::Result => 4,
        };
        items.push(Item::Steps(
            WIZARD_STEPS
                .iter()
                .map(|label| (*label).to_owned())
                .collect(),
            current,
        ));
        match wizard.step {
            WizardStep::Plan => self.yk_plan_items(wizard, items),
            WizardStep::Confirm => self.yk_confirm_items(wizard, items),
            WizardStep::Credentials => Self::yk_credentials_items(wizard, items),
            WizardStep::Running => {
                items.push(Item::CardStart(None));
                items.push(Item::Subtitle("YubiKey에 키를 넣는 중입니다".to_owned()));
                items.push(Item::Text(
                    "YubiKey를 빼지 마세요. 몇 초 걸립니다(터치는 필요 없습니다).".to_owned(),
                ));
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
        let form = wizard.pgp(key);
        items.push(Item::CardStart(Some(CardSlot::OpenPgp(key).label())));
        items.push(Item::LabeledRow(
            "넣을 키".to_owned(),
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
                    kind_label(kind),
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
        items.push(Item::LabeledRow(
            if matches!(form.kind, PgpKind::Btc | PgpKind::Zec) {
                "주소 인덱스 (0–999)".to_owned()
            } else {
                "계정 인덱스 (0–999)".to_owned()
            },
            vec![Ctl::edit(edit, &form.index_text, 80, false, 3)],
        ));
        if matches!(form.kind, PgpKind::Btc | PgpKind::Shared) {
            items.push(Item::LabeledRow(
                format!("주소 형식 ({})", self.yk_network().display_name()),
                CARD_SCRIPTS
                    .into_iter()
                    .enumerate()
                    .map(|(position, script)| {
                        Ctl::radio(
                            ids::pgp_id(key, PgpAction::Script(script)),
                            &script_label(script),
                            form.script == script,
                            position == 0,
                        )
                    })
                    .collect(),
            ));
        }
        if form.kind == PgpKind::Zec {
            items.push(Item::LabeledRow(
                "Zcash 네트워크".to_owned(),
                [ZecNetwork::Mainnet, ZecNetwork::Testnet]
                    .into_iter()
                    .enumerate()
                    .map(|(position, network)| {
                        Ctl::radio(
                            ids::pgp_id(key, PgpAction::Zec(network)),
                            zec_network_label(network),
                            form.zec == network,
                            position == 0,
                        )
                    })
                    .collect(),
            ));
        }
        items.push(Item::LabeledRow(
            "터치".to_owned(),
            PGP_TOUCH
                .into_iter()
                .enumerate()
                .map(|(position, touch)| {
                    Ctl::radio(
                        ids::pgp_id(key, PgpAction::Touch(touch)),
                        touch_label(touch),
                        form.touch == touch,
                        position == 0,
                    )
                })
                .collect(),
        ));
        if let Ok(Some(slot)) = YkWizard::pgp_preview(form, key, self.yk_network()) {
            items.push(Item::Help(format!("경로: {}", slot.role.path_text())));
            if let KeyRole::Btc { index, .. } = slot.role
                && index >= 20
            {
                items.push(Item::Help(
                    "주소 인덱스가 20 이상이면 다른 지갑으로 복구할 때 gap limit을 늘려야 합니다."
                        .to_owned(),
                ));
            }
        }
        items.push(Item::Help(
            "'고정'을 고르면 관리자 PIN을 아는 프로그램도 터치를 끌 수 없지만, 나중에 바꾸려면 OpenPGP 초기화와 재등록이 필요합니다."
                .to_owned(),
        ));
        if form.kind == PgpKind::Shared {
            items.push(Item::Banner(T_YK_SHARED.to_owned(), Tone::Warn));
        }
        items.push(Item::CardEnd);
    }

    /// The "백업 복사본" card of the plan screen (the enrolled cards to copy).
    fn yk_backup_items(&self, wizard: &YkWizard, items: &mut Vec<Item>) {
        let records = &self.card.records;
        if !records.is_empty() {
            items.push(Item::CardStart(Some("백업 복사본".to_owned())));
            items.push(Item::Row(vec![Ctl::check(
                ids::BACKUP_TOGGLE,
                "백업 YubiKey 만들기 (같은 키 복사)",
                wizard.backup_of.is_some(),
            )]));
            items.push(Item::Help(
                "같은 키를 다른 YubiKey에도 넣어 예비용으로 씁니다. 이미 등록한 YubiKey의 슬롯 구성을 그대로 따릅니다."
                    .to_owned(),
            ));
            if let Some(serial) = wizard.backup_of {
                items.push(Item::LabeledRow(
                    "복사할 YubiKey".to_owned(),
                    records
                        .iter()
                        .enumerate()
                        .map(|(row, record)| {
                            Ctl::radio(
                                ids::BACKUP_BASE
                                    .saturating_add(u16::try_from(row).unwrap_or(u16::MAX)),
                                &format!("#{} (슬롯 {}개)", record.serial, record.slots.len()),
                                record.serial == serial,
                                row == 0,
                            )
                        })
                        .collect(),
                ));
                if let Some(record) = records.iter().find(|record| record.serial == serial) {
                    for slot in &record.slots {
                        items.push(Item::Text(format!(
                            "{} — {} ({})",
                            slot.slot.label(),
                            slot.role.title(),
                            slot.role.path_text()
                        )));
                    }
                }
                items.push(Item::Help(
                    "같은 슬롯·같은 경로·같은 정책으로 이 YubiKey에 넣습니다. 같은 복구 단어(+ passphrase)를 입력해야 합니다."
                        .to_owned(),
                ));
            }
            items.push(Item::CardEnd);
        }
    }

    fn yk_plan_items(&self, wizard: &YkWizard, items: &mut Vec<Item>) {
        if wizard.origin == WizardOrigin::NewWallet {
            items.push(Item::Banner(
                "복구 단어 확인을 마쳤습니다. 이제 YubiKey에 넣을 키를 고르세요. 첫 YubiKey를 가져오면 지갑이 만들어집니다."
                    .to_owned(),
                Tone::Success,
            ));
        }
        self.yk_backup_items(wizard, items);
        if wizard.backup_of.is_none() {
            self.yk_pgp_items(wizard, PgpKey::Sig, items);
            self.yk_pgp_items(wizard, PgpKey::Aut, items);
            if wizard.uses_shared() {
                items.push(Item::Row(vec![Ctl::check(
                    ids::SHARED_ACK,
                    "이해했습니다: 공유 키는 두 체인의 신원을 연결할 수 있습니다",
                    wizard.shared_ack,
                )]));
            }
            items.push(Item::CardStart(Some("PIV — Solana 계정".to_owned())));
            items.push(Item::LabeledRow(
                "Solana 계정 수 (0–20)".to_owned(),
                vec![Ctl::edit(
                    ids::SOL_COUNT_EDIT,
                    &wizard.sol_count_text,
                    80,
                    false,
                    2,
                )],
            ));
            items.push(Item::LabeledRow(
                "첫 계정 인덱스".to_owned(),
                vec![Ctl::edit(
                    ids::SOL_START_EDIT,
                    &wizard.sol_start_text,
                    80,
                    false,
                    3,
                )],
            ));
            items.push(Item::LabeledRow(
                "터치".to_owned(),
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
                            touch_label(touch),
                            wizard.piv_touch == touch,
                            position == 0,
                        )
                    })
                    .collect(),
            ));
            items.push(Item::Help(
                "PIV 보관 슬롯 82부터 차례로 Solana 계정 m/44'/501'/i'/0'을 넣습니다. Solana를 쓰지 않으면 0으로 두세요."
                    .to_owned(),
            ));
            items.push(Item::Help(T_YK_PIV_FIRMWARE.to_owned()));
            items.push(Item::CardEnd);
        }
        if let Some(error) = &wizard.error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        items.push(Item::Row(vec![
            Ctl::primary(
                ids::PLAN_NEXT,
                if wizard.seed_held {
                    "다음 (확인)"
                } else {
                    "다음 (복구 단어 입력)"
                },
            ),
            Ctl::button(ids::WIZARD_CANCEL, "취소"),
        ]));
    }

    fn yk_confirm_items(&self, wizard: &YkWizard, items: &mut Vec<Item>) {
        let Some(preview) = wizard.preview.as_ref() else {
            items.push(Item::CardStart(None));
            items.push(Item::Subtitle("확인 중…".to_owned()));
            items.push(Item::Text(
                "복구 단어에서 고른 키의 경로와 주소를 계산하고 있습니다(YubiKey와 통신하지 않음)."
                    .to_owned(),
            ));
            items.push(Item::CardEnd);
            items.push(Item::Row(vec![
                Ctl::button(ids::CONFIRM_BACK, "← 슬롯 다시 고르기"),
                Ctl::button(ids::WIZARD_CANCEL, "취소"),
            ]));
            return;
        };
        if preview.same_as_vault {
            items.push(Item::Banner(T_YK_SAME.to_owned(), Tone::HighRisk));
            items.push(Item::Row(vec![Ctl::check(
                ids::SAME_ACK,
                "이해했습니다. 그래도 이 복구 단어로 등록합니다",
                wizard.same_ack,
            )]));
        }
        if let Err(error) = preview.plan {
            items.push(Item::Banner(error.to_string(), Tone::Danger));
        }
        items.push(Item::CardStart(Some("가져오기 전에 확인하세요".to_owned())));
        items.push(Item::Text(
            "아래 경로와 주소는 입력한 복구 단어에서 이 PC가 계산한 값입니다(YubiKey와는 아직 통신하지 않았습니다). 쓰려는 주소와 전체가 같은지 확인하세요."
                .to_owned(),
        ));
        for line in &preview.lines {
            let planned = line.planned;
            slot_items(
                planned.slot,
                planned.role,
                planned.touch,
                planned.pin,
                &line.addresses,
                items,
            );
            let holders = crate::yubikey::holders(&self.card.records, planned.role);
            let relation = if holders.is_empty() {
                "새 키".to_owned()
            } else {
                let list: Vec<String> = holders.iter().map(|serial| format!("#{serial}")).collect();
                format!(
                    "{} — 같은 경로를 가진 YubiKey: {}",
                    if planned.backup_copy {
                        "백업 복사본"
                    } else {
                        "이미 다른 YubiKey에 있음"
                    },
                    list.join(", ")
                )
            };
            items.push(Item::Field("관계".to_owned(), relation));
        }
        Self::yk_card_items(wizard, items);
        items.push(Item::CardEnd);
        if wizard.applets().1 {
            items.push(Item::Help(T_YK_PIV_FIRMWARE.to_owned()));
        }
        items.push(Item::Help(T_YK_OVERWRITE.to_owned()));
        items.push(Item::Row(vec![
            Ctl::primary(ids::CONFIRM_NEXT, "다음").enabled(wizard.can_continue()),
            Ctl::button(ids::CONFIRM_BACK, "← 슬롯 다시 고르기"),
            Ctl::button(ids::WIZARD_CANCEL, "취소"),
        ]));
    }

    /// The card the wizard enrols (spec/10 §7.3: one card only, identified read-only).
    fn yk_card_items(wizard: &YkWizard, items: &mut Vec<Item>) {
        let text = match (&wizard.card, &wizard.card_error) {
            (Some(card), _) => format!(
                "YubiKey #{} (펌웨어 {}) — 이 YubiKey에만 씁니다.",
                card.serial, card.firmware
            ),
            (None, Some(error)) => error.clone(),
            (None, None) => "연결한 YubiKey를 읽는 중…".to_owned(),
        };
        items.push(Item::Field("연결한 YubiKey".to_owned(), text));
        if wizard.card.is_none() && wizard.card_error.is_some() {
            items.push(Item::Row(vec![Ctl::button(
                ids::IDENTIFY_AGAIN,
                "다시 읽기",
            )]));
        }
    }

    fn yk_credentials_items(wizard: &YkWizard, items: &mut Vec<Item>) {
        let (pgp, piv) = wizard.applets();
        items.push(Item::CardStart(Some("YubiKey 자격 정보".to_owned())));
        items.push(Item::Text(
            "YubiKey를 하나만 연결하세요. PIN·관리 키는 이 작업에만 쓰고 바로 지웁니다(저장하지 않음)."
                .to_owned(),
        ));
        Self::yk_card_items(wizard, items);
        if pgp {
            items.push(Item::Field(
                "OpenPGP".to_owned(),
                "관리자 PIN(PW3)을 다음 창에서 입력합니다 (공장 기본값 12345678).".to_owned(),
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
            for line in card.counters.lines(&kinds) {
                items.push(Item::Help(line));
            }
        }
        if piv && wizard.management_protected() {
            items.push(Item::Field(
                "PIV 관리 키".to_owned(),
                "관리 키: PIN으로 보호됨 — PIV PIN만 입력".to_owned(),
            ));
        } else if piv {
            items.push(Item::LabeledRow(
                "PIV 관리 키".to_owned(),
                vec![
                    Ctl::radio(
                        ids::MGMT_DEFAULT,
                        "기본 관리 키 사용",
                        wizard.default_management,
                        true,
                    ),
                    Ctl::radio(
                        ids::MGMT_CUSTOM,
                        "관리 키 직접 입력 (16진수 48자리)",
                        !wizard.default_management,
                        false,
                    ),
                ],
            ));
            if wizard.management.is_none() {
                items.push(Item::Help(
                    "연결한 YubiKey의 관리 키 설정을 아직 읽지 못했습니다. ykman으로 PIN 보호(--protect)를 해 둔 YubiKey라면 연결한 뒤 '← 이전' → '다음'으로 다시 읽으세요."
                        .to_owned(),
                ));
            }
        }
        items.push(Item::CardEnd);
        let ready = wizard.can_continue() && wizard.card.is_some();
        items.push(Item::CardStart(Some("어떻게 등록할까요?".to_owned())));
        items.push(Item::Row(vec![
            Ctl::primary(ids::IMPORT, "복구 단어에서 키를 넣기 (처음 등록)").enabled(ready),
        ]));
        items.push(Item::Help(T_YK_IMPORT.to_owned()));
        items.push(Item::Row(vec![
            Ctl::button(ids::ADOPT, "이미 넣은 키 연결하기 (가져오기 없이 등록)").enabled(ready),
        ]));
        items.push(Item::Help(T_YK_ADOPT.to_owned()));
        items.push(Item::Banner(T_YK_OVERWRITE.to_owned(), Tone::Warn));
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::button(ids::CRED_BACK, "← 이전"),
            Ctl::button(ids::WIZARD_CANCEL, "취소"),
        ]));
    }

    fn yk_result_items(&self, wizard: &YkWizard, items: &mut Vec<Item>) {
        if let Some(failure) = &wizard.failure {
            items.push(Item::Banner(failure.clone(), Tone::Danger));
            items.push(Item::Row(vec![
                Ctl::primary(ids::RETRY, "다시 시도"),
                Ctl::button(ids::CONFIRM_BACK, "← 슬롯 다시 고르기"),
                Ctl::button(ids::WIZARD_CANCEL, "취소"),
            ]));
            return;
        }
        let Some(enrolled) = wizard.enrolled.as_ref() else {
            return;
        };
        let record: &HwKeyRecord = &enrolled.record;
        items.push(Item::Banner(
            if wizard.adopt {
                format!(
                    "YubiKey #{}을(를) 가져오기 없이 등록했습니다 (카드에 쓰지 않음, 슬롯 {}개).",
                    record.serial,
                    record.slots.len()
                )
            } else {
                format!(
                    "YubiKey #{}에 키를 가져왔습니다 (슬롯 {}개).",
                    record.serial,
                    record.slots.len()
                )
            },
            Tone::Success,
        ));
        if wizard.created {
            items.push(Item::Banner(
                "YubiKey 지갑을 만들었습니다. 복구 단어는 이 PC에 저장하지 않았습니다 — 적은 종이를 안전하게 보관하세요. 백업 YubiKey를 지금 더 등록할 수 있습니다."
                    .to_owned(),
                Tone::Info,
            ));
        }
        items.push(Item::CardStart(Some(format!("YubiKey #{}", record.serial))));
        items.push(Item::Field(
            "펌웨어".to_owned(),
            record.firmware.to_string(),
        ));
        items.push(Item::Help(
            "YubiKey에서 다시 읽은 공개키와 그 주소입니다.".to_owned(),
        ));
        for slot in &record.slots {
            slot_items(
                slot.slot,
                slot.role,
                slot.touch,
                slot.pin,
                &address_texts(slot.role, &slot.public).unwrap_or_default(),
                items,
            );
        }
        items.push(Item::Row(vec![Ctl::button(ids::RECHECK, "다시 확인")]));
        if let Some(lines) = &wizard.check {
            for line in lines {
                items.push(Item::Text(line.clone()));
            }
        }
        items.push(Item::CardEnd);
        // "가져오기" and "가져오기 없이 등록" both end here (spec/10 §9.3).
        self.yk_pin_items(record.serial, items);
        for note in &wizard.notes {
            items.push(Item::Banner(note.clone(), Tone::Info));
        }
        // spec/10 §9.3: a new YubiKey wallet ends with its PIN setup (it cannot be skipped).
        let pins_first = wizard.created && !wizard.pins_done();
        if pins_first {
            items.push(Item::Banner(T_YK_PINS_FIRST.to_owned(), Tone::Warn));
        }
        items.push(Item::Row(vec![
            Ctl::primary(ids::FINISH, "완료").enabled(!pins_first),
            Ctl::button(ids::ANOTHER, "다른 YubiKey 등록(백업)")
                .enabled(self.card.records.len() < MAX_CARDS && !pins_first),
        ]));
    }

    /// The main-window note after a card signing refused for factory PINs (spec/10 §9.3), with
    /// `PIN 설정` (the card's "PIN 설정" card in the `YubiKey` list).
    pub fn yk_pin_needed_items(&self, items: &mut Vec<Item>) {
        if let Some(serial) = self.card.pin_needed {
            items.push(Item::Banner(
                format!("{T_YK_PIN_NEEDED} (YubiKey #{serial})"),
                Tone::Warn,
            ));
            items.push(Item::Row(vec![Ctl::primary(
                ids::PIN_NEEDED_OPEN,
                "PIN 설정",
            )]));
        }
    }

    /// "기본값 변경 / PIN 설정" of card `serial` (spec/10 §9.3): the defaults still seen, the
    /// PIN guide, and the two modes — "8자리 하나로 통일" (default: one W12 window sets the four
    /// PINs and protects the management key) or one secret at a time.
    pub fn yk_pin_items(&self, serial: u32, items: &mut Vec<Item>) {
        let separate = self.card.pins_separate;
        items.push(Item::CardStart(Some(format!(
            "기본값 변경 / PIN 설정 — YubiKey #{serial}"
        ))));
        for line in crate::app_card::defaults_lines(self.yk_pin_defaults(serial)) {
            items.push(Item::Banner(line, Tone::Warn));
        }
        items.push(Item::Subtitle("PIN 안내".to_owned()));
        for line in T_YK_PIN_GUIDE {
            items.push(Item::Text(format!("· {line}")));
        }
        items.push(Item::Help(T_YK_PIN_LOCKS.to_owned()));
        items.push(Item::Text(T_YK_PIN_EASY.to_owned()));
        items.push(Item::LabeledRow(
            "방식".to_owned(),
            vec![
                Ctl::radio(
                    ids::PINS_UNIFIED,
                    "8자리 하나로 통일 (권장)",
                    !separate,
                    true,
                ),
                Ctl::radio(ids::PINS_SEPARATE, "하나씩 따로", separate, false),
            ],
        ));
        if separate {
            items.push(Item::Row(vec![
                Ctl::button(ids::CHANGE_PW1, "OpenPGP PIN"),
                Ctl::button(ids::CHANGE_PW3, "OpenPGP 관리자 PIN"),
                Ctl::button(ids::CHANGE_PIV_PIN, "PIV PIN"),
                Ctl::button(ids::CHANGE_PUK, "PIV PUK"),
            ]));
            items.push(Item::Row(vec![Ctl::button(
                ids::CHANGE_MGMT,
                "PIV 관리 키 자동 보호",
            )]));
            items.push(Item::Help(T_YK_PROTECT_MGMT.to_owned()));
        } else {
            items.push(Item::Row(vec![Ctl::primary(
                ids::SET_PINS,
                "PIN 설정하기 (8자리 하나)",
            )]));
            items.push(Item::Help(T_YK_PIN_TRADEOFF.to_owned()));
        }
        items.push(Item::CardEnd);
    }

    /// The removal overlay's text (spec/10 §7.5).
    #[must_use]
    pub fn yk_remove_text(&self) -> String {
        let position = self
            .card
            .remove_target
            .and_then(|id| self.card.record_ids.iter().position(|other| *other == id));
        let Some(record) = position.and_then(|position| self.card.records.get(position)) else {
            return "선택한 YubiKey 기록을 지웁니다.".to_owned();
        };
        let others: Vec<&HwKeyRecord> = self
            .card
            .records
            .iter()
            .filter(|other| other.serial != record.serial)
            .collect();
        let lost: Vec<String> = record
            .slots
            .iter()
            .filter(|slot| {
                !others.iter().any(|other| {
                    other
                        .slots
                        .iter()
                        .any(|held| held.role.key_identity() == slot.role.key_identity())
                })
            })
            .map(|slot| slot.role.title())
            .collect();
        let mut text = format!(
            "YubiKey #{}의 기록을 이 지갑에서 지웁니다. YubiKey 안의 키는 지우지 않습니다.",
            record.serial
        );
        if lost.is_empty() {
            text.push_str(" 이 YubiKey의 키는 모두 다른 YubiKey에도 있어 계정은 그대로 남습니다.");
        } else {
            text.push_str(" 이 YubiKey에만 있는 계정(");
            text.push_str(&lost.join(", "));
            text.push_str(")은 목록에서 사라집니다. 같은 복구 단어로 다시 등록하면 돌아옵니다.");
        }
        text.push_str(" 잃어버린 YubiKey라면 PIN을 3번 틀리면 잠기지만, 자산을 새 복구 단어로 옮길지는 직접 판단하세요. 계속하려면 비밀번호를 입력하세요.");
        text
    }
}
