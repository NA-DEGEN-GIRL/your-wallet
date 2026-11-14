//! Screen contents S01–S15 (spec/04 §2) as [`Item`] lists, and the command ids of their
//! controls. Fixed sentences follow spec/04 §2.16; nothing from RPC or the OS is shown.
//!
//! Layout rules (spec/04 §2.0, design system §1.6): one primary button per screen (two on the
//! chain tabs: 보내기 / 받기), sections in cards with a heading, a plain-language help line under
//! technical fields, technical settings behind `고급 설정 보기`, flows with a step indicator.

use core::fmt::Write as _;

use yw_core::evm::chain::SEPOLIA;
use yw_core::evm::display::format_address;

use crate::apikeys::{KeyName, mask_url, template_entry};
use crate::app::{App, AppMode, Confirm, Screen, SettingsSection, TestState};
use crate::errors::ErrorCode;
use crate::meta::EvmAccountPref;
use crate::network::NetworkId;
use crate::settings::{LogLevel, RpcTemplate};
use crate::ui::main_window::{Ctl, Item, Tone};
use crate::ui::theme::AddressKind;
use yw_core::lang::{Lang, Text};

pub mod text;

pub use text::{
    T_ACCOUNTS_BACKUP, T_ACCOUNTS_IMPORTED, T_ACCOUNTS_KEY_ONLY, T_ACCOUNTS_YUBIKEY,
    T_ACCOUNTS_YUBIKEY_WORDS, T_ACTIVITY_RECEIVED, T_ALT_PASS, T_ALT_PASS_RECEIVE,
    T_BALANCE_FAILED, T_BALANCE_LOADING, T_DISCARD, T_MAINNET, T_REFRESH_TIP, T_REMOVE_KEY,
    T_TOKEN_DELETE, T_WER_UNPROTECTED,
};

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
    /// of [`App::url_networks`](crate::app::App::url_networks) opens that row.
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
}

/// Steps of the create flow (S02 → W01 → W08 → W10, spec/04 §2.3).
pub const CREATE_STEPS: [Text; 3] = [
    text::STEP_PASSWORD,
    text::STEP_WRITE_WORDS,
    text::STEP_BACKUP_CHECK,
];
/// Steps of the import flow (S05 → W01 → W05 → S06, spec/04 §2.4).
pub const IMPORT_STEPS: [Text; 3] = [
    text::STEP_PASSWORD,
    text::STEP_ENTER_WORDS,
    text::STEP_FIRST_ADDRESS,
];

/// The step indicator item of a flow.
#[must_use]
pub fn steps<const N: usize>(labels: [&str; N], current: usize) -> Item {
    Item::Steps(
        labels.iter().map(|label| (*label).to_owned()).collect(),
        current,
    )
}

/// The `← 메인으로` link.
#[must_use]
pub fn back_main(lang: Lang) -> Item {
    Item::Row(vec![
        Ctl::link(ids::BACK_MAIN, text::BACK_MAIN.get(lang)).tip(text::BACK_MAIN_TIP.get(lang)),
    ])
}

/// The `언어 · Language` card title: the same in both languages (spec/14 §1), like the `한국어`
/// option, so either reader finds the setting.
pub const LANGUAGE_TITLE: &str = "언어 · Language";
/// The `한국어` option of the language card (the language's own name in both languages).
pub const LANGUAGE_KOREAN: &str = "한국어";

/// T-FIRST-1 (S01, three plain sentences).
pub const T_FIRST: [Text; 3] = [text::T_FIRST_1, text::T_FIRST_2, text::T_FIRST_3];

/// T-BACKUP-FAIL (W10 after a wrong answer, spec/04 §2.3): the same four positions are asked
/// again, and the paper may be what is wrong. `words_again`: closing W10 leads back to the words
/// (S04 or the recovery-phrase list); the new `YubiKey` wallet's W10 has no way back to them.
#[must_use]
pub fn backup_retry_text(lang: Lang, positions: [u8; 4], words_again: bool) -> String {
    let [a, b, c, d] = positions.map(|position| position.to_string());
    let next = if words_again {
        text::BACKUP_RETRY_WORDS_AGAIN
    } else {
        text::BACKUP_RETRY_NO_WORDS
    };
    text::BACKUP_RETRY.fill(lang, [&a, &b, &c, &d, next.get(lang)])
}

/// The selected-account card of a network without an RPC address (spec/04 §2.6, 2026-11-08):
/// why there is no balance, in place of "RPC 연결을 확인하고 새로고침하세요".
#[must_use]
pub fn no_endpoint_text(lang: Lang, network: &str) -> String {
    text::NO_ENDPOINT.fill(lang, [network])
}

/// `HH:MM` in local time (UTC with a suffix if the conversion fails).
#[must_use]
pub fn local_hh_mm(unix_ms: u64) -> String {
    let wall = yw_win::time::local_wall_ms(unix_ms);
    let text = crate::logging::format_utc(wall.unwrap_or(unix_ms));
    let time = text.get(11..16).unwrap_or("--:--").to_owned();
    if wall.is_some() {
        time
    } else {
        format!("{time} UTC")
    }
}

/// The line under a balance read successfully: "블록 N 기준 · HH:MM 갱신" (EVM) or
/// "HH:MM 갱신" (no block number).
#[must_use]
pub fn balance_read_text(lang: Lang, block: Option<u64>, at_unix_ms: Option<u64>) -> String {
    let when = at_unix_ms.map(|at| text::UPDATED_AT.fill(lang, [&local_hh_mm(at)]));
    match (block, when) {
        (Some(block), Some(when)) => text::AT_BLOCK_WHEN.fill(lang, [&block.to_string(), &when]),
        (Some(block), None) => text::AT_BLOCK.fill(lang, [&block.to_string()]),
        (None, Some(when)) => when,
        (None, None) => String::new(),
    }
}

/// The line under a balance kept from before a failed read (2026-11-12): where the number is
/// from — "블록 N 기준 · HH:MM 이후 갱신 실패" (EVM), "HH:MM 이후 갱신 실패" (no block number).
/// Why it failed is the network card's band.
#[must_use]
pub fn balance_stale_text(lang: Lang, block: Option<u64>, at_unix_ms: Option<u64>) -> String {
    let since = at_unix_ms.map_or_else(
        || text::UPDATE_FAILED.get(lang).to_owned(),
        |at| text::UPDATE_FAILED_SINCE.fill(lang, [&local_hh_mm(at)]),
    );
    match block {
        Some(block) => text::AT_BLOCK_WHEN.fill(lang, [&block.to_string(), &since]),
        None => since,
    }
}

/// The network card's band of a failed balance read (2026-11-10; one line since 2026-11-12):
/// what failed (the code's short name) and its code. The buttons under it are the next step,
/// and the code's whole §7 text is the answer of `RPC 테스트` and of settings. A code without
/// a short name keeps its whole text.
#[must_use]
pub fn balance_failure_text(lang: Lang, code: ErrorCode) -> String {
    match code.short_name_in(lang) {
        Some(name) => text::BALANCE_FAILURE.fill(lang, [name, code.code()]),
        None => code.text_in(lang),
    }
}

/// Every chain's `받기` (S12) command, and every `주소 복사` on S10 (2026-11-11: the account
/// cards' address line and the Zcash 받기 card) — an unverified passphrase's addresses belong
/// to another wallet, so they are not handed out from the main screen either.
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

/// The account cards' address line (2026-11-11, spec/04 §2.6): the user's own address without
/// spaces, the 4 characters after its prefix and the last 4 emphasized
/// (`ui::theme::own_address_spans`), on a flat button whose click copies it (`copy`, off when
/// `enabled` is not; the `주소 복사` of before), then `explorer` — the ↗ icon
/// `탐색기에서 주소 보기` (`App::explorer_address_icon`) when the network has an address page —
/// at the right end. Recipient checks (approval, send, receive) keep the grouped form of §3.3.
#[must_use]
pub fn own_address_row(
    lang: Lang,
    address: &str,
    kind: AddressKind,
    copy: u16,
    enabled: bool,
    explorer: Option<Ctl>,
) -> Item {
    Item::CopyLine {
        value: Ctl::value(
            copy,
            crate::ui::screens_links::T_ADDRESS_COPY.get(lang),
            crate::ui::theme::own_address_spans(address, kind, false),
        )
        .enabled(enabled),
        actions: explorer.into_iter().collect(),
    }
}

/// The receive screens' and the address book's address line (S12, 2026-11-12): the address
/// whole with its ends emphasized like every address (§3.3, `ui::theme::address_spans`; `shown`
/// may still be the older grouped form) on the flat copy button — the `주소 복사` button under
/// the address of before; the command still copies the address itself — and `actions`
/// (Bitcoin's `새 주소`) at the right end.
#[must_use]
pub fn receive_address_row(lang: Lang, shown: &str, copy: u16, actions: Vec<Ctl>) -> Item {
    let spans =
        crate::ui::theme::address_spans(shown).unwrap_or_else(|| vec![(shown.to_owned(), false)]);
    Item::CopyLine {
        value: Ctl::value(
            copy,
            crate::ui::screens_links::T_ADDRESS_COPY.get(lang),
            spans,
        ),
        actions,
    }
}

/// Turns off every `받기` and `주소 복사` control in `items` (unverified-passphrase sessions).
fn disable_receive(items: &mut [Item]) {
    for item in items {
        match item {
            Item::Row(ctls) | Item::LabeledRow(_, ctls) | Item::Toolbar(_, ctls) => {
                for ctl in ctls.iter_mut().filter(|ctl| RECEIVE_IDS.contains(&ctl.id)) {
                    ctl.enabled = false;
                }
            }
            Item::CopyLine { value, .. } if RECEIVE_IDS.contains(&value.id) => {
                value.enabled = false;
            }
            _ => {}
        }
    }
}

/// The `vault.ywv` facts line (review L17): generation and last write time, so a file swapped
/// for an older copy is noticeable.
#[must_use]
pub fn vault_file_text(lang: Lang, generation: u64, written_unix_ms: u64) -> String {
    let wall = yw_win::time::local_wall_ms(written_unix_ms);
    let text = crate::logging::format_utc(wall.unwrap_or(written_unix_ms));
    let short = text.get(..16).unwrap_or(&text).replace('T', " ");
    let when = if wall.is_some() {
        short
    } else {
        format!("{short} UTC")
    };
    text::VAULT_FILE.fill(lang, [&generation.to_string(), &when])
}

/// The banner when the meta remembers a newer `vault.ywv` generation (review L17).
#[must_use]
pub fn rollback_text(lang: Lang, seen: u64, found: u64) -> String {
    text::ROLLBACK.fill(lang, [&seen.to_string(), &found.to_string()])
}

fn header(app: &App, items: &mut Vec<Item>) {
    let lang = app.settings.language;
    if app.passphrase_unverified() {
        items.push(Item::Banner(
            T_ALT_PASS.get(lang).to_owned(),
            Tone::HighRisk,
        ));
    }
    app.meta_failed_items(items);
    app.journal_closed_items(items);
    if app.guard.pending.is_some() && app.screen != Screen::Confirm(Confirm::SettingsFile) {
        // What differs, in plain words with both values (2026-11-08); the safe choice is the
        // primary button and `파일 값 사용…` asks once more (spec/04 §6.7).
        items.push(Item::Banner(
            text::SETTINGS_TAMPERED_BANNER
                .fill(lang, [crate::settings::SETTINGS_TAMPERED_TEXT.get(lang)]),
            Tone::Warn,
        ));
        for line in app.settings_file_lines() {
            items.push(Item::Help(line));
        }
        items.push(Item::Row(vec![
            Ctl::primary(ids::SETTINGS_RESTORE, text::SETTINGS_RESTORE.get(lang)),
            Ctl::button(
                ids::SETTINGS_ACCEPT_FILE,
                text::SETTINGS_ACCEPT_FILE.get(lang),
            ),
        ]));
    }
    for banner in &app.banners {
        items.push(Item::Banner(banner.text.clone(), banner.tone));
    }
    app.yk_pin_needed_items(items);
    if let Some(info) = &app.info {
        items.push(Item::Banner(info.clone(), Tone::Info));
    }
    if !app.banners.is_empty() || app.info.is_some() {
        items.push(Item::Row(vec![Ctl::link(
            ids::DISMISS_BANNERS,
            text::DISMISS_BANNERS.get(lang),
        )]));
    }
}

fn indexer_name(indexer: crate::settings::BtcIndexer) -> &'static str {
    match indexer {
        crate::settings::BtcIndexer::Esplora => "Esplora",
        crate::settings::BtcIndexer::BbRpc => "Blockbook RPC",
        crate::settings::BtcIndexer::BbRest => "Blockbook REST",
    }
}

fn cap_value(lang: Lang, value: &str) -> &str {
    if value.is_empty() {
        text::DEFAULT_VALUE.get(lang)
    } else {
        value
    }
}

impl App {
    /// One plain line per value that differs between the settings in use and `settings.json`
    /// (the settings-file banner and its `파일 값 사용` overlay): the value in use, then the
    /// value in the file, with the JSON key in brackets. Nothing here is secret (spec/04 §6.7).
    #[must_use]
    pub fn settings_file_lines(&self) -> Vec<String> {
        let Some(pending) = self.guard.pending.as_ref() else {
            return Vec::new();
        };
        let (file, differing) = (&pending.0, &pending.1);
        let current = &self.settings;
        let lang = current.language;
        let mut lines = Vec::new();
        for kind in differing {
            match kind {
                crate::settings::Differing::AutoLock => lines.push(text::DIFF_AUTO_LOCK.fill(
                    lang,
                    [
                        &current.auto_lock_minutes.to_string(),
                        &file.auto_lock_minutes.to_string(),
                    ],
                )),
                crate::settings::Differing::FeeCaps => {
                    let mut chains: Vec<u64> = current
                        .fee_caps
                        .iter()
                        .chain(&file.fee_caps)
                        .map(|(id, _)| *id)
                        .collect();
                    chains.sort_unstable();
                    chains.dedup();
                    for id in chains {
                        let caps_of = |settings: &crate::settings::Settings| {
                            settings
                                .fee_caps
                                .iter()
                                .find(|(chain, _)| *chain == id)
                                .map(|(_, caps)| caps.clone())
                        };
                        let (now, then) = (caps_of(current), caps_of(file));
                        if now == then {
                            continue;
                        }
                        let part = |caps: Option<&crate::settings::FeeCapsText>,
                                    pick: fn(&crate::settings::FeeCapsText) -> &str| {
                            caps.map_or(text::DEFAULT_VALUE.get(lang), |caps| {
                                cap_value(lang, pick(caps))
                            })
                            .to_owned()
                        };
                        lines.push(text::DIFF_FEE_CAPS.fill(
                            lang,
                            [
                                &self.network_name(NetworkId::Eip155(id)),
                                &part(now.as_ref(), |caps| &caps.max_fee_per_gas_gwei),
                                &part(then.as_ref(), |caps| &caps.max_fee_per_gas_gwei),
                                &part(now.as_ref(), |caps| &caps.max_priority_fee_per_gas_gwei),
                                &part(then.as_ref(), |caps| &caps.max_priority_fee_per_gas_gwei),
                                &part(now.as_ref(), |caps| &caps.max_total_fee),
                                &part(then.as_ref(), |caps| &caps.max_total_fee),
                            ],
                        ));
                    }
                }
                crate::settings::Differing::Indexer => {
                    let server = |bitcoin: &crate::settings::BitcoinSettings| {
                        format!(
                            "{} (mainnet {} · testnet4 {})",
                            indexer_name(bitcoin.indexer),
                            cap_value(lang, &bitcoin.esplora_mainnet),
                            cap_value(lang, &bitcoin.esplora_testnet4)
                        )
                    };
                    lines.push(
                        text::DIFF_INDEXER
                            .fill(lang, [&server(&current.bitcoin), &server(&file.bitcoin)]),
                    );
                }
                crate::settings::Differing::NewChains => {
                    for chain in file.evm_chains.iter().filter(|chain| {
                        !current
                            .evm_chains
                            .iter()
                            .any(|known| known.chain_id == chain.chain_id)
                    }) {
                        lines.push(
                            text::DIFF_NEW_CHAIN
                                .fill(lang, [&chain.name, &chain.chain_id.to_string()]),
                        );
                    }
                }
            }
        }
        lines
    }
}

impl App {
    /// The recovery card of a wallet with recovery words (settings → 보안): the backup status
    /// when the first phrase is not the only backup (2026-11-08), and the reveal buttons.
    fn backup_card_rows(&self, unlocked: bool, public: bool, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let lines = self.backup_status_lines();
        if lines.is_empty() {
            items.push(Item::Help(text::BACKUP_CARD_HELP.get(lang).to_owned()));
        } else {
            // Several backups (2026-11-08): the first recovery phrase is no longer the
            // whole wallet's backup, so say what each part needs (status only, no values).
            items.push(Item::Subtitle(
                text::BACKUP_STATUS_TITLE.get(lang).to_owned(),
            ));
            for line in lines {
                items.push(Item::Text(line));
            }
            items.push(Item::Help(text::BACKUP_STATUS_HELP.get(lang).to_owned()));
        }
        let several = self.several_mnemonics();
        let mut row = vec![
            Ctl::button(
                ids::REVEAL_MNEMONIC,
                if several {
                    text::REVEAL_FIRST_MNEMONIC.get(lang)
                } else {
                    text::REVEAL_MNEMONIC.get(lang)
                },
            )
            .enabled(public),
            Ctl::button(ids::REVEAL_KEY, text::REVEAL_KEY.get(lang))
                .enabled(unlocked && !self.hardware_selected()),
        ];
        if several {
            row.push(Ctl::link(
                crate::ui::screens_mnemonics::ids::MAIN_LINK,
                text::MANAGE_MNEMONICS.get(lang),
            ));
        }
        items.push(Item::Row(row));
    }

    /// The `내 계정` / `내 Solana 계정` help (2026-11-10): a wallet without recovery words that has
    /// `YubiKey` cards says where their keys' backup is (not the key-only text); a wallet with
    /// words and `YubiKey` accounts says that those come back with the card's own words. Since
    /// 2026-11-12 only what is not backed up by this wallet's words is said: an imported key
    /// always gets its reminder, and a wallet of derived accounts only has no paragraph.
    #[must_use]
    pub(crate) fn accounts_help(&self, has_card: bool, imported: bool) -> Option<String> {
        let lang = self.settings.language;
        if self.key_only() && !self.card.records.is_empty() {
            return Some(if imported {
                format!(
                    "{} {}",
                    T_ACCOUNTS_YUBIKEY.get(lang),
                    T_ACCOUNTS_IMPORTED.get(lang)
                )
            } else {
                T_ACCOUNTS_YUBIKEY.get(lang).to_owned()
            });
        }
        if self.key_only() {
            return Some(T_ACCOUNTS_KEY_ONLY.get(lang).to_owned());
        }
        match (imported, has_card) {
            (true, true) => Some(format!(
                "{} {}",
                T_ACCOUNTS_BACKUP.get(lang),
                T_ACCOUNTS_YUBIKEY_WORDS.get(lang)
            )),
            (true, false) => Some(T_ACCOUNTS_BACKUP.get(lang).to_owned()),
            (false, true) => Some(T_ACCOUNTS_YUBIKEY_WORDS.get(lang).to_owned()),
            (false, false) => None,
        }
    }

    /// The backup status of a wallet whose first recovery phrase is not its only backup
    /// (2026-11-08, settings → 보안): one line per recovery phrase (words, passphrase, quiz),
    /// the imported keys, and one per `YubiKey` key (2026-11-10). Empty for a wallet with one
    /// phrase only.
    #[must_use]
    pub fn backup_status_lines(&self) -> Vec<String> {
        if !self.several_mnemonics()
            && self.imported_key_count() == 0
            && self.card.records.is_empty()
        {
            return Vec::new();
        }
        self.backup_status_all()
    }

    /// The imported keys of every chain.
    fn imported_key_count(&self) -> usize {
        self.meta.as_ref().map_or(0, |meta| {
            meta.evm_raw_accounts.len()
                + meta.sol_raw_accounts.len()
                + meta
                    .btc_accounts
                    .accounts
                    .iter()
                    .filter(|account| account.is_imported())
                    .count()
        })
    }

    /// [`Self::backup_status_lines`] of any wallet (a wallet without recovery words included:
    /// settings → 보안 and S22 show it always, 2026-11-10).
    #[must_use]
    pub fn backup_status_all(&self) -> Vec<String> {
        let lang = self.settings.language;
        let imported = self.imported_key_count();
        let mut lines = Vec::new();
        for info in &self.mn.infos {
            lines.push(text::BACKUP_STATUS_PHRASE.fill(
                lang,
                [
                    &self.mnemonic_label(info.id),
                    &info.words.to_string(),
                    if info.passphrase_used {
                        " + passphrase"
                    } else {
                        ""
                    },
                    if info.primary {
                        text::BACKUP_STATUS_FIRST.get(lang)
                    } else {
                        ""
                    },
                    if info.backup_confirmed {
                        text::BACKUP_CONFIRMED.get(lang)
                    } else {
                        text::BACKUP_NOT_CONFIRMED.get(lang)
                    },
                ],
            ));
        }
        if imported > 0 {
            lines.push(text::BACKUP_STATUS_IMPORTED.fill(lang, [&imported.to_string()]));
        }
        // One line per card key (2026-11-10): where it is, and whether recovery words make it
        // again (a key connected without words is only on its cards).
        let mut seen: Vec<(yw_core::yubikey::plan::Curve, Vec<u32>)> = Vec::new();
        for record in &self.card.records {
            for slot in &record.slots {
                let identity = slot.role.key_identity();
                if seen.contains(&identity) {
                    continue;
                }
                seen.push(identity);
                let holders: Vec<String> = crate::yubikey::holders(&self.card.records, slot.role)
                    .iter()
                    .map(|serial| format!("#{serial}"))
                    .collect();
                let cards = holders.join("·");
                let title = slot.role.title_in(lang);
                lines.push(
                    if yw_core::yubikey::plan::is_unknown_index(slot.role.index()) {
                        if holders.len() > 1 {
                            text::BACKUP_STATUS_CARD_ON.fill(lang, [&title, &cards])
                        } else {
                            text::BACKUP_STATUS_CARD_ONLY.fill(lang, [&title, &cards])
                        }
                    } else {
                        text::BACKUP_STATUS_CARD_WORDS.fill(lang, [&title, &cards])
                    },
                );
            }
        }
        lines
    }
}

/// The one line under the settings tabs, only where something people look for in this section
/// lives elsewhere (spec/04 §2.11). The list of the section's cards that used to open every
/// section ("이 구역: …") repeated the card headings right below it and is gone (2026-11-12).
#[must_use]
pub const fn settings_elsewhere(lang: Lang, section: SettingsSection) -> Option<&'static str> {
    let text = match section {
        SettingsSection::Security => text::ELSEWHERE_SECURITY,
        SettingsSection::Chains => text::ELSEWHERE_CHAINS,
        SettingsSection::Bitcoin => text::ELSEWHERE_BITCOIN,
        SettingsSection::YubiKey => text::ELSEWHERE_YUBIKEY,
        SettingsSection::Other => text::ELSEWHERE_OTHER,
        SettingsSection::Network
        | SettingsSection::Solana
        | SettingsSection::Ai
        | SettingsSection::Mnemonics => return None,
    };
    Some(text.get(lang))
}

/// The items of the current screen.
impl App {
    /// Builds the current screen.
    #[must_use]
    pub fn items(&self) -> Vec<Item> {
        let lang = self.settings.language;
        let mut items = Vec::new();
        if self.screen == Screen::Main {
            items.push(Item::Toolbar(
                "Your Wallet".to_owned(),
                vec![
                    Ctl::button(
                        crate::ui::screens_evm::ids::BOOK_OPEN,
                        text::ADDRESS_BOOK.get(lang),
                    ),
                    Ctl::button(
                        crate::ui::screens_sites::ids::SITES_OPEN,
                        text::SITES_WC.get(lang),
                    ),
                    // Shortcuts in the tooltips (2026-11-12; "잠금 (Ctrl+L)" in the label before).
                    Ctl::button(ids::OPEN_SETTINGS, text::SETTINGS.get(lang))
                        .tip(text::SETTINGS_TIP.get(lang)),
                    Ctl::button(ids::LOCK, text::LOCK.get(lang)).tip(text::LOCK_TIP.get(lang)),
                ],
            ));
        }
        header(self, &mut items);
        match &self.screen {
            Screen::Starting => items.push(Item::Muted(text::STARTING.get(lang).to_owned())),
            Screen::FirstRun => self.first_run(&mut items),
            Screen::CreateIntro => Self::create_intro(lang, &mut items),
            Screen::Processing(text) => {
                items.push(Item::Gap(40));
                items.push(Item::CardStart(None));
                items.push(Item::Subtitle(text::PLEASE_WAIT.get(lang).to_owned()));
                items.push(Item::Text((*text).to_owned()));
                items.push(Item::CardEnd);
                if self.wait.stalled {
                    self.wait_stalled(&mut items);
                }
            }
            Screen::BackupPending => Self::backup_pending(lang, &mut items),
            Screen::Reset => self.reset_screen(&mut items),
            Screen::Extension => self.extension_screen(&mut items),
            Screen::HyperCore => self.hc_screen(&mut items),
            Screen::ImportIntro => Self::import_intro(lang, &mut items),
            Screen::ImportAddress(address) => Self::import_address(lang, address, &mut items),
            Screen::Locked => self.locked(&mut items),
            Screen::PassMismatch => self.pass_mismatch(&mut items),
            Screen::Done => self.done(&mut items),
            Screen::Recovery => self.recovery(&mut items),
            Screen::Main => self.main_screen(&mut items),
            Screen::Settings(section) => self.settings_screen(*section, &mut items),
            Screen::Confirm(kind) => self.confirm(*kind, &mut items),
            Screen::Send => self.send_screen(&mut items),
            Screen::SendResult => self.send_result_screen(&mut items),
            Screen::Receive => self.receive_screen(&mut items),
            Screen::AddressBook => self.book_screen(&mut items),
            Screen::TokenAdd => self.token_screen(&mut items),
            Screen::ChainEdit => self.chain_edit_screen(&mut items),
            Screen::Sites => self.sites_screen(&mut items),
            Screen::SolSend => self.sol_send_screen(&mut items),
            Screen::SolSendResult => self.sol_send_result_screen(&mut items),
            Screen::SolReceive => self.sol_receive_screen(&mut items),
            Screen::SolScan => self.sol_scan_screen(&mut items),
            Screen::BtcSend => self.btc_send_screen(&mut items),
            Screen::BtcSendResult => self.btc_send_result_screen(&mut items),
            Screen::BtcBump => self.btc_bump_screen(&mut items),
            Screen::BtcReceive => self.btc_receive_screen(&mut items),
            Screen::KeyStartIntro => self.key_start_intro(&mut items),
            Screen::KeyStartAddress(view) => self.key_start_address(view, &mut items),
            Screen::YubiKey => self.yk_wizard_screen(&mut items),
            Screen::YubiKeyWalletIntro => self.yk_wallet_intro(&mut items),
        }
        if self.passphrase_unverified() {
            disable_receive(&mut items);
        }
        // The copy just made says so at its own control (2026-11-12, `App::copy_text`).
        if let Some(copied) = self.copied {
            crate::ui::main_window::mark_copied(lang, &mut items, copied.id, copied.address);
        }
        items
    }

    fn first_run(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Gap(24));
        items.push(Item::Display("Your Wallet".to_owned()));
        items.push(Item::Gap(4));
        // The first two sentences are true for every path; the third (24 words are the only
        // backup) belongs to the new-wallet card (2026-11-08).
        for sentence in &T_FIRST[..2] {
            items.push(Item::Text(sentence.get(lang).to_owned()));
        }
        items.push(Item::Gap(8));
        if self.leftover {
            items.push(Item::Banner(
                text::LEFTOVER.get(lang).to_owned(),
                Tone::Warn,
            ));
            items.push(Item::Mono(self.paths.data.display().to_string()));
            items.push(Item::Row(vec![
                Ctl::button(ids::OPEN_DATA_FOLDER, text::OPEN_FOLDER.get(lang)),
                Ctl::link(
                    crate::ui::screens_reset::ids::RESET_OPEN,
                    text::LEFTOVER_MOVE.get(lang),
                ),
            ]));
        }
        // Two groups (2026-11-08): start something new, or bring back a wallet already used;
        // all five ways are on the first view of the default window.
        let enabled = !self.leftover;
        items.push(Item::CardStart(Some(
            text::FIRST_NEW_TITLE.get(lang).to_owned(),
        )));
        items.push(Item::Text(text::FIRST_NEW_TEXT.get(lang).to_owned()));
        items.push(Item::Help(T_FIRST[2].get(lang).to_owned()));
        items.push(Item::Row(vec![
            Ctl::primary(ids::FIRST_CREATE, text::CREATE_WALLET.get(lang)).enabled(enabled),
            Ctl::button(
                crate::ui::screens_yubikey::ids::NEW_WALLET,
                text::FIRST_YK_WALLET.get(lang),
            )
            .enabled(enabled),
        ]));
        items.push(Item::Help(
            text::FIRST_YK_WALLET_HELP.fill(lang, [crate::app_yubikey::text::YK_WALLET.get(lang)]),
        ));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            text::FIRST_EXISTING_TITLE.get(lang).to_owned(),
        )));
        items.push(Item::Row(vec![
            Ctl::button(ids::FIRST_IMPORT, text::FIRST_IMPORT.get(lang)).enabled(enabled),
            Ctl::button(
                crate::ui::screens_keys::ids::FIRST_KEY,
                text::FIRST_KEY.get(lang),
            )
            .enabled(enabled),
            Ctl::button(
                crate::ui::screens_yubikey::ids::CONNECT_NEW_WALLET,
                text::FIRST_YK_CONNECT.get(lang),
            )
            .enabled(enabled),
        ]));
        for line in [
            text::FIRST_IMPORT_HELP.get(lang).to_owned(),
            text::FIRST_KEY_HELP.fill(
                lang,
                [crate::ui::screens_keys::text::KEY_START_CARD.get(lang)],
            ),
            text::FIRST_YK_CONNECT_HELP.get(lang).to_owned(),
        ] {
            items.push(Item::Help(line));
        }
        items.push(Item::CardEnd);
    }

    fn create_intro(lang: Lang, items: &mut Vec<Item>) {
        items.push(Item::Title(text::CREATE_WALLET.get(lang).to_owned()));
        items.push(steps(CREATE_STEPS.map(|step| step.get(lang)), 0));
        items.push(Item::CardStart(Some(
            text::BEFORE_START.get(lang).to_owned(),
        )));
        for line in [
            text::CREATE_INTRO_1,
            text::CREATE_INTRO_2,
            text::CREATE_INTRO_3,
        ] {
            items.push(Item::Text(line.get(lang).to_owned()));
        }
        items.push(Item::Help(text::CREATE_INTRO_HELP.get(lang).to_owned()));
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::primary(ids::CREATE_NEXT, text::START.get(lang)),
            Ctl::button(ids::INTRO_CANCEL, text::CANCEL.get(lang)),
        ]));
    }

    fn backup_pending(lang: Lang, items: &mut Vec<Item>) {
        items.push(Item::Title(text::BACKUP_PENDING_TITLE.get(lang).to_owned()));
        items.push(Item::Banner(
            text::BACKUP_PENDING_BANNER.get(lang).to_owned(),
            Tone::Warn,
        ));
        items.push(Item::CardStart(None));
        items.push(Item::Text(text::BACKUP_PENDING_TEXT.get(lang).to_owned()));
        items.push(Item::Row(vec![
            Ctl::primary(ids::BACKUP_CHECK, text::BACKUP_CHECK.get(lang)),
            Ctl::button(
                crate::ui::screens_evm::ids::RECEIVE_OPEN,
                text::RECEIVE.get(lang),
            ),
            Ctl::button(ids::LOCK, text::LOCK.get(lang)),
        ]));
        items.push(Item::CardEnd);
        Self::reset_link(lang, items, text::BACKUP_PENDING_RESET.get(lang));
    }

    fn import_intro(lang: Lang, items: &mut Vec<Item>) {
        items.push(Item::Title(text::IMPORT_WALLET.get(lang).to_owned()));
        items.push(steps(IMPORT_STEPS.map(|step| step.get(lang)), 0));
        items.push(Item::CardStart(Some(
            text::IMPORT_NEED_TITLE.get(lang).to_owned(),
        )));
        items.push(Item::Text(text::IMPORT_NEED_WORDS.get(lang).to_owned()));
        items.push(Item::Text(
            text::IMPORT_NEED_PASSPHRASE.get(lang).to_owned(),
        ));
        items.push(Item::Help(text::IMPORT_KEY_HINT.get(lang).to_owned()));
        items.push(Item::Help(
            crate::app_btc::BTC_IMPORT_NOTE.get(lang).to_owned(),
        ));
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::primary(ids::IMPORT_NEXT, text::START.get(lang)),
            Ctl::button(ids::INTRO_CANCEL, text::CANCEL.get(lang)),
        ]));
    }

    fn import_address(lang: Lang, address: &str, items: &mut Vec<Item>) {
        items.push(Item::Title(text::STEP_FIRST_ADDRESS.get(lang).to_owned()));
        items.push(steps(IMPORT_STEPS.map(|step| step.get(lang)), 3));
        items.push(Item::CardStart(None));
        items.push(Item::Text(text::IMPORT_ADDRESS_TEXT.get(lang).to_owned()));
        let shown = yw_core::evm::address::parse_address(address)
            .map_or_else(|_| address.to_owned(), |parsed| format_address(&parsed));
        items.push(Item::Mono(shown));
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::primary(ids::IMPORT_CORRECT, text::IMPORT_CORRECT.get(lang)),
            Ctl::button(ids::IMPORT_WRONG, text::IMPORT_WRONG.get(lang)),
        ]));
        items.push(Item::Help(text::IMPORT_ADDRESS_HELP.get(lang).to_owned()));
    }

    fn locked(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Gap(48));
        items.push(Item::Display(text::LOCKED_TITLE.get(lang).to_owned()));
        items.push(Item::Text(text::LOCKED_TEXT.get(lang).to_owned()));
        if let Some(pending) = self.unlock_pending_text() {
            items.push(Item::Banner(pending, Tone::Info));
        }
        // The screen's one action, wider than a default button; the way out for a lost password
        // is a single row at the bottom (2026-11-12).
        items.push(Item::Gap(4));
        items.push(Item::Row(vec![
            Ctl::primary(ids::UNLOCK, text::UNLOCK.get(lang)).width(160),
        ]));
        items.push(Item::Help(
            text::LOCKED_AUTO_LOCK.fill(lang, [&self.settings.auto_lock_minutes.to_string()]),
        ));
        if let Some((generation, written)) = self.guard.vault_file {
            items.push(Item::Muted(vault_file_text(lang, generation, written)));
        }
        if self.unlock_failed && self.prev_on_disk && self.mode == AppMode::Locked {
            // spec/02 §6.3: a damaged key section is indistinguishable from a wrong password.
            items.push(Item::Gap(8));
            items.push(Item::Help(text::LOCKED_DAMAGED.get(lang).to_owned()));
            items.push(Item::Row(vec![Ctl::link(
                ids::RECOVER,
                text::RECOVER_PREV.get(lang),
            )]));
        }
        // What a reset does (the files are moved, not deleted) is the first band of S22.
        items.push(Item::Gap(16));
        items.push(Item::LabeledRow(
            text::FORGOT_PASSWORD.get(lang).to_owned(),
            vec![Ctl::link(
                crate::ui::screens_reset::ids::RESET_OPEN,
                text::RESET_WALLET.get(lang),
            )],
        ));
    }

    fn pass_mismatch(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Title(text::MISMATCH_TITLE.get(lang).to_owned()));
        items.push(Item::Banner(
            text::MISMATCH_BANNER.get(lang).to_owned(),
            Tone::Warn,
        ));
        items.push(Item::CardStart(None));
        items.push(Item::Row(vec![Ctl::check(
            ids::MISMATCH_CHECK,
            text::MISMATCH_CHECK.get(lang),
            self.mismatch_checked,
        )]));
        items.push(Item::Row(vec![
            Ctl::primary(ids::MISMATCH_RETRY, text::MISMATCH_RETRY.get(lang)),
            Ctl::button(ids::MISMATCH_CONTINUE, text::MISMATCH_CONTINUE.get(lang))
                .enabled(self.mismatch_checked),
        ]));
        items.push(Item::CardEnd);
    }

    fn done(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Title(text::DONE_TITLE.get(lang).to_owned()));
        if let Some(done) = self.done_yubikey {
            let (banner, backup) = match done {
                crate::app_yubikey::YkDone::Created(serial) => (
                    text::DONE_YK_CREATED.fill(lang, [&serial.to_string()]),
                    text::DONE_YK_CREATED_BACKUP,
                ),
                crate::app_yubikey::YkDone::Connected(serial) => (
                    text::DONE_YK_CONNECTED.fill(lang, [&serial.to_string()]),
                    text::DONE_YK_CONNECTED_BACKUP,
                ),
            };
            items.push(Item::Banner(banner, Tone::Success));
            items.push(Item::Help(backup.get(lang).to_owned()));
        } else if self.keys.done_start {
            items.push(Item::Banner(
                crate::ui::screens_keys::text::KEY_START_OK
                    .get(self.settings.language)
                    .to_owned(),
                Tone::Success,
            ));
            items.push(Item::Banner(
                crate::ui::screens_keys::text::KEY_START_BACKUP
                    .get(self.settings.language)
                    .to_owned(),
                Tone::Warn,
            ));
        } else if self.done_imported {
            // No backup check runs on import: the words came from the user's existing backup.
            items.push(Item::Banner(
                text::DONE_IMPORTED.get(lang).to_owned(),
                Tone::Success,
            ));
            items.push(Item::Help(text::DONE_IMPORTED_BACKUP.get(lang).to_owned()));
        } else {
            items.push(Item::Banner(
                text::DONE_BACKUP_OK.get(lang).to_owned(),
                Tone::Success,
            ));
        }
        // One '처음 설정' card (2026-11-10): RPC, the optional dApp connection, a first small
        // deposit; `지갑 열기` always below it.
        items.push(Item::CardStart(Some(text::DONE_SETUP.get(lang).to_owned())));
        self.done_rpc_items(items);
        items.push(Item::Rule);
        self.done_dapp_items(items);
        items.push(Item::Rule);
        self.done_deposit_items(items);
        items.push(Item::CardEnd);
        if self.done_imported || self.keys.done_start {
            self.done_balance_card(items);
        }
        items.push(Item::Row(vec![Ctl::primary(
            ids::DONE_CONTINUE,
            text::DONE_OPEN_WALLET.get(lang),
        )]));
    }

    /// S08 ① 블록체인 연결(RPC): the `QuickNode` address field while there is no address, the
    /// results of `연결하기`, or how many addresses there are and this run's tests.
    fn done_rpc_items(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Subtitle(text::DONE_RPC_TITLE.get(lang).to_owned()));
        if !self.done_tested.is_empty() {
            self.done_results(items);
            return;
        }
        if !self.apikeys.endpoints().is_empty() {
            let (configured, _, works, failed, _) = self.rpc_summary();
            items.push(Item::Text(text::DONE_RPC_SUMMARY.fill(
                lang,
                [
                    &configured.to_string(),
                    &works.to_string(),
                    &failed.to_string(),
                ],
            )));
            items.push(Item::Row(vec![Ctl::button(
                ids::DONE_RPC,
                text::OPEN_RPC_SETTINGS.get(lang),
            )]));
            return;
        }
        items.push(Item::Text(text::DONE_RPC_NEED.get(lang).to_owned()));
        if self.settings.rpc_template == RpcTemplate::QuickNode {
            items.push(Item::LabeledRow(
                text::QUICKNODE_ADDRESS.get(lang).to_owned(),
                vec![Ctl::edit(ids::DONE_QN_EDIT, "", 520, true, 256)],
            ));
            items.push(Item::Help(text::T_DONE_QUICKNODE.get(lang).to_owned()));
            if let Some(error) = &self.done_error {
                items.push(Item::Banner(error.clone(), Tone::Danger));
            }
            items.push(Item::Row(vec![
                Ctl::primary(ids::DONE_CONNECT, text::DONE_CONNECT.get(lang)),
                Ctl::link(ids::DONE_RPC, text::DONE_OTHER_PROVIDERS.get(lang)),
            ]));
        } else {
            items.push(Item::Help(text::DONE_PROVIDER_HELP.get(lang).to_owned()));
            items.push(Item::Row(vec![Ctl::button(
                ids::DONE_RPC,
                text::DONE_SET_RPC.get(lang),
            )]));
        }
        if crate::app_rpc_import::rpc_json_path().is_some_and(|path| path.is_file()) {
            items.push(Item::Row(vec![Ctl::link(
                ids::DONE_RPC_JSON,
                text::DONE_RPC_JSON.get(lang),
            )]));
        }
    }

    /// S08 after `연결하기`: one line per network made (✓ works / ✗ with its §7 text and a link to
    /// its row / … testing), then the count — with how many are still being tested, so a short
    /// count while the queue runs does not read as failures.
    fn done_results(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let networks = self.url_networks();
        let mut works = 0_usize;
        let mut testing = 0_usize;
        let mut failed = false;
        for network in &self.done_tested {
            let name = self.network_name(*network);
            match self
                .rpc_messages
                .iter()
                .find(|(id, _, _)| id == network)
                .map(|(_, message, state)| (message, *state))
            {
                Some((_, TestState::Works)) => {
                    works = works.saturating_add(1);
                    items.push(Item::Text(format!("✓ {name}")));
                }
                Some((message, TestState::Failed)) => {
                    failed = true;
                    items.push(Item::Banner(format!("✗ {name} — {message}"), Tone::Danger));
                    if let Some(row) = networks
                        .iter()
                        .position(|known| known == network)
                        .and_then(|row| u16::try_from(row).ok())
                        .filter(|row| *row < ids::RPC_ROW_OPEN_SPAN)
                    {
                        items.push(Item::Row(vec![Ctl::link(
                            ids::RPC_ROW_OPEN_BASE.saturating_add(row),
                            &text::OPEN_ROW.fill(lang, [&name]),
                        )]));
                    }
                }
                Some((_, TestState::Testing)) | None => {
                    testing = testing.saturating_add(1);
                    items.push(Item::Muted(text::TESTING_NAME.fill(lang, [&name])));
                }
            }
        }
        let total = self.done_tested.len();
        let (total, works) = (total.to_string(), works.to_string());
        items.push(Item::Subtitle(if testing == 0 {
            text::WORKS_OF.fill(lang, [&total, &works])
        } else {
            text::WORKS_OF_TESTING.fill(lang, [&total, &works, &testing.to_string()])
        }));
        if failed {
            items.push(Item::Help(text::DONE_FAILED_HELP.get(lang).to_owned()));
        }
        items.push(Item::Row(vec![Ctl::button(
            ids::DONE_RPC,
            text::OPEN_RPC_SETTINGS.get(lang),
        )]));
    }

    /// S08 ② dApp 연결 (선택): the Chrome extension or `WalletConnect`.
    fn done_dapp_items(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Subtitle(text::DONE_DAPP_TITLE.get(lang).to_owned()));
        items.push(Item::Text(
            text::CHROME_EXTENSION_STATUS.fill(lang, [self.extension_status().text_in(lang)]),
        ));
        items.push(Item::Row(vec![Ctl::button(
            crate::ui::screens_reset::ids::EXT_OPEN,
            text::HOW_TO_INSTALL.get(lang),
        )]));
        items.push(Item::Text(format!(
            "WalletConnect: {}",
            if self.settings.walletconnect_project.is_empty() {
                text::NO_PROJECT_ID.get(lang)
            } else {
                text::CONFIGURED.get(lang)
            }
        )));
        items.push(Item::Row(vec![Ctl::button(
            ids::DONE_WC,
            text::SETTINGS.get(lang),
        )]));
    }

    /// S08 ③ 첫 입금 시험: receive on the wallet's first chain (EVM when it has an account).
    fn done_deposit_items(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Subtitle(
            text::DONE_DEPOSIT_TITLE.get(lang).to_owned(),
        ));
        let evm = self.selected_account().is_some();
        let mut line = text::DONE_DEPOSIT_TEXT.get(lang).to_owned();
        if evm {
            if self.settings.evm_chain_id == SEPOLIA {
                line.push_str(text::DONE_DEPOSIT_SEPOLIA.get(lang));
            } else {
                line.push_str(&text::DONE_DEPOSIT_NETWORK.fill(
                    lang,
                    [&self.network_name(NetworkId::Eip155(self.settings.evm_chain_id))],
                ));
            }
        }
        items.push(Item::Text(line));
        let receive = if evm {
            Some(crate::ui::screens_evm::ids::RECEIVE_OPEN)
        } else if self.sol_selected().is_some() {
            Some(crate::ui::screens_sol::ids::RECEIVE_OPEN)
        } else if self.settings.bitcoin.enabled {
            Some(crate::ui::screens_btc::ids::RECEIVE_OPEN)
        } else {
            None
        };
        if let Some(id) = receive {
            items.push(Item::Row(vec![Ctl::button(id, text::RECEIVE.get(lang))]));
        }
    }

    /// S08 after an import or "개인키로 시작하기": why a wallet that held funds may show none
    /// (the network, accounts not searched, chains off).
    fn done_balance_card(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let mut lines: Vec<Item> = Vec::new();
        if self.selected_account().is_some() {
            if self.settings.evm_chain_id == SEPOLIA {
                lines.push(Item::Text(text::DONE_BALANCE_SEPOLIA.get(lang).to_owned()));
                lines.push(Item::Row(vec![Ctl::button(
                    ids::DONE_MAINNET,
                    text::DONE_SHOW_MAINNET.get(lang),
                )]));
            } else {
                lines.push(Item::Text(text::DONE_BALANCE_NETWORK.fill(
                    lang,
                    [&self.network_name(NetworkId::Eip155(self.settings.evm_chain_id))],
                )));
            }
        }
        if self.done_imported {
            lines.push(Item::Text(text::DONE_BALANCE_ACCOUNTS.get(lang).to_owned()));
            let bitcoin = !self.settings.bitcoin.enabled;
            let zcash = !self.settings.zcash.enabled;
            let off = match (bitcoin, zcash) {
                (true, true) => Some(text::DONE_OFF_BOTH),
                (true, false) => Some(text::DONE_OFF_BITCOIN),
                (false, true) => Some(text::DONE_OFF_ZCASH),
                (false, false) => None,
            };
            if let Some(line) = off {
                lines.push(Item::Text(line.get(lang).to_owned()));
            }
        }
        if lines.is_empty() {
            return;
        }
        items.push(Item::CardStart(Some(
            text::DONE_NO_BALANCE.get(lang).to_owned(),
        )));
        items.extend(lines);
        items.push(Item::CardEnd);
    }

    fn recovery(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Title(text::RECOVERY_TITLE.get(lang).to_owned()));
        items.push(Item::CardStart(None));
        let prev = match self.mode {
            AppMode::Corrupt { prev_available } => {
                let code = if self.payload_damaged {
                    ErrorCode::Vlt008
                } else {
                    ErrorCode::Vlt002
                };
                items.push(Item::Banner(code.text_in(lang), Tone::Danger));
                prev_available
            }
            AppMode::MainMissing => {
                items.push(Item::Text(text::RECOVERY_MISSING.get(lang).to_owned()));
                true
            }
            _ => false,
        };
        if prev {
            items.push(Item::Help(text::RECOVERY_PREV_HELP.get(lang).to_owned()));
        }
        items.push(Item::Field(
            text::DATA_FOLDER.get(lang).to_owned(),
            self.paths.data.display().to_string(),
        ));
        let mut row = Vec::new();
        if prev {
            row.push(Ctl::primary(ids::RECOVER, text::RECOVERY_RESTORE.get(lang)));
        }
        row.push(Ctl::button(
            ids::OPEN_DATA_FOLDER,
            text::OPEN_FOLDER.get(lang),
        ));
        row.push(Ctl::button(ids::EXIT, text::EXIT.get(lang)));
        items.push(Item::Row(row));
        items.push(Item::CardEnd);
        items.push(Item::Help(
            text::RECOVERY_NEVER_DELETES.get(lang).to_owned(),
        ));
        Self::reset_link(lang, items, text::RECOVERY_RESET.get(lang));
    }

    /// The selected EVM account's hero card: name, big balance, address, 보내기 / 받기.
    #[expect(
        clippy::too_many_lines,
        reason = "the hero card's balance states in order"
    )]
    fn evm_hero(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let chain_id = self.settings.evm_chain_id;
        let Some((address, source, label)) = self.selected_account() else {
            return;
        };
        items.push(Item::CardStart(None));
        items.push(Item::Subtitle(self.evm_account_title(source, &label)));
        items.push(Item::Help(self.evm_path_text(source)));
        self.mn_signing_banner(self.evm_backup_gate(source), items);
        self.card_pin_banner(self.evm_card_gate(source), items);
        let balance = self.native_balance(chain_id, &address);
        let state = self.evm.balances.get(&chain_id);
        let endpoint = self.apikeys.has(KeyName::Rpc(NetworkId::Eip155(chain_id)));
        let blocked = self.evm.blocked(chain_id).is_some();
        let error = state.and_then(|state| state.error);
        let block = state
            .and_then(|state| state.snapshot.as_ref())
            .map(|snapshot| snapshot.block);
        // Three states under the big balance (2026-11-10): loading, read at block N, or failed —
        // the failure is explained once, by the network card above (`evm_balance_failure`).
        match (balance, error) {
            (Some(value), Some(code)) if blocked => {
                // A blocked chain keeps its band and this caption (U17 and E-RPC-006 as before).
                items.push(Item::Display(self.native_text(chain_id, &value)));
                if let Some(block) = block {
                    items.push(Item::Help(
                        text::AT_BLOCK_FAILED.fill(lang, [&block.to_string(), code.code()]),
                    ));
                }
            }
            (Some(value), Some(_)) => {
                // The earlier value, dimmed, and where it is from (2026-11-12: not "잔액을
                // 읽지 못했습니다" under a balance).
                items.push(Item::DisplayMuted(self.native_text(chain_id, &value)));
                items.push(Item::Help(balance_stale_text(
                    lang,
                    block,
                    state.and_then(|state| state.updated_unix_ms),
                )));
            }
            (Some(value), None) => {
                items.push(Item::Display(self.native_text(chain_id, &value)));
                if let Some(block) = block {
                    items.push(Item::Help(balance_read_text(
                        lang,
                        Some(block),
                        state.and_then(|state| state.updated_unix_ms),
                    )));
                }
            }
            (None, _) if !endpoint => {
                items.push(Item::Display(text::BALANCE_NONE.get(lang).to_owned()));
                items.push(Item::Help(no_endpoint_text(
                    lang,
                    &self.network_name(NetworkId::Eip155(chain_id)),
                )));
            }
            (None, Some(_)) if !blocked => {
                items.push(Item::Display(text::BALANCE_NONE.get(lang).to_owned()));
                items.push(Item::Help(T_BALANCE_FAILED.get(lang).to_owned()));
            }
            (None, Some(_)) => {
                items.push(Item::Display(text::BALANCE_NONE.get(lang).to_owned()));
                items.push(Item::Help(text::BALANCE_NOT_YET.get(lang).to_owned()));
            }
            (None, None) => {
                items.push(Item::Display(text::BALANCE_NONE.get(lang).to_owned()));
                items.push(Item::Help(T_BALANCE_LOADING.get(lang).to_owned()));
            }
        }
        // The visible tokens with a balance, like the Solana tab's one-line summary.
        let tokens: Vec<String> = self
            .evm_token_rows(chain_id)
            .iter()
            .filter(|row| row.place == crate::token_view::RowPlace::Shown)
            .filter_map(|row| {
                row.balance.filter(|value| !value.is_zero()).map(|value| {
                    yw_core::evm::amount::format_amount(&value, row.decimals, &row.symbol)
                })
            })
            .take(4)
            .collect();
        if !tokens.is_empty() {
            items.push(Item::Help(
                text::TOKENS_LINE.fill(lang, [&tokens.join(" · ")]),
            ));
        }
        // The own address whole, its ends emphasized, with `주소 복사` on the same line
        // (2026-11-11; recipient checks elsewhere keep the grouped form).
        items.push(self.own_address_line(
            NetworkId::Eip155(chain_id),
            &address.to_checksum(),
            AddressKind::Evm,
            crate::ui::screens_evm::ids::COPY_ADDRESS,
            true,
            crate::ui::screens_explorer::ids::CARD_EVM,
        ));
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        let mut row = vec![
            Ctl::primary(crate::ui::screens_evm::ids::SEND_OPEN, text::SEND.get(lang))
                .enabled(unlocked),
            Ctl::primary(
                crate::ui::screens_evm::ids::RECEIVE_OPEN,
                text::RECEIVE.get(lang),
            ),
        ];
        if endpoint {
            row.push(
                Ctl::link(
                    crate::ui::screens_evm::ids::REFRESH,
                    text::REFRESH.get(lang),
                )
                .tip(T_REFRESH_TIP.get(lang)),
            );
        } else {
            // Nothing to refresh without an address: that network's row with its field open
            // (spec/04 §2.6, 2026-11-10).
            row.push(Ctl::button(ids::EVM_RPC_OPEN, text::DONE_SET_RPC.get(lang)));
        }
        items.push(Item::Row(row));
        items.push(Item::CardEnd);
    }

    #[expect(clippy::too_many_lines, reason = "the S10 sections in order")]
    fn main_screen(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        // T-ALT-PASS is drawn by `header` on every screen.
        self.tab_row(items);
        if self.sol_tab_active() {
            // The cluster band is the tab's own (`sol_cluster_banner`, one per screen; 2026-11-10:
            // a second T-MAINNET above the tab was drawn here since 11-08).
            self.sol_main_screen(items);
            return;
        }
        if self.zec_tab_active() {
            self.zec_main_screen(items);
            return;
        }
        if self.btc_tab_active() {
            // Imported keys are accounts of the Bitcoin account list (a key-only wallet has
            // only those).
            self.btc_main_screen(items);
            return;
        }
        items.push(Item::CardStart(None));
        // One drop-down instead of a grid of chips (2026-11-11): the selected network with its
        // badge, and the network tag on the same line; open, the list hangs under it (each
        // entry is the chip of before: same ids, same handler).
        let selected = self.settings.evm_chain_id;
        let open = self.evm.network_picker;
        let chains = self.settings.registered_evm();
        let labels: Vec<String> = chains
            .iter()
            .take(usize::from(ids::NETWORK_SPAN))
            .map(|chain_id| self.network_choice_label(*chain_id))
            .collect();
        items.push(Item::LabeledRow(
            text::NETWORK.get(lang).to_owned(),
            vec![
                Ctl::picker(
                    crate::ui::screens_evm::ids::NETWORK_PICKER,
                    &self.network_choice_label(selected),
                    open,
                )
                .badge(self.evm_badge(selected))
                .fit(labels.iter().map(String::as_str)),
            ],
        ));
        if selected == SEPOLIA {
            items.push(Item::Pill(
                text::TESTNET_PILL.get(lang).to_owned(),
                Tone::Testnet,
            ));
        } else if yw_core::evm::chain::is_builtin_mainnet(selected) {
            // The built-in mainnets (user chains carry no testnet flag, so no tag).
            items.push(Item::Pill(T_MAINNET.get(lang).to_owned(), Tone::BtcMainnet));
        }
        if open {
            items.push(Item::Menu(
                chains
                    .iter()
                    .take(usize::from(ids::NETWORK_SPAN))
                    .enumerate()
                    .map(|(index, chain_id)| {
                        Ctl::entry(
                            ids::NETWORK_BASE.saturating_add(u16::try_from(index).unwrap_or(0)),
                            &self.network_choice_label(*chain_id),
                            *chain_id == selected,
                        )
                        .badge(self.evm_badge(*chain_id))
                    })
                    .collect(),
            ));
        }
        self.evm_banners(items);
        self.evm_balance_failure(items);
        items.push(Item::Help(self.evm_status_line()));
        items.push(Item::CardEnd);
        if self.account_rows().is_empty() && self.meta.is_some() {
            self.no_accounts_card(yw_core::keyimport::ImportChain::Evm, items);
            return;
        }
        self.evm_hero(items);
        items.push(Item::CardStart(Some(
            text::MY_ACCOUNTS.get(lang).to_owned(),
        )));
        let selected = self.selected_pref();
        let rows = self.account_rows();
        let has_card = rows
            .iter()
            .any(|(pref, ..)| matches!(pref, EvmAccountPref::Hardware(_)));
        let imported = self
            .meta
            .as_ref()
            .is_some_and(|meta| !meta.evm_raw_accounts.is_empty());
        if let Some(help) = self.accounts_help(has_card, imported) {
            items.push(Item::Help(help));
        }
        // A drop-down like the network's (2026-11-11): the selected account on its button, the
        // accounts under it while open (each keeps the id its radio had); the selected
        // account's actions follow (2026-11-12: its path, balance and address are the hero
        // card's and are not said again here).
        let mut entries = Vec::new();
        let mut chosen = None;
        for (row, (pref, label, ..)) in rows
            .into_iter()
            .take(usize::from(ids::ACCOUNT_SPAN))
            .enumerate()
        {
            let is_selected = selected == Some(pref);
            let tag = match pref {
                EvmAccountPref::Record(_) => Some(text::IMPORTED_KEY_TAG.get(lang).to_owned()),
                EvmAccountPref::Hardware(_) => Some("YubiKey".to_owned()),
                EvmAccountPref::Index(_) => self.mnemonic_tag(None),
                EvmAccountPref::Mnemonic(id, _) => self.mnemonic_tag(Some(id)),
            };
            entries.push(crate::ui::screens_links::PickerEntry {
                id: ids::ACCOUNT_BASE.saturating_add(u16::try_from(row).unwrap_or(0)),
                label: tag.map_or_else(|| label.clone(), |tag| format!("{label} · {tag}")),
                selected: is_selected,
                enabled: true,
            });
            if is_selected {
                chosen = Some((pref, label));
            }
        }
        if !entries.is_empty() {
            self.push_account_picker(items, crate::ui::screens_links::ids::PICKER_EVM, &entries);
        }
        if let Some((pref, label)) = chosen {
            if self.rename == Some(pref) {
                items.push(Item::Row(vec![
                    Ctl::edit(ids::RENAME_EDIT, &label, 260, false, 64),
                    Ctl::primary(ids::RENAME_SAVE, text::SAVE.get(lang)),
                    Ctl::button(ids::RENAME_CANCEL, text::CANCEL.get(lang)),
                ]));
            } else {
                let mut row_ctls = vec![Ctl::button(ids::RENAME, text::RENAME.get(lang)).compact()];
                match pref {
                    // A recovery phrase's first account (…/0) cannot be hidden: no button
                    // (2026-11-12; an off button and a line saying why before).
                    EvmAccountPref::Index(index) | EvmAccountPref::Mnemonic(_, index) => {
                        if index != 0 {
                            row_ctls.push(Ctl::button(ids::HIDE, text::HIDE.get(lang)).compact());
                        }
                    }
                    EvmAccountPref::Record(_) => {
                        row_ctls.push(
                            Ctl::danger(ids::REMOVE_KEY, text::DELETE.get(lang))
                                .compact()
                                .enabled(self.can_remove_imported()),
                        );
                    }
                    // A YubiKey account (spec/10 §13): no "개인키 보기" (the key is on the card
                    // only); hidden until a card with its key is enrolled again.
                    EvmAccountPref::Hardware(_) => {
                        row_ctls.push(Ctl::button(ids::HIDE, text::HIDE.get(lang)).compact());
                    }
                }
                items.push(Item::Row(row_ctls));
            }
        }
        self.hidden_items(crate::app_hidden::Family::Evm, items);
        items.push(Item::Rule);
        let mut actions = Vec::new();
        if !self.key_only() {
            actions.push(
                Ctl::button(ids::ADD_ACCOUNT, text::ADD_ACCOUNT.get(lang))
                    .compact()
                    .enabled(self.can_add_account()),
            );
        }
        actions.push(
            Ctl::button(ids::IMPORT_KEY, text::IMPORT_KEY.get(lang))
                .compact()
                .enabled(self.can_import(yw_core::keyimport::ImportChain::Evm)),
        );
        actions.push(
            Ctl::link(
                crate::ui::screens_mnemonics::ids::MAIN_LINK,
                text::ADD_MANAGE_MNEMONICS.get(lang),
            )
            .compact(),
        );
        items.push(Item::Row(actions));
        self.mn_pick_row(items);
        items.push(Item::CardEnd);
        self.evm_main_sections(items);
    }

    /// The top link of settings and S13: `← 처음 설정으로` while they were opened from S08's
    /// '처음 설정' card ([`App::done_return`], spec/04 §2.3), else `← 메인으로`.
    #[must_use]
    pub fn back_row(&self) -> Item {
        let lang = self.settings.language;
        if self.done_return {
            Item::Row(vec![Ctl::link(ids::BACK_DONE, text::BACK_DONE.get(lang))])
        } else {
            back_main(lang)
        }
    }

    fn settings_screen(&self, section: SettingsSection, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(self.back_row());
        items.push(Item::Title(text::SETTINGS.get(lang).to_owned()));
        items.push(Item::Row(vec![
            Ctl::tab(
                ids::SECTION_SECURITY,
                text::TAB_SECURITY.get(lang),
                section == SettingsSection::Security,
            )
            .width(68),
            // Keys and backups first and fixed widths (2026-11-08): the nine tabs keep one row
            // at the default 960 DIP window.
            Ctl::tab(
                crate::ui::screens_mnemonics::ids::SECTION_MNEMONICS,
                text::TAB_MNEMONICS.get(lang),
                section == SettingsSection::Mnemonics,
            )
            .width(88),
            Ctl::tab(
                crate::ui::screens_yubikey::ids::SECTION_YUBIKEY,
                "YubiKey",
                section == SettingsSection::YubiKey,
            )
            .width(84),
            Ctl::tab(
                ids::SECTION_NETWORK,
                text::TAB_NETWORK.get(lang),
                section == SettingsSection::Network,
            )
            .width(120),
            Ctl::tab(
                crate::ui::screens_evm::ids::SECTION_CHAINS,
                text::TAB_CHAINS.get(lang),
                section == SettingsSection::Chains,
            )
            .width(92),
            Ctl::tab(
                crate::ui::screens_sol::ids::SECTION_SOL,
                "Solana",
                section == SettingsSection::Solana,
            )
            .width(76),
            Ctl::tab(
                crate::ui::screens_btc::ids::SECTION_BTC,
                "Bitcoin",
                section == SettingsSection::Bitcoin,
            )
            .width(76),
            Ctl::tab(
                crate::ui::screens_llm::ids::SECTION_AI,
                text::TAB_AI.get(lang),
                section == SettingsSection::Ai,
            )
            .width(80),
            Ctl::tab(
                ids::SECTION_OTHER,
                text::TAB_OTHER.get(lang),
                section == SettingsSection::Other,
            )
            .width(108),
        ]));
        if let Some(elsewhere) = settings_elsewhere(lang, section) {
            items.push(Item::Help(elsewhere.to_owned()));
        }
        match section {
            SettingsSection::Security => self.security_section(items),
            SettingsSection::Network => self.network_section(items),
            SettingsSection::Chains => self.chains_section(items),
            SettingsSection::Solana => self.sol_settings_section(items),
            SettingsSection::Bitcoin => self.btc_settings_section(items),
            SettingsSection::Ai => self.llm_settings_section(items),
            SettingsSection::Other => self.other_section(items),
            SettingsSection::YubiKey => self.yk_settings_section(items),
            SettingsSection::Mnemonics => self.mn_settings_section(items),
        }
    }

    /// The `고급 설정 보기 ▸` / `고급 설정 숨기기 ▾` link.
    pub(crate) fn advanced_toggle(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Row(vec![Ctl::link(
            ids::ADVANCED_TOGGLE,
            if self.show_advanced {
                text::ADVANCED_HIDE.get(lang)
            } else {
                text::ADVANCED_SHOW.get(lang)
            },
        )]));
    }

    fn security_section(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        self.language_card(items);
        items.push(Item::CardStart(Some(
            text::AUTO_LOCK_TITLE.get(lang).to_owned(),
        )));
        items.push(Item::Help(text::AUTO_LOCK_HELP.get(lang).to_owned()));
        items.push(Item::LabeledRow(
            text::AUTO_LOCK_LABEL.get(lang).to_owned(),
            vec![
                Ctl::edit(
                    ids::AUTOLOCK_EDIT,
                    &self.settings.auto_lock_minutes.to_string(),
                    80,
                    false,
                    2,
                ),
                Ctl::button(ids::AUTOLOCK_SAVE, text::SAVE.get(lang)),
            ],
        ));
        items.push(Item::CardEnd);
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        let public = unlocked || self.mode == AppMode::BackupPending;
        items.push(Item::CardStart(Some(
            text::SECRETS_TITLE.get(lang).to_owned(),
        )));
        if self.key_only() {
            // No recovery words: what brings this wallet back is said anyway (2026-11-10).
            let lines = self.backup_status_all();
            if !lines.is_empty() {
                items.push(Item::Subtitle(
                    text::BACKUP_STATUS_TITLE.get(lang).to_owned(),
                ));
                for line in lines {
                    items.push(Item::Text(line));
                }
            }
            items.push(Item::Help(text::SECRETS_KEY_ONLY.get(lang).to_owned()));
            items.push(Item::Row(vec![
                Ctl::button(ids::REVEAL_KEY, text::REVEAL_KEY.get(lang)).enabled(
                    unlocked && self.selected_account().is_some() && !self.hardware_selected(),
                ),
            ]));
        } else {
            self.backup_card_rows(unlocked, public, items);
        }
        items.push(Item::Help(text::SECRETS_KEY_NOTE.get(lang).to_owned()));
        items.push(Item::Row(vec![Ctl::check(
            ids::COPY_TOGGLE,
            text::ALLOW_COPY.get(lang),
            self.settings.allow_secret_copy,
        )]));
        items.push(Item::Help(text::ALLOW_COPY_HELP.get(lang).to_owned()));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            text::PASSWORD_TITLE.get(lang).to_owned(),
        )));
        items.push(Item::Help(text::PASSWORD_HELP.get(lang).to_owned()));
        items.push(Item::Help(
            crate::app::T_PASSWORD_OLD_COPIES.get(lang).to_owned(),
        ));
        items.push(Item::Row(vec![
            Ctl::button(ids::CHANGE_PASSWORD, text::CHANGE_PASSWORD.get(lang)).enabled(public),
        ]));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            text::FILE_PROTECTION_TITLE.get(lang).to_owned(),
        )));
        if let Some((generation, written)) = self.guard.vault_file {
            items.push(Item::Text(vault_file_text(lang, generation, written)));
        }
        items.push(Item::Help(if self.guard.wer_unprotected {
            T_WER_UNPROTECTED.get(lang).to_owned()
        } else {
            text::WER_PROTECTED.get(lang).to_owned()
        }));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            text::RESET_TITLE.get(lang).to_owned(),
        )));
        items.push(Item::Help(text::RESET_CARD_HELP.get(lang).to_owned()));
        items.push(Item::Row(vec![Ctl::danger(
            crate::ui::screens_reset::ids::RESET_OPEN,
            text::RESET_WALLET.get(lang),
        )]));
        items.push(Item::CardEnd);
    }

    /// `언어 · Language` (spec/04 §2.11, spec/14 §1): the first card of the first settings tab,
    /// its title and options in both languages so a user who cannot read the current one still
    /// finds it. The change applies at once (an approval window already open keeps its language).
    fn language_card(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::CardStart(Some(LANGUAGE_TITLE.to_owned())));
        items.push(Item::Help(text::LANGUAGE_HELP.get(lang).to_owned()));
        items.push(Item::Row(vec![
            Ctl::radio(ids::LANG_KO, LANGUAGE_KOREAN, lang == Lang::Ko, true),
            Ctl::radio(ids::LANG_EN, "English", lang == Lang::En, false),
        ]));
        items.push(Item::CardEnd);
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the RPC provider form and the URL rows"
    )]
    fn network_section(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        // A pending rpc.json import review stays first (it waits for a decision), and so does the
        // advice to delete the plaintext file right after an import.
        if self.rpc_import.on_top() {
            self.rpc_import_section(items);
        }
        items.push(Item::CardStart(Some(
            text::RPC_PROVIDER_TITLE.get(lang).to_owned(),
        )));
        if !self.rpc_import.on_top()
            && crate::app_rpc_import::rpc_json_path().is_some_and(|path| path.is_file())
        {
            items.push(Item::Text(text::RPC_JSON_FOUND.get(lang).to_owned()));
        }
        items.push(Item::Help(text::RPC_PROVIDER_HELP.get(lang).to_owned()));
        let template = self.settings.rpc_template;
        items.push(Item::Row(vec![
            Ctl::radio(
                ids::TPL_QUICKNODE,
                text::TPL_QUICKNODE.get(lang),
                template == RpcTemplate::QuickNode,
                true,
            ),
            Ctl::radio(
                ids::TPL_ALCHEMY,
                text::ALCHEMY.get(lang),
                template == RpcTemplate::Alchemy,
                false,
            ),
            Ctl::radio(
                ids::TPL_MANUAL,
                text::TPL_MANUAL.get(lang),
                template == RpcTemplate::Manual,
                false,
            ),
        ]));
        let stored = self.template_stored();
        let status = if stored {
            text::CONFIGURED.get(lang)
        } else {
            text::NONE.get(lang)
        };
        match template {
            RpcTemplate::QuickNode => {
                items.push(Item::Help(text::QN_STORED.fill(lang, [status])));
                items.push(Item::LabeledRow(
                    text::QN_NAME.get(lang).to_owned(),
                    vec![Ctl::edit(ids::QN_NAME_EDIT, "", 320, true, 256)],
                ));
                items.push(Item::Help(text::QN_NAME_HELP.get(lang).to_owned()));
                items.push(Item::LabeledRow(
                    text::QN_TOKEN.get(lang).to_owned(),
                    vec![Ctl::edit(ids::QN_TOKEN_EDIT, "", 320, true, 256)],
                ));
                items.push(Item::Help(text::QN_TOKEN_HELP.get(lang).to_owned()));
                items.push(Item::Help(text::T_QUICKNODE_CHAINS.get(lang).to_owned()));
            }
            RpcTemplate::Alchemy => {
                items.push(Item::Help(text::ALCHEMY_STORED.fill(lang, [status])));
                items.push(Item::LabeledRow(
                    text::API_KEY.get(lang).to_owned(),
                    vec![Ctl::edit(ids::ALCHEMY_KEY_EDIT, "", 320, true, 256)],
                ));
                items.push(Item::Help(text::ALCHEMY_KEY_HELP.get(lang).to_owned()));
            }
            RpcTemplate::Manual => {
                items.push(Item::Help(text::MANUAL_HELP.get(lang).to_owned()));
            }
        }
        let manual = template == RpcTemplate::Manual;
        items.push(Item::Row(vec![
            Ctl::primary(ids::GENERATE, text::GENERATE.get(lang)).enabled(!manual),
            Ctl::button(ids::TPL_SAVE, text::TPL_SAVE.get(lang)).enabled(!manual),
            Ctl::danger(ids::TPL_DELETE, text::TPL_DELETE.get(lang)).enabled(!manual && stored),
        ]));
        if self.rpc_removed == Some(crate::app::RpcRemoved::Template) {
            items.push(Item::Banner(
                text::TPL_DELETED.get(lang).to_owned(),
                Tone::Success,
            ));
        }
        items.push(Item::Help(text::GENERATE_HELP.get(lang).to_owned()));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            text::RPC_LIST_TITLE.get(lang).to_owned(),
        )));
        self.rpc_summary_items(items);
        items.push(Item::Help(text::RPC_LIST_HELP.get(lang).to_owned()));
        let mut networks = self.url_networks();
        networks.truncate(usize::from(ids::ROW_SPAN / 3));
        // The note above an open field: the stored credentials can make the empty addresses.
        let template_name = match template {
            RpcTemplate::QuickNode => Some("QuickNode"),
            RpcTemplate::Alchemy => Some(text::ALCHEMY.get(lang)),
            RpcTemplate::Manual => None,
        };
        // One line per network (2026-11-12): its name, the three actions and its state as a tag
        // on the same line; a full-width band only for a failure (it has the reason) and for
        // `삭제`. 13 networks fit on one screen instead of three.
        for (row, network) in networks.into_iter().enumerate() {
            let url = self.apikeys.rpc_url(network);
            let base =
                ids::ROW_BASE.saturating_add(u16::try_from(row).unwrap_or(0).saturating_mul(3));
            items.push(Item::LabeledRow(
                self.network_name(network),
                vec![
                    Ctl::button(
                        base,
                        if url.is_some() {
                            text::REPLACE.get(lang)
                        } else {
                            text::ENTER.get(lang)
                        },
                    )
                    .compact(),
                    Ctl::button(base.saturating_add(1), text::TEST.get(lang))
                        .compact()
                        .enabled(url.is_some()),
                    Ctl::danger(base.saturating_add(2), text::DELETE.get(lang))
                        .compact()
                        .enabled(url.is_some()),
                ],
            ));
            let message = self.rpc_messages.iter().find(|(id, _, _)| *id == network);
            let pill = match (url.is_some(), message.map(|(_, _, state)| *state)) {
                (false, _) => Some((text::NONE, Tone::Warn)),
                (true, Some(TestState::Works)) => Some((text::WORKS, Tone::Success)),
                (true, Some(TestState::Failed)) => Some((text::FAILED, Tone::Danger)),
                (true, Some(TestState::Testing)) => Some((text::TESTING, Tone::Info)),
                (true, None) => None,
            };
            if let Some((label, tone)) = pill {
                items.push(Item::Pill(label.get(lang).to_owned(), tone));
            }
            if self.replace_target == Some(network) {
                items.push(Item::Help(url.as_ref().map_or_else(
                    || text::ROW_NO_ADDRESS.fill(lang, [&network.to_string()]),
                    |url| text::ROW_ADDRESS.fill(lang, [&network.to_string(), &mask_url(url)]),
                )));
                if let Some(name) = template_name.filter(|_| {
                    stored && template_entry(template, network, &self.settings).is_some()
                }) {
                    items.push(Item::Help(text::ROW_TEMPLATE_STORED.fill(lang, [name])));
                }
                items.push(Item::Row(vec![
                    Ctl::edit(ids::REPLACE_EDIT, "", 420, true, 2_048),
                    Ctl::primary(ids::REPLACE_SAVE, text::SAVE.get(lang)),
                    Ctl::button(ids::REPLACE_CANCEL, text::CANCEL.get(lang)),
                ]));
                items.push(Item::Help(text::ROW_PASTE_HELP.get(lang).to_owned()));
            }
            if let Some((_, message, TestState::Failed)) = message {
                items.push(Item::Banner(message.clone(), Tone::Danger));
            }
            if self.rpc_removed == Some(crate::app::RpcRemoved::Url(network)) {
                items.push(Item::Banner(
                    text::RPC_URL_DELETED.get(lang).to_owned(),
                    Tone::Success,
                ));
            }
        }
        items.push(Item::CardEnd);
        // Block explorers (2026-11-11): per network, like the RPC list above.
        self.explorer_settings_card(items);
        let dormant = self.apikeys.dormant_names();
        if !dormant.is_empty() {
            items.push(Item::CardStart(Some(
                text::DORMANT_TITLE.get(lang).to_owned(),
            )));
            items.push(Item::Help(
                text::DORMANT_HELP.fill(lang, [&dormant.len().to_string()]),
            ));
            items.push(Item::Row(vec![Ctl::danger(
                ids::PRUNE_DORMANT,
                text::DORMANT_DELETE.get(lang),
            )]));
            items.push(Item::CardEnd);
        }
        // The developer import's button last: most owners set RPC with the provider card above.
        if !self.rpc_import.on_top() {
            self.rpc_import_section(items);
        }
    }

    /// The RPC list's numbers over the networks that have an address: `(with an address,
    /// networks, works, failed, not tested in this run)`.
    #[must_use]
    pub fn rpc_summary(&self) -> (usize, usize, usize, usize, usize) {
        let networks = self.url_networks();
        let (mut configured, mut works, mut failed) = (0_usize, 0_usize, 0_usize);
        for network in &networks {
            if !self.apikeys.has(KeyName::Rpc(*network)) {
                continue;
            }
            configured = configured.saturating_add(1);
            match self
                .rpc_messages
                .iter()
                .find(|(id, _, _)| id == network)
                .map(|(_, _, state)| *state)
            {
                Some(TestState::Works) => works = works.saturating_add(1),
                Some(TestState::Failed) => failed = failed.saturating_add(1),
                Some(TestState::Testing) | None => {}
            }
        }
        let untested = configured.saturating_sub(works).saturating_sub(failed);
        (configured, networks.len(), works, failed, untested)
    }

    /// The head of "네트워크별 RPC 주소" (2026-11-10): how many addresses there are, this run's
    /// tests, the failed networks as links to their rows, and `모두 테스트`.
    fn rpc_summary_items(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let (configured, total, works, failed, untested) = self.rpc_summary();
        items.push(Item::Text(text::RPC_LIST_SUMMARY.fill(
            lang,
            [
                &configured.to_string(),
                &total.to_string(),
                &works.to_string(),
                &failed.to_string(),
                &untested.to_string(),
            ],
        )));
        let links: Vec<Ctl> = self
            .url_networks()
            .into_iter()
            .enumerate()
            .filter(|(_, network)| {
                self.apikeys.has(KeyName::Rpc(*network))
                    && self
                        .rpc_messages
                        .iter()
                        .any(|(id, _, state)| id == network && *state == TestState::Failed)
            })
            .filter_map(|(row, network)| {
                let row = u16::try_from(row)
                    .ok()
                    .filter(|row| *row < ids::RPC_ROW_OPEN_SPAN)?;
                Some(Ctl::link(
                    ids::RPC_ROW_OPEN_BASE.saturating_add(row),
                    &self.network_name(network),
                ))
            })
            .collect();
        if !links.is_empty() {
            items.push(Item::LabeledRow(
                text::FAILED_NETWORKS.get(lang).to_owned(),
                links,
            ));
        }
        let tests = &self.rpc_tests;
        let label = if tests.busy() {
            text::TESTING_PROGRESS.fill(
                lang,
                [
                    &tests
                        .done
                        .saturating_add(1)
                        .min(tests.total.max(1))
                        .to_string(),
                    &tests.total.max(1).to_string(),
                ],
            )
        } else {
            text::TEST_ALL.get(lang).to_owned()
        };
        items.push(Item::Row(vec![
            Ctl::button(ids::TEST_ALL, &label).enabled(configured > 0 && !tests.busy()),
        ]));
    }

    fn other_section(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::CardStart(Some(
            text::EXTENSION_TITLE.get(lang).to_owned(),
        )));
        items.push(Item::Text(self.extension_status().text_in(lang).to_owned()));
        items.push(Item::Help(
            crate::ui::screens_reset::T_EXT_COMPAT_SHORT
                .get(lang)
                .to_owned(),
        ));
        items.push(Item::Row(vec![Ctl::button(
            crate::ui::screens_reset::ids::EXT_OPEN,
            text::EXTENSION_OPEN.get(lang),
        )]));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("WalletConnect".to_owned())));
        items.push(Item::Help(text::WC_HELP.get(lang).to_owned()));
        items.push(Item::Field(
            text::STATUS.get(lang).to_owned(),
            if self.settings.walletconnect_project.is_empty() {
                text::WC_OFF.get(lang).to_owned()
            } else {
                text::WC_ON.fill(lang, [&self.wc.sessions.len().to_string()])
            },
        ));
        items.push(Item::Row(vec![Ctl::button(
            crate::ui::screens_sites::ids::SITES_OPEN,
            text::WC_OPEN_SITES.get(lang),
        )]));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            text::BROWSER_LINK_TITLE.get(lang).to_owned(),
        )));
        items.push(Item::Help(text::BROWSER_LINK_HELP.get(lang).to_owned()));
        items.push(Item::Row(vec![Ctl::check(
            ids::AUTOLAUNCH_TOGGLE,
            text::AUTOLAUNCH.get(lang),
            self.settings.browser_auto_launch,
        )]));
        items.push(Item::Help(text::AUTOLAUNCH_HELP.get(lang).to_owned()));
        items.push(Item::Row(vec![Ctl::check(
            ids::LOCALHOST_TOGGLE,
            text::LOCALHOST.get(lang),
            self.settings.allow_localhost_dapps,
        )]));
        items.push(Item::Help(text::LOCALHOST_HELP.get(lang).to_owned()));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            text::DIAGNOSTICS_TITLE.get(lang).to_owned(),
        )));
        items.push(Item::Help(text::DIAGNOSTICS_HELP.get(lang).to_owned()));
        items.push(Item::Row(vec![Ctl::button(
            ids::OPEN_LOG_FOLDER,
            text::OPEN_LOG_FOLDER.get(lang),
        )]));
        if self.show_advanced {
            let level = self.settings.log_level;
            items.push(Item::LabeledRow(
                text::LOG_LEVEL.get(lang).to_owned(),
                vec![
                    Ctl::radio(ids::LOG_ERROR, "error", level == LogLevel::Error, true),
                    Ctl::radio(ids::LOG_WARN, "warn", level == LogLevel::Warn, false),
                    Ctl::radio(ids::LOG_INFO, "info", level == LogLevel::Info, false),
                    Ctl::radio(ids::LOG_DEBUG, "debug", level == LogLevel::Debug, false),
                ],
            ));
            items.push(Item::Help(text::LOG_LEVEL_HELP.get(lang).to_owned()));
        }
        self.advanced_toggle(items);
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            text::ABOUT_TITLE.get(lang).to_owned(),
        )));
        // The installed commit says which build runs (2026-11-10, `build_info`).
        items.push(Item::Field(
            text::VERSION.get(lang).to_owned(),
            crate::build_info::version_text(lang, self.install_commit.as_deref()),
        ));
        items.push(Item::Field(
            text::DATA_FOLDER.get(lang).to_owned(),
            self.paths.data.display().to_string(),
        ));
        items.push(Item::Row(vec![Ctl::button(
            ids::OPEN_DATA_FOLDER,
            text::OPEN_FOLDER.get(lang),
        )]));
        items.push(Item::Field(
            text::SHORTCUTS.get(lang).to_owned(),
            text::SHORTCUTS_TEXT.get(lang).to_owned(),
        ));
        items.push(Item::CardEnd);
    }

    #[expect(clippy::too_many_lines, reason = "one arm per overlay")]
    fn confirm(&self, kind: Confirm, items: &mut Vec<Item>) {
        // The E-VLT-006 choices have their own texts and buttons (`app_sidecar`).
        if kind == Confirm::SidecarCorrupt {
            self.meta_overlay(items);
            return;
        }
        if kind == Confirm::JournalCorrupt {
            self.journal_overlay(items);
            return;
        }
        let lang = self.settings.language;
        let btc = self.btc.confirm;
        let (title, text, yes) = match kind {
            Confirm::Btc => btc.map_or(("Bitcoin", String::new(), text::OK.get(lang)), |confirm| {
                confirm.texts(lang)
            }),
            Confirm::CopyOn => (
                text::C_COPY_TITLE.get(lang),
                text::C_COPY_TEXT.get(lang).to_owned(),
                text::C_ALLOW.get(lang),
            ),
            Confirm::LocalhostOn => (
                text::C_LOCALHOST_TITLE.get(lang),
                text::C_LOCALHOST_TEXT.get(lang).to_owned(),
                text::C_TURN_ON.get(lang),
            ),
            Confirm::RevealMnemonic | Confirm::RevealKey => (
                if kind == Confirm::RevealMnemonic {
                    text::REVEAL_MNEMONIC.get(lang)
                } else {
                    text::REVEAL_KEY.get(lang)
                },
                text::C_REVEAL_TEXT.get(lang).to_owned(),
                text::C_CONTINUE.get(lang),
            ),
            Confirm::Generate => (
                text::C_GENERATE_TITLE.get(lang),
                self.generate_text(),
                text::C_CREATE.get(lang),
            ),
            Confirm::RpcUrlDelete(network) => (
                text::C_RPC_DELETE_TITLE.get(lang),
                self.rpc_delete_text(network),
                text::C_REMOVE.get(lang),
            ),
            Confirm::TemplateDelete => (
                text::C_TPL_DELETE_TITLE.get(lang),
                self.template_delete_text(),
                text::C_REMOVE.get(lang),
            ),
            Confirm::LlmKeyDelete => (
                text::C_LLM_KEY_TITLE.get(lang),
                text::C_LLM_KEY_TEXT.get(lang).to_owned(),
                text::C_REMOVE.get(lang),
            ),
            Confirm::YkAbandon => (
                text::C_YK_ABANDON_TITLE.get(lang),
                crate::app_yubikey::text::YK_ABANDON.get(lang).to_owned(),
                text::C_YK_ABANDON_YES.get(lang),
            ),
            Confirm::YkPinLater => (
                text::C_PIN_LATER_TITLE.get(lang),
                text::C_PIN_LATER_TEXT.get(lang).to_owned(),
                text::C_PIN_LATER_YES.get(lang),
            ),
            // Drawn above.
            Confirm::SidecarCorrupt | Confirm::JournalCorrupt => ("", String::new(), ""),
            Confirm::RemoveKey => (
                text::C_REMOVE_KEY_TITLE.get(lang),
                T_REMOVE_KEY.get(lang).to_owned(),
                text::C_CONTINUE.get(lang),
            ),
            Confirm::RemoveImported => (
                text::C_REMOVE_KEY_TITLE.get(lang),
                crate::ui::screens_keys::text::REMOVE_IMPORTED
                    .get(lang)
                    .to_owned(),
                text::C_CONTINUE.get(lang),
            ),
            Confirm::RemoveYubiKey => (
                text::C_REMOVE_YK_TITLE.get(lang),
                self.yk_remove_text(),
                text::C_CONTINUE.get(lang),
            ),
            Confirm::RevealImported => (
                text::REVEAL_KEY.get(lang),
                text::C_REVEAL_TEXT.get(lang).to_owned(),
                text::C_CONTINUE.get(lang),
            ),
            Confirm::ChainPin => (
                text::C_CHAIN_PIN_TITLE.get(lang),
                self.chain_pin_text(),
                text::C_CHAIN_PIN_YES.get(lang),
            ),
            Confirm::ChainRepin => (
                text::C_REPIN.get(lang),
                self.chain_repin_text(),
                text::C_REPIN.get(lang),
            ),
            Confirm::ChainDelete => (
                text::C_CHAIN_DELETE_TITLE.get(lang),
                text::C_CHAIN_DELETE_TEXT.get(lang).to_owned(),
                text::DELETE.get(lang),
            ),
            Confirm::BookDelete => (
                text::C_BOOK_DELETE_TITLE.get(lang),
                self.book_delete_text(),
                text::DELETE.get(lang),
            ),
            Confirm::TokenDelete => (
                text::C_TOKEN_DELETE_TITLE.get(lang),
                T_TOKEN_DELETE.get(lang).to_owned(),
                text::DELETE.get(lang),
            ),
            Confirm::DisconnectAll => (
                text::C_DISCONNECT_TITLE.get(lang),
                if self.wc.sessions.is_empty() {
                    text::C_DISCONNECT_TEXT.get(lang).to_owned()
                } else {
                    text::C_DISCONNECT_WC_TEXT.fill(lang, [&self.wc.sessions.len().to_string()])
                },
                text::C_DISCONNECT_YES.get(lang),
            ),
            Confirm::SettingsFile => (
                text::C_SETTINGS_FILE_TITLE.get(lang),
                text::C_SETTINGS_FILE_TEXT.get(lang).to_owned(),
                text::C_SETTINGS_FILE_YES.get(lang),
            ),
            Confirm::WcDisconnectAll => (
                text::C_WC_DISCONNECT_TITLE.get(lang),
                text::C_WC_DISCONNECT_TEXT.fill(lang, [&self.wc.sessions.len().to_string()]),
                text::C_WC_DISCONNECT_YES.get(lang),
            ),
            Confirm::Discard => (
                text::C_DISCARD_TITLE.get(lang),
                T_DISCARD.get(lang).to_owned(),
                text::C_DISCARD_YES.get(lang),
            ),
            Confirm::LlmOn => (
                text::C_LLM_ON_TITLE.get(lang),
                self.llm_notice_text().unwrap_or_default(),
                text::C_TURN_ON.get(lang),
            ),
            Confirm::PruneDormant => (
                text::DORMANT_DELETE.get(lang),
                text::C_PRUNE_TEXT.fill(
                    lang,
                    [
                        &self.apikeys.dormant_names().len().to_string(),
                        &self.apikeys.dormant_names().join(", "),
                    ],
                ),
                text::DELETE.get(lang),
            ),
        };
        let destructive = matches!(
            kind,
            Confirm::PruneDormant
                | Confirm::RpcUrlDelete(_)
                | Confirm::TemplateDelete
                | Confirm::LlmKeyDelete
                | Confirm::ChainDelete
                | Confirm::BookDelete
                | Confirm::TokenDelete
                | Confirm::DisconnectAll
                | Confirm::WcDisconnectAll
                | Confirm::Discard
                | Confirm::RemoveKey
                | Confirm::RemoveImported
                | Confirm::RemoveYubiKey
        );
        items.push(Item::Title(title.to_owned()));
        items.push(Item::CardStart(None));
        match kind {
            // The "지워지는 계정" block (2026-11-10), then the imported-key band with the balance
            // sentence inside it (the key is lost for good with its removal).
            Confirm::RemoveKey | Confirm::RemoveImported => {
                let account = if kind == Confirm::RemoveKey {
                    self.remove_key_account()
                } else {
                    self.imported_removed()
                };
                let inside = account.map_or_else(Vec::new, |account| {
                    items.push(Item::Subtitle(text::C_REMOVED_ACCOUNT.get(lang).to_owned()));
                    crate::ui::removed::removed_items(lang, &[account], items)
                });
                let mut band = inside.join(" ");
                if !band.is_empty() {
                    band.push(' ');
                }
                band.push_str(&text);
                items.push(Item::Banner(band, Tone::HighRisk));
            }
            Confirm::RemoveYubiKey => {
                items.push(Item::Text(text));
                self.yk_remove_items(items);
            }
            _ => items.push(Item::Text(text)),
        }
        if kind == Confirm::SettingsFile {
            for line in self.settings_file_lines() {
                items.push(Item::Text(line));
            }
        }
        if kind == Confirm::TokenDelete
            && let Some((label, address)) = self.token_delete_target()
        {
            items.push(Item::Field(text::C_TOKEN.get(lang).to_owned(), label));
            items.push(Item::Help(text::C_CONTRACT_ADDRESS.get(lang).to_owned()));
            items.push(Item::Mono(yw_core::evm::display::format_address(&address)));
        }
        if kind == Confirm::RevealImported
            && let Some((label, address)) = self.imported_target_text()
        {
            items.push(Item::Field(text::C_ACCOUNT.get(lang).to_owned(), label));
            items.push(Item::Mono(address));
        }
        if kind == Confirm::Generate {
            items.push(Item::Row(vec![Ctl::check(
                ids::OVERWRITE_CHECK,
                text::C_OVERWRITE.get(lang),
                self.overwrite_checked,
            )]));
        }
        if matches!(kind, Confirm::ChainRepin | Confirm::LlmOn) {
            let (check_id, check_text, checked) = if kind == Confirm::LlmOn {
                (
                    crate::ui::screens_llm::ids::NOTICE_CHECK,
                    text::C_UNDERSTOOD.get(lang),
                    self.llm_ui.notice_checked,
                )
            } else {
                (
                    crate::ui::screens_evm::ids::REPIN_CHECK,
                    text::C_REPIN_CHECK.get(lang),
                    self.evm.repin.as_ref().is_some_and(|repin| repin.checked),
                )
            };
            items.push(Item::Row(vec![Ctl::check(check_id, check_text, checked)]));
            items.push(Item::Row(vec![
                Ctl::primary(ids::CONFIRM_YES, yes).enabled(checked),
                Ctl::button(ids::CONFIRM_NO, text::CANCEL.get(lang)),
            ]));
            items.push(Item::CardEnd);
            return;
        }
        if kind == Confirm::YkAbandon {
            // Going on is the main choice; giving up discards the words (spec/10 §7.1-1).
            items.push(Item::Row(vec![
                Ctl::primary(ids::CONFIRM_NO, text::C_KEEP_CREATING.get(lang)),
                Ctl::danger(ids::CONFIRM_YES, yes),
            ]));
            items.push(Item::CardEnd);
            return;
        }
        if kind == Confirm::YkPinLater {
            // Setting the PIN now is the main choice (back to the result and its PIN card).
            items.push(Item::Row(vec![
                Ctl::primary(ids::CONFIRM_NO, text::C_PIN_NOW.get(lang)),
                Ctl::button(ids::CONFIRM_YES, yes),
            ]));
            items.push(Item::CardEnd);
            return;
        }
        let no = match (kind, btc) {
            (Confirm::Btc, Some(confirm)) => confirm.no_label(lang),
            _ => text::CANCEL.get(lang),
        };
        items.push(Item::Row(vec![
            if destructive {
                Ctl::danger(ids::CONFIRM_YES, yes)
            } else {
                Ctl::primary(ids::CONFIRM_YES, yes)
            },
            Ctl::button(ids::CONFIRM_NO, no),
        ]));
        items.push(Item::CardEnd);
    }

    /// The EVM imported key about to be removed (`Confirm::RemoveKey`) as the "지워지는 계정"
    /// block shows it (2026-11-10, was `remove_key_balance`): the selected EVM network's native
    /// balance as last read; other networks and tokens are not checked.
    fn remove_key_account(&self) -> Option<crate::ui::removed::RemovedAccount> {
        let (label, address) = self.pending_remove.and_then(|id| {
            self.meta.as_ref()?.evm_raw_accounts.iter().find_map(|raw| {
                (raw.record_id == *id.as_bytes())
                    .then(|| yw_core::evm::address::parse_address(&raw.address).ok())
                    .flatten()
                    .map(|address| (raw.label.clone(), address))
            })
        })?;
        Some(self.evm_removed(label, &address, true))
    }

    /// `RpcUrlDelete`'s text (2026-11-10): the address cannot be shown again, how it comes back,
    /// and what stops meanwhile.
    fn rpc_delete_text(&self, network: NetworkId) -> String {
        let lang = self.settings.language;
        let again = match self.settings.rpc_template {
            RpcTemplate::Manual => text::C_RPC_AGAIN_MANUAL.get(lang).to_owned(),
            template => text::C_RPC_AGAIN_TEMPLATE.fill(
                lang,
                [
                    if template == RpcTemplate::QuickNode {
                        "QuickNode"
                    } else {
                        text::ALCHEMY.get(lang)
                    },
                    if self.template_stored() {
                        text::CONFIGURED.get(lang)
                    } else {
                        text::NONE.get(lang)
                    },
                ],
            ),
        };
        // A stored template credential fills an empty network at the next start (2026-11-11).
        let refill = if self.template_stored()
            && template_entry(self.settings.rpc_template, network, &self.settings).is_some()
        {
            text::C_RPC_REFILL.get(lang)
        } else {
            ""
        };
        text::C_RPC_DELETE_TEXT.fill(
            lang,
            [
                &self.network_name(network),
                &network.to_string(),
                &again,
                refill,
            ],
        )
    }

    /// `TemplateDelete`'s text (2026-11-10).
    fn template_delete_text(&self) -> String {
        let lang = self.settings.language;
        if self.settings.rpc_template == RpcTemplate::Alchemy {
            text::C_TPL_DELETE_ALCHEMY.get(lang).to_owned()
        } else {
            text::C_TPL_DELETE_QUICKNODE.get(lang).to_owned()
        }
    }

    fn generate_text(&self) -> String {
        let lang = self.settings.language;
        let (targets, skipped) = self.generation_plan();
        let mut out = text::C_GENERATE_TEXT.get(lang).to_owned();
        for network in targets {
            let existing = if self.apikeys.has(KeyName::Rpc(network)) {
                text::C_GENERATE_EXISTING.get(lang)
            } else {
                ""
            };
            let _ = write!(
                out,
                "\n· {} ({network}){existing}",
                self.network_name(network)
            );
        }
        if !skipped.is_empty() {
            out.push_str(text::C_GENERATE_SKIPPED.get(lang));
            for network in skipped {
                let _ = write!(out, "\n· {} ({network})", self.network_name(network));
            }
        }
        out
    }
}
