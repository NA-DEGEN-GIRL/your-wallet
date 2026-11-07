//! Screen contents S01–S15 (spec/04 §2) as [`Item`] lists, and the command ids of their
//! controls. Fixed sentences follow spec/04 §2.16; nothing from RPC or the OS is shown.
//!
//! Layout rules (spec/04 §2.0, design system §1.6): one primary button per screen (two on the
//! chain tabs: 보내기 / 받기), sections in cards with a heading, a plain-language help line under
//! technical fields, technical settings behind `고급 설정 보기`, flows with a step indicator.

use core::fmt::Write as _;

use yw_core::evm::chain::SEPOLIA;
use yw_core::evm::display::format_address;

use crate::apikeys::{KeyName, mask_url};
use crate::app::{App, AppMode, Confirm, Screen, SettingsSection};
use crate::errors::ErrorCode;
use crate::meta::EvmAccountPref;
use crate::network::NetworkId;
use crate::settings::{LogLevel, RpcTemplate};
use crate::ui::main_window::{Ctl, Item, Tone};

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
    /// S08 RPC 설정하기.
    pub const DONE_RPC: u16 = 160;
    /// S08 지갑 열기 / 나중에.
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
    /// Template save.
    pub const TPL_SAVE: u16 = 526;
    /// Template delete.
    pub const TPL_DELETE: u16 = 527;
    /// 네트워크 URL 생성.
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
    /// T-RPC-GENERATE `기존 URL 덮어쓰기`.
    pub const OVERWRITE_CHECK: u16 = 802;

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
    ];
}

/// Steps of the create flow (S02 → W01 → W08 → W10, spec/04 §2.3).
pub const CREATE_STEPS: [&str; 3] = ["비밀번호 정하기", "복구 단어 적기", "백업 확인"];
/// Steps of the import flow (S05 → W01 → W05 → S06, spec/04 §2.4).
pub const IMPORT_STEPS: [&str; 3] = ["비밀번호 정하기", "복구 단어 입력", "첫 주소 확인"];

/// The step indicator item of a flow.
#[must_use]
pub fn steps(labels: [&str; 3], current: usize) -> Item {
    Item::Steps(
        labels.iter().map(|label| (*label).to_owned()).collect(),
        current,
    )
}

/// The `← 메인으로` link.
#[must_use]
pub fn back_main() -> Item {
    Item::Row(vec![Ctl::link(ids::BACK_MAIN, "← 메인으로")])
}

/// T-FIRST-1 (S01, three plain sentences).
pub const T_FIRST: [&str; 3] = [
    "Your Wallet은 이 PC에서만 쓰는 개인용 암호화폐 지갑입니다.",
    "돈을 보내거나 사이트에 서명할 때는 언제나 이 앱의 확인 창에서 내용을 보고 직접 승인합니다.",
    "지갑을 만들 때 받는 복구 단어 24개가 유일한 백업입니다. 종이에 적어 안전한 곳에 보관하세요.",
];

/// T-ALT-PASS (every screen while `App::passphrase_unverified`, spec/04 §2.1): not dismissible.
pub const T_ALT_PASS: &str = "passphrase 확인값과 맞지 않는 passphrase로 연 지갑입니다. 오타라면 이 지갑은 원래 지갑이 아닌 다른(빈) 지갑이고, 여기로 받은 자산은 지금 입력한 passphrase와 대소문자·공백까지 정확히 같은 값을 다시 넣어야만 꺼낼 수 있습니다. 그래서 받기와 사이트 연결·서명을 막았습니다. 계정 이름·주소록·연결 기록도 저장되지 않습니다. 잘못 입력했다면 잠그고 다시 여세요.";
/// Shown when `받기` is pressed in that mode.
pub const T_ALT_PASS_RECEIVE: &str = "확인되지 않은 passphrase로 연 지갑에서는 받기를 쓸 수 없습니다. 잠그고 passphrase를 다시 입력하세요.";
/// T-MAINNET: the main-screen badge of a network with real assets (EVM mainnets, Solana mainnet;
/// Bitcoin shows `BITCOIN MAINNET`, spec/08 §2).
pub const T_MAINNET: &str = "메인넷 — 실제 자산";
/// S10 `내 계정` help: only derived accounts come back from the recovery words.
pub const T_ACCOUNTS_BACKUP: &str = "보내기·받기에 쓸 계정을 고르세요. 경로(m/44'/60'/…)가 있는 계정은 복구 단어로 복구되지만, '가져온 개인키' 계정은 복구 단어로 복구되지 않으니 그 개인키를 따로 백업하세요.";
/// S10 `내 계정` help of a key-only wallet (no recovery words).
pub const T_ACCOUNTS_KEY_ONLY: &str = "보내기·받기에 쓸 계정을 고르세요. 이 지갑은 개인키로 시작해 복구 단어가 없습니다. 모든 계정은 '가져온 키'이며 각각의 원래 개인키가 유일한 백업입니다.";
/// The imported-key removal confirmation (export first: imported keys are not in the 24 words).
pub const T_REMOVE_KEY: &str = "선택한 가져온 개인키 계정을 이 지갑에서 지웁니다. 가져온 개인키는 복구 단어로 복구되지 않으므로, 지우고 나면 원래 개인키 없이는 이 계정의 자산에 다시 접근할 수 없습니다. 지우기 전에 설정 → 보안 → '개인키 보기'로 개인키를 내보내 안전하게 보관했는지 확인하세요. 계속하려면 비밀번호를 입력하세요.";
/// The EVM `폐기` confirmation: discarding only stops tracking; a resend may pay twice.
pub const T_DISCARD: &str = "폐기는 이 앱에서 추적만 멈추고 '폐기됨'으로 표시합니다. 네트워크에서 거래를 취소하지는 않습니다. 이미 전파된 거래라면 나중에 처리될 수 있고, 그 사이 같은 송금을 다시 보내면 두 거래가 모두 처리되어 두 번 지불될 수 있습니다. 확실히 막으려면 폐기 대신 '취소'(같은 nonce의 취소 거래)를 쓰고, 다시 보내기 전에 탐색기에서 이 거래가 사라졌는지 확인하세요.";
/// T-TOKEN-DELETE: `삭제` of a user-added EVM token (spec/04 §2.6); the label and the full
/// contract address follow it.
pub const T_TOKEN_DELETE: &str = "이 토큰을 이 네트워크의 토큰 목록에서 지웁니다. 토큰이나 잔액은 그대로이며 블록체인에는 아무것도 보내지 않습니다. 같은 컨트랙트 주소로 언제든 다시 추가할 수 있습니다. 지운 뒤 이 토큰의 활동 기록은 원시 단위로 보입니다.";
/// Every chain's `받기` (S12) command.
pub const RECEIVE_IDS: [u16; 3] = [
    crate::ui::screens_evm::ids::RECEIVE_OPEN,
    crate::ui::screens_sol::ids::RECEIVE_OPEN,
    crate::ui::screens_btc::ids::RECEIVE_OPEN,
];

/// Turns off every `받기` control in `items` (unverified-passphrase sessions).
fn disable_receive(items: &mut [Item]) {
    for item in items {
        if let Item::Row(ctls) | Item::LabeledRow(_, ctls) | Item::Toolbar(_, ctls) = item {
            for ctl in ctls.iter_mut().filter(|ctl| RECEIVE_IDS.contains(&ctl.id)) {
                ctl.enabled = false;
            }
        }
    }
}

/// The `vault.ywv` facts line (review L17): generation and last write time, so a file swapped
/// for an older copy is noticeable.
#[must_use]
pub fn vault_file_text(generation: u64, written_unix_ms: u64) -> String {
    let wall = yw_win::time::local_wall_ms(written_unix_ms);
    let text = crate::logging::format_utc(wall.unwrap_or(written_unix_ms));
    let short = text.get(..16).unwrap_or(&text).replace('T', " ");
    let when = if wall.is_some() {
        short
    } else {
        format!("{short} UTC")
    };
    format!(
        "지갑 파일(vault.ywv): 저장 횟수(세대) {generation} · 마지막 저장 {when}. 기억하는 것보다 작거나 이전 시각이면 파일이 예전 사본으로 바뀌었을 수 있습니다."
    )
}

/// The banner when the meta remembers a newer `vault.ywv` generation (review L17).
#[must_use]
pub fn rollback_text(seen: u64, found: u64) -> String {
    format!(
        "지갑 파일(vault.ywv)이 예전 사본으로 바뀌었을 수 있습니다: 이 지갑은 세대 {seen}까지 저장했는데 지금 파일은 세대 {found}입니다. 직접 백업에서 되돌린 것이 아니라면 지운 계정·키가 다시 나타나거나 최근 변경이 사라졌을 수 있으니 확인하세요."
    )
}

/// The banner when the crash-report exclusion failed at startup (review L9).
pub const T_WER_UNPROTECTED: &str = "Windows 오류 보고(WER) 제외 등록에 실패했습니다. 이 앱이 비정상 종료되면 메모리 덤프가 남을 수 있고, 덤프에는 잠금 해제 중인 지갑 키가 들어 있을 수 있습니다.";

fn header(app: &App, items: &mut Vec<Item>) {
    if app.passphrase_unverified() {
        items.push(Item::Banner(T_ALT_PASS.to_owned(), Tone::HighRisk));
    }
    if let Some(pending) = &app.guard.pending {
        let keys: Vec<&str> = pending.1.iter().map(|differing| differing.key()).collect();
        items.push(Item::Banner(
            format!(
                "{} ({}). 지금은 앱에 저장된 값을 씁니다. 직접 바꾼 것이면 '파일 값 사용'을 누르세요.",
                crate::settings::SETTINGS_TAMPERED_TEXT,
                keys.join(", ")
            ),
            Tone::Warn,
        ));
        items.push(Item::Row(vec![
            Ctl::button(ids::SETTINGS_ACCEPT_FILE, "파일 값 사용"),
            Ctl::button(ids::SETTINGS_RESTORE, "앱에 저장된 값으로 되돌리기"),
        ]));
    }
    for banner in &app.banners {
        items.push(Item::Banner(banner.text.clone(), Tone::Danger));
    }
    app.yk_pin_needed_items(items);
    if let Some(info) = &app.info {
        items.push(Item::Banner(info.clone(), Tone::Info));
    }
    if !app.banners.is_empty() || app.info.is_some() {
        items.push(Item::Row(vec![Ctl::link(
            ids::DISMISS_BANNERS,
            "알림 닫기",
        )]));
    }
}

/// The items of the current screen.
impl App {
    /// Builds the current screen.
    #[must_use]
    pub fn items(&self) -> Vec<Item> {
        let mut items = Vec::new();
        if self.screen == Screen::Main {
            items.push(Item::Toolbar(
                "Your Wallet".to_owned(),
                vec![
                    Ctl::button(crate::ui::screens_evm::ids::BOOK_OPEN, "주소록"),
                    Ctl::button(crate::ui::screens_sites::ids::SITES_OPEN, "연결된 사이트"),
                    Ctl::button(ids::OPEN_SETTINGS, "설정"),
                    Ctl::button(ids::LOCK, "잠금 (Ctrl+L)"),
                ],
            ));
        }
        header(self, &mut items);
        match &self.screen {
            Screen::Starting => items.push(Item::Muted("지갑을 불러오는 중…".to_owned())),
            Screen::FirstRun => self.first_run(&mut items),
            Screen::CreateIntro => Self::create_intro(&mut items),
            Screen::Processing(text) => {
                items.push(Item::Gap(40));
                items.push(Item::CardStart(None));
                items.push(Item::Subtitle("잠시만 기다려 주세요".to_owned()));
                items.push(Item::Text((*text).to_owned()));
                items.push(Item::CardEnd);
                if self.wait.stalled {
                    self.wait_stalled(&mut items);
                }
            }
            Screen::BackupPending => Self::backup_pending(&mut items),
            Screen::Reset => self.reset_screen(&mut items),
            Screen::Extension => self.extension_screen(&mut items),
            Screen::HyperCore => self.hc_screen(&mut items),
            Screen::ImportIntro => Self::import_intro(&mut items),
            Screen::ImportAddress(address) => Self::import_address(address, &mut items),
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
            Screen::KeyStartAddress(view) => Self::key_start_address(view, &mut items),
            Screen::YubiKey => self.yk_wizard_screen(&mut items),
            Screen::YubiKeyWalletIntro => Self::yk_wallet_intro(&mut items),
        }
        if self.passphrase_unverified() {
            disable_receive(&mut items);
        }
        items
    }

    fn first_run(&self, items: &mut Vec<Item>) {
        items.push(Item::Gap(24));
        items.push(Item::Display("Your Wallet".to_owned()));
        items.push(Item::Gap(4));
        for sentence in T_FIRST {
            items.push(Item::Text(sentence.to_owned()));
        }
        items.push(Item::Gap(8));
        if self.leftover {
            items.push(Item::Banner(
                "이전 지갑의 파일이 데이터 폴더에 남아 있습니다. 앱을 종료하고 파일을 다른 곳으로 옮긴 뒤 다시 실행하세요.".to_owned(),
                Tone::Warn,
            ));
            items.push(Item::Mono(self.paths.data.display().to_string()));
            items.push(Item::Row(vec![
                Ctl::button(ids::OPEN_DATA_FOLDER, "폴더 열기"),
                Ctl::link(
                    crate::ui::screens_reset::ids::RESET_OPEN,
                    "남은 파일을 reset- 폴더로 옮기기…",
                ),
            ]));
        }
        items.push(Item::CardStart(Some("처음 사용합니다".to_owned())));
        items.push(Item::Text(
            "새 지갑을 만들고 복구 단어 24개를 종이에 적습니다. 5분쯤 걸립니다.".to_owned(),
        ));
        items.push(Item::Row(vec![
            Ctl::primary(ids::FIRST_CREATE, "새 지갑 만들기").enabled(!self.leftover),
        ]));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            "다른 지갑에서 쓰던 복구 단어가 있습니다".to_owned(),
        )));
        items.push(Item::Text(
            "영어 복구 단어(니모닉) 12·15·18·21·24개로 기존 지갑을 그대로 가져옵니다.".to_owned(),
        ));
        items.push(Item::Row(vec![
            Ctl::button(ids::FIRST_IMPORT, "기존 지갑 가져오기").enabled(!self.leftover),
        ]));
        items.push(Item::CardEnd);
        self.first_run_key_card(items);
        self.first_run_yubikey_card(items);
    }

    fn create_intro(items: &mut Vec<Item>) {
        items.push(Item::Title("새 지갑 만들기".to_owned()));
        items.push(steps(CREATE_STEPS, 0));
        items.push(Item::CardStart(Some("시작하기 전에".to_owned())));
        for line in [
            "· 종이와 펜을 준비하세요. 다음 화면들에서 복구 단어 24개와 첫 주소를 적습니다.",
            "· 복구 단어는 종이(또는 금속)에만 적고 사진·클라우드·메신저에 남기지 마세요.",
            "· 화면 공유·녹화를 끄고 주변에 사람이나 카메라가 없는지 확인하세요.",
        ] {
            items.push(Item::Text(line.to_owned()));
        }
        items.push(Item::Help(
            "복구 단어를 아는 사람은 누구든 지갑의 자산을 옮길 수 있습니다. 이 앱도 복구 단어를 대신 보관하거나 되찾아 주지 못합니다."
                .to_owned(),
        ));
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::primary(ids::CREATE_NEXT, "시작하기"),
            Ctl::button(ids::INTRO_CANCEL, "취소"),
        ]));
    }

    fn backup_pending(items: &mut Vec<Item>) {
        items.push(Item::Title("백업 확인이 필요합니다".to_owned()));
        items.push(Item::Banner(
            "백업 확인이 끝나지 않았습니다. 확인 전에는 보내기·서명·dApp 승인을 쓸 수 없습니다."
                .to_owned(),
            Tone::Warn,
        ));
        items.push(Item::CardStart(None));
        items.push(Item::Text(
            "복구 단어를 다시 보고, 그중 단어 4개를 입력해 종이에 바르게 적었는지 확인합니다."
                .to_owned(),
        ));
        items.push(Item::Row(vec![
            Ctl::primary(ids::BACKUP_CHECK, "복구 단어 보고 백업 확인"),
            Ctl::button(crate::ui::screens_evm::ids::RECEIVE_OPEN, "받기"),
            Ctl::button(ids::LOCK, "잠금"),
        ]));
        items.push(Item::CardEnd);
        Self::reset_link(
            items,
            "복구 단어를 적지 못했거나 잃어버렸다면, 이 지갑에 자산을 받기 전에 초기화하고 새로 만드세요.",
        );
    }

    fn import_intro(items: &mut Vec<Item>) {
        items.push(Item::Title("기존 지갑 가져오기".to_owned()));
        items.push(steps(IMPORT_STEPS, 0));
        items.push(Item::CardStart(Some("준비할 것".to_owned())));
        items.push(Item::Text(
            "· 다른 지갑에서 쓰던 영어 복구 단어(BIP39 니모닉) 12·15·18·21·24개".to_owned(),
        ));
        items.push(Item::Text(
            "· 그 지갑에서 BIP39 passphrase(25번째 단어)를 썼다면 그 passphrase".to_owned(),
        ));
        items.push(Item::Help(
            "복구 단어 없이 개인키(EVM·Solana·Bitcoin)만 있다면 첫 화면의 '개인키로 시작하기'를 쓰세요. 이미 지갑이 있다면 메인 화면의 '개인키 가져오기'로 더할 수 있습니다."
                .to_owned(),
        ));
        items.push(Item::Help(crate::app_btc::BTC_IMPORT_NOTE.to_owned()));
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::primary(ids::IMPORT_NEXT, "시작하기"),
            Ctl::button(ids::INTRO_CANCEL, "취소"),
        ]));
    }

    fn import_address(address: &str, items: &mut Vec<Item>) {
        items.push(Item::Title("첫 주소 확인".to_owned()));
        items.push(steps(IMPORT_STEPS, 3));
        items.push(Item::CardStart(None));
        items.push(Item::Text(
            "가져온 지갑의 첫 주소입니다. 이전 지갑에서 쓰던 주소와 전체가 같은지 확인하세요."
                .to_owned(),
        ));
        let shown = yw_core::evm::address::parse_address(address)
            .map_or_else(|_| address.to_owned(), |parsed| format_address(&parsed));
        items.push(Item::Mono(shown));
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::primary(ids::IMPORT_CORRECT, "맞습니다"),
            Ctl::button(ids::IMPORT_WRONG, "다릅니다"),
        ]));
        items.push(Item::Help(
            "다르면 복구 단어의 순서·철자나 passphrase를 확인하세요. '다릅니다'를 누르면 복구 단어를 다시 입력합니다."
                .to_owned(),
        ));
    }

    fn locked(&self, items: &mut Vec<Item>) {
        items.push(Item::Gap(48));
        items.push(Item::Display("지갑이 잠겨 있습니다".to_owned()));
        items.push(Item::Text(
            "계정과 잔액을 보려면 비밀번호로 잠금을 해제하세요.".to_owned(),
        ));
        if let Some(pending) = self.unlock_pending_text() {
            items.push(Item::Banner(pending, Tone::Info));
        }
        items.push(Item::Row(vec![Ctl::primary(ids::UNLOCK, "잠금 해제")]));
        items.push(Item::Help(format!(
            "{}분 동안 쓰지 않거나, Windows를 잠그거나 절전에 들어가면 지갑이 자동으로 잠깁니다.",
            self.settings.auto_lock_minutes
        )));
        if let Some((generation, written)) = self.guard.vault_file {
            items.push(Item::Muted(vault_file_text(generation, written)));
        }
        if self.unlock_failed && self.prev_on_disk && self.mode == AppMode::Locked {
            // spec/02 §6.3: a damaged key section is indistinguishable from a wrong password.
            items.push(Item::Gap(8));
            items.push(Item::Help(
                "비밀번호가 맞는데도 계속 열리지 않으면 지갑 파일이 손상되었을 수 있습니다. 같은 비밀번호로 이전 사본(.prev) 복구를 시도할 수 있습니다. 지갑 파일이 정상이면 복구하지 않고 그대로 엽니다."
                    .to_owned(),
            ));
            items.push(Item::Row(vec![Ctl::link(
                ids::RECOVER,
                "이전 사본(.prev)으로 복구",
            )]));
        }
        Self::reset_link(
            items,
            "비밀번호를 잊었거나 더 진행할 수 없다면: 지갑 파일을 옮겨 두고(지우지 않음) 복구 단어로 새로 시작할 수 있습니다.",
        );
    }

    fn pass_mismatch(&self, items: &mut Vec<Item>) {
        items.push(Item::Title("passphrase 확인".to_owned()));
        items.push(Item::Banner(
            "passphrase가 다를 수 있습니다. 다른 passphrase는 다른(빈) 지갑을 엽니다.".to_owned(),
            Tone::Warn,
        ));
        items.push(Item::CardStart(None));
        items.push(Item::Row(vec![Ctl::check(
            ids::MISMATCH_CHECK,
            "다른 passphrase는 다른(빈) 지갑을 엽니다",
            self.mismatch_checked,
        )]));
        items.push(Item::Row(vec![
            Ctl::primary(ids::MISMATCH_RETRY, "다시 입력"),
            Ctl::button(ids::MISMATCH_CONTINUE, "이 passphrase로 계속")
                .enabled(self.mismatch_checked),
        ]));
        items.push(Item::CardEnd);
    }

    fn done(&self, items: &mut Vec<Item>) {
        items.push(Item::Title("준비되었습니다".to_owned()));
        if self.keys.done_start {
            items.push(Item::Banner(
                crate::ui::screens_keys::T_KEY_START_OK.to_owned(),
                Tone::Success,
            ));
            items.push(Item::Banner(
                crate::ui::screens_keys::T_KEY_START_BACKUP.to_owned(),
                Tone::Warn,
            ));
        } else if self.done_imported {
            // No backup check runs on import: the words came from the user's existing backup.
            items.push(Item::Banner(
                "지갑을 가져왔습니다. 이제 지갑을 쓸 수 있습니다.".to_owned(),
                Tone::Success,
            ));
            items.push(Item::Help(
                "이 지갑의 백업은 방금 입력한 복구 단어(와 passphrase)입니다. 그 종이 백업을 계속 안전하게 보관하세요."
                    .to_owned(),
            ));
        } else {
            items.push(Item::Banner(
                "백업을 확인했습니다. 이제 지갑을 쓸 수 있습니다.".to_owned(),
                Tone::Success,
            ));
        }
        if self.apikeys.endpoints().is_empty() {
            items.push(Item::CardStart(Some(
                "마지막 단계: 블록체인 연결(RPC)".to_owned(),
            )));
            items.push(Item::Text(
                "잔액을 보고 돈을 보내려면 블록체인 노드에 연결할 주소(RPC 엔드포인트)가 필요합니다."
                    .to_owned(),
            ));
            items.push(Item::Help(
                "QuickNode나 알케미 계정이 있으면 설정에서 이름과 토큰만 넣어 모든 네트워크의 주소를 한 번에 만들 수 있습니다. 나중에 설정 → 네트워크(RPC)에서 해도 됩니다."
                    .to_owned(),
            ));
            items.push(Item::Row(vec![
                Ctl::primary(ids::DONE_RPC, "RPC 설정하기"),
                Ctl::button(ids::DONE_CONTINUE, "나중에"),
            ]));
            items.push(Item::CardEnd);
        } else {
            items.push(Item::Row(vec![Ctl::primary(
                ids::DONE_CONTINUE,
                "지갑 열기",
            )]));
        }
        self.extension_link(items);
    }

    fn recovery(&self, items: &mut Vec<Item>) {
        items.push(Item::Title("지갑 파일 복구".to_owned()));
        items.push(Item::CardStart(None));
        let prev = match self.mode {
            AppMode::Corrupt { prev_available } => {
                let code = if self.payload_damaged {
                    ErrorCode::Vlt008
                } else {
                    ErrorCode::Vlt002
                };
                items.push(Item::Banner(code.text(), Tone::Danger));
                prev_available
            }
            AppMode::MainMissing => {
                items.push(Item::Text(
                    "지갑 파일이 없고 이전 사본(.prev)이 있습니다.".to_owned(),
                ));
                true
            }
            _ => false,
        };
        if prev {
            items.push(Item::Help(
                "이전 사본으로 복구하면 마지막 변경(예: 가져온 개인키)이 사라질 수 있습니다. 지금 파일은 지우지 않고 데이터 폴더에 vault.ywv.corrupt-<시각> 이름으로 옮겨 두며, 복구 뒤 그 이름을 알려 드립니다(직접 되돌리는 방법: 복구 안내)."
                    .to_owned(),
            ));
        }
        items.push(Item::Field(
            "데이터 폴더".to_owned(),
            self.paths.data.display().to_string(),
        ));
        let mut row = Vec::new();
        if prev {
            row.push(Ctl::primary(ids::RECOVER, "이전 사본으로 복구"));
        }
        row.push(Ctl::button(ids::OPEN_DATA_FOLDER, "폴더 열기"));
        row.push(Ctl::button(ids::EXIT, "종료"));
        items.push(Item::Row(row));
        items.push(Item::CardEnd);
        items.push(Item::Help(
            "앱은 지갑 파일을 지우거나 덮어쓰지 않습니다. 복구 단어가 있으면 언제든 새로 가져올 수 있습니다."
                .to_owned(),
        ));
        Self::reset_link(
            items,
            "복구할 수 없다면: 지갑 파일을 데이터 폴더 안의 reset- 폴더로 옮겨 두고 처음부터 시작합니다.",
        );
    }

    /// The selected EVM account's hero card: name, big balance, address, 보내기 / 받기.
    fn evm_hero(&self, items: &mut Vec<Item>) {
        let chain_id = self.settings.evm_chain_id;
        let Some((address, source, label)) = self.selected_account() else {
            return;
        };
        items.push(Item::CardStart(None));
        items.push(Item::Subtitle(label));
        items.push(Item::Help(match source {
            yw_core::vault::EvmKeySource::Derived(index) => {
                format!("m/44'/60'/0'/0/{}", index.get())
            }
            yw_core::vault::EvmKeySource::Raw(_) => "가져온 개인키".to_owned(),
            yw_core::vault::EvmKeySource::Hardware(index) => {
                format!("YubiKey · m/44'/60'/0'/0/{}", index.get())
            }
        }));
        let balance = self.native_balance(chain_id, &address);
        let state = self.evm.balances.get(&chain_id);
        if let Some(value) = balance {
            items.push(Item::Display(self.native_text(chain_id, &value)));
            if let Some(block) = state
                .and_then(|state| state.snapshot.as_ref())
                .map(|snapshot| snapshot.block)
            {
                let mut caption = format!("블록 {block} 기준");
                if let Some(code) = state.and_then(|state| state.error) {
                    let _ = write!(caption, " · 갱신 실패 {}", code.code());
                }
                items.push(Item::Help(caption));
            }
        } else {
            items.push(Item::Display("잔액 —".to_owned()));
            items.push(Item::Help(
                "잔액을 아직 읽지 못했습니다. RPC 연결을 확인하고 새로고침하세요.".to_owned(),
            ));
        }
        items.push(Item::Mono(format_address(&address)));
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        let endpoint = self.apikeys.has(KeyName::Rpc(NetworkId::Eip155(chain_id)));
        let mut row = vec![
            Ctl::primary(crate::ui::screens_evm::ids::SEND_OPEN, "보내기").enabled(unlocked),
            Ctl::primary(crate::ui::screens_evm::ids::RECEIVE_OPEN, "받기"),
            Ctl::link(crate::ui::screens_evm::ids::REFRESH, "새로고침"),
        ];
        if !endpoint {
            row.push(Ctl::link(ids::SECTION_NETWORK, "RPC 설정하기"));
        }
        items.push(Item::Row(row));
        items.push(Item::CardEnd);
    }

    #[expect(clippy::too_many_lines, reason = "the S10 sections in order")]
    fn main_screen(&self, items: &mut Vec<Item>) {
        // T-ALT-PASS is drawn by `header` on every screen.
        self.tab_row(items);
        if self.sol_tab_active() {
            if self.sol_cluster() == yw_core::sol::SolCluster::Mainnet {
                items.push(Item::Banner(T_MAINNET.to_owned(), Tone::BtcMainnet));
            }
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
        let chains = self.settings.registered_evm();
        let chips: Vec<Ctl> = chains
            .iter()
            .take(usize::from(ids::NETWORK_SPAN))
            .enumerate()
            .map(|(index, chain_id)| {
                Ctl::tab(
                    ids::NETWORK_BASE.saturating_add(u16::try_from(index).unwrap_or(0)),
                    &self.network_label(*chain_id),
                    *chain_id == self.settings.evm_chain_id,
                )
                .badge(self.evm_badge(*chain_id))
            })
            .collect();
        items.push(Item::CardStart(None));
        items.push(Item::LabeledRow("네트워크".to_owned(), chips));
        if self.settings.evm_chain_id == SEPOLIA {
            items.push(Item::Banner(
                "테스트넷 — 실제 자산이 아닙니다".to_owned(),
                Tone::Testnet,
            ));
        } else if yw_core::evm::chain::is_builtin_mainnet(self.settings.evm_chain_id) {
            // The built-in mainnets (user chains carry no testnet flag, so no badge).
            items.push(Item::Banner(T_MAINNET.to_owned(), Tone::BtcMainnet));
        }
        self.evm_banners(items);
        items.push(Item::Help(self.evm_status_line()));
        items.push(Item::CardEnd);
        if self.account_rows().is_empty() && self.meta.is_some() {
            self.no_accounts_card(yw_core::keyimport::ImportChain::Evm, items);
            return;
        }
        self.evm_hero(items);
        items.push(Item::CardStart(Some("내 계정".to_owned())));
        items.push(Item::Help(if self.key_only() {
            T_ACCOUNTS_KEY_ONLY.to_owned()
        } else {
            T_ACCOUNTS_BACKUP.to_owned()
        }));
        let selected = self.selected_pref();
        for (row, (pref, label, address, path)) in self
            .account_rows()
            .into_iter()
            .take(usize::from(ids::ACCOUNT_SPAN))
            .enumerate()
        {
            let is_selected = selected == Some(pref);
            let shown_label = match pref {
                EvmAccountPref::Record(_) => format!("{label}  [가져온 키]"),
                EvmAccountPref::Hardware(_) => format!("{label}  [YubiKey]"),
                EvmAccountPref::Index(_) => label.clone(),
            };
            items.push(Item::Row(vec![
                Ctl::radio(
                    ids::ACCOUNT_BASE.saturating_add(u16::try_from(row).unwrap_or(0)),
                    &shown_label,
                    is_selected,
                    row == 0,
                )
                .width(420),
            ]));
            let balance = self.balance_text(&address);
            let shown = yw_core::evm::address::parse_address(&address)
                .map_or_else(|_| address.clone(), |parsed| format_address(&parsed));
            items.push(Item::Mono(shown));
            items.push(Item::Help(match balance {
                Some(balance) => format!("{path} · {balance}"),
                None => path,
            }));
            if is_selected {
                if self.rename == Some(pref) {
                    items.push(Item::Row(vec![
                        Ctl::edit(ids::RENAME_EDIT, &label, 260, false, 64),
                        Ctl::primary(ids::RENAME_SAVE, "저장"),
                        Ctl::button(ids::RENAME_CANCEL, "취소"),
                    ]));
                } else {
                    let mut row_ctls = vec![Ctl::button(ids::RENAME, "이름 바꾸기")];
                    match pref {
                        EvmAccountPref::Index(index) => {
                            row_ctls.push(Ctl::button(ids::HIDE, "숨기기").enabled(index != 0));
                        }
                        EvmAccountPref::Record(_) => {
                            row_ctls.push(
                                Ctl::danger(ids::REMOVE_KEY, "삭제")
                                    .enabled(self.can_remove_imported()),
                            );
                        }
                        // A YubiKey account (spec/10 §13): no "개인키 보기" (the key is on
                        // the card only); hidden until a card with its key is enrolled again.
                        EvmAccountPref::Hardware(_) => {
                            row_ctls.push(Ctl::button(ids::HIDE, "숨기기"));
                        }
                    }
                    items.push(Item::Row(row_ctls));
                }
            }
            items.push(Item::Gap(4));
        }
        items.push(Item::Rule);
        let mut actions = Vec::new();
        if !self.key_only() {
            actions.push(
                Ctl::button(ids::ADD_ACCOUNT, "계정 추가").enabled(
                    self.meta
                        .as_ref()
                        .and_then(crate::meta::Meta::next_index)
                        .is_some(),
                ),
            );
        }
        actions.push(
            Ctl::button(ids::IMPORT_KEY, "개인키 가져오기")
                .enabled(self.can_import(yw_core::keyimport::ImportChain::Evm)),
        );
        items.push(Item::Row(actions));
        items.push(Item::CardEnd);
        self.evm_main_sections(items);
    }

    fn settings_screen(&self, section: SettingsSection, items: &mut Vec<Item>) {
        items.push(back_main());
        items.push(Item::Title("설정".to_owned()));
        items.push(Item::Row(vec![
            Ctl::tab(
                ids::SECTION_SECURITY,
                "보안",
                section == SettingsSection::Security,
            ),
            Ctl::tab(
                ids::SECTION_NETWORK,
                "네트워크(RPC)",
                section == SettingsSection::Network,
            ),
            Ctl::tab(
                crate::ui::screens_evm::ids::SECTION_CHAINS,
                "EVM 체인",
                section == SettingsSection::Chains,
            ),
            Ctl::tab(
                crate::ui::screens_sol::ids::SECTION_SOL,
                "Solana",
                section == SettingsSection::Solana,
            ),
            Ctl::tab(
                crate::ui::screens_btc::ids::SECTION_BTC,
                "Bitcoin",
                section == SettingsSection::Bitcoin,
            ),
            Ctl::tab(
                crate::ui::screens_llm::ids::SECTION_AI,
                "AI 설명",
                section == SettingsSection::Ai,
            ),
            Ctl::tab(
                crate::ui::screens_yubikey::ids::SECTION_YUBIKEY,
                "YubiKey",
                section == SettingsSection::YubiKey,
            ),
            Ctl::tab(
                ids::SECTION_OTHER,
                "브라우저·진단·정보",
                section == SettingsSection::Other,
            ),
        ]));
        match section {
            SettingsSection::Security => self.security_section(items),
            SettingsSection::Network => self.network_section(items),
            SettingsSection::Chains => self.chains_section(items),
            SettingsSection::Solana => self.sol_settings_section(items),
            SettingsSection::Bitcoin => self.btc_settings_section(items),
            SettingsSection::Ai => self.llm_settings_section(items),
            SettingsSection::Other => self.other_section(items),
            SettingsSection::YubiKey => self.yk_settings_section(items),
        }
    }

    /// The `고급 설정 보기 ▸` / `고급 설정 숨기기 ▾` link.
    pub(crate) fn advanced_toggle(&self, items: &mut Vec<Item>) {
        items.push(Item::Row(vec![Ctl::link(
            ids::ADVANCED_TOGGLE,
            if self.show_advanced {
                "고급 설정 숨기기 ▾"
            } else {
                "고급 설정 보기 ▸"
            },
        )]));
    }

    fn security_section(&self, items: &mut Vec<Item>) {
        items.push(Item::CardStart(Some("자동 잠금".to_owned())));
        items.push(Item::Help(
            "정한 시간 동안 쓰지 않으면 지갑을 잠급니다. Windows를 잠그거나 절전에 들어갈 때도 잠깁니다."
                .to_owned(),
        ));
        items.push(Item::LabeledRow(
            "잠그기까지(분, 1–60)".to_owned(),
            vec![
                Ctl::edit(
                    ids::AUTOLOCK_EDIT,
                    &self.settings.auto_lock_minutes.to_string(),
                    80,
                    false,
                    2,
                ),
                Ctl::button(ids::AUTOLOCK_SAVE, "저장"),
            ],
        ));
        items.push(Item::CardEnd);
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        let public = unlocked || self.mode == AppMode::BackupPending;
        items.push(Item::CardStart(Some("복구 단어·개인키".to_owned())));
        if self.key_only() {
            items.push(Item::Help(
                "이 지갑은 개인키로 시작해 복구 단어가 없습니다. 각 계정의 백업은 그 원래 개인키이며, 보기 전에 비밀번호를 다시 묻고 화면 캡처에서 제외된 창에 보여줍니다."
                    .to_owned(),
            ));
            items.push(Item::Row(vec![
                Ctl::button(ids::REVEAL_KEY, "개인키 보기").enabled(
                    unlocked && self.selected_account().is_some() && !self.hardware_selected(),
                ),
            ]));
        } else {
            items.push(Item::Help(
                "복구 단어(니모닉)는 지갑 전체의 백업입니다. 보기 전에 비밀번호를 다시 묻고, 화면 캡처에서 제외된 창에 보여줍니다."
                    .to_owned(),
            ));
            items.push(Item::Row(vec![
                Ctl::button(ids::REVEAL_MNEMONIC, "복구 단어 보기").enabled(public),
                Ctl::button(ids::REVEAL_KEY, "개인키 보기")
                    .enabled(unlocked && !self.hardware_selected()),
            ]));
        }
        items.push(Item::Help(
            "개인키 보기는 메인 화면에서 선택한 EVM 계정의 키를 보여줍니다. Solana·Bitcoin의 가져온 개인키는 각 탭의 계정에서 '개인키 보기'를 누르세요."
                .to_owned(),
        ));
        items.push(Item::Row(vec![Ctl::check(
            ids::COPY_TOGGLE,
            "복구 단어·개인키 복사 허용",
            self.settings.allow_secret_copy,
        )]));
        items.push(Item::Help(
            "기본은 꺼짐입니다. 켜면 복사한 값은 클립보드 기록에 남지 않고 30초 뒤 지워집니다."
                .to_owned(),
        ));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("비밀번호".to_owned())));
        items.push(Item::Help(
            "이 PC에서 지갑을 열 때 쓰는 비밀번호입니다. 바꿔도 복구 단어와 주소는 그대로입니다."
                .to_owned(),
        ));
        items.push(Item::Help(crate::app::T_PASSWORD_OLD_COPIES.to_owned()));
        items.push(Item::Row(vec![
            Ctl::button(ids::CHANGE_PASSWORD, "비밀번호 변경").enabled(public),
        ]));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("지갑 파일과 보호 상태".to_owned())));
        if let Some((generation, written)) = self.guard.vault_file {
            items.push(Item::Text(vault_file_text(generation, written)));
        }
        items.push(Item::Help(if self.guard.wer_unprotected {
            T_WER_UNPROTECTED.to_owned()
        } else {
            "Windows 오류 보고(WER)에서 이 앱을 제외했습니다: 비정상 종료 때 메모리 덤프를 남기지 않습니다."
                .to_owned()
        }));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("지갑 초기화".to_owned())));
        items.push(Item::Help(
            "이 PC의 지갑 파일을 데이터 폴더 안의 reset- 폴더로 옮기고(지우지 않음) 처음 화면으로 돌아갑니다. 다시 쓰려면 복구 단어 또는 원래 개인키가 필요합니다."
                .to_owned(),
        ));
        items.push(Item::Row(vec![Ctl::danger(
            crate::ui::screens_reset::ids::RESET_OPEN,
            "지갑 초기화…",
        )]));
        items.push(Item::CardEnd);
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the RPC provider form and the URL rows"
    )]
    fn network_section(&self, items: &mut Vec<Item>) {
        self.rpc_import_section(items);
        items.push(Item::CardStart(Some("RPC 공급자".to_owned())));
        items.push(Item::Help(
            "RPC는 지갑이 블록체인에서 잔액을 읽고 거래를 보낼 때 쓰는 연결 주소입니다. QuickNode나 알케미 계정 정보를 한 번 넣으면 아래 모든 네트워크의 주소를 자동으로 만들 수 있습니다."
                .to_owned(),
        ));
        let template = self.settings.rpc_template;
        items.push(Item::Row(vec![
            Ctl::radio(
                ids::TPL_QUICKNODE,
                "QuickNode 멀티체인",
                template == RpcTemplate::QuickNode,
                true,
            ),
            Ctl::radio(
                ids::TPL_ALCHEMY,
                "알케미",
                template == RpcTemplate::Alchemy,
                false,
            ),
            Ctl::radio(
                ids::TPL_MANUAL,
                "직접 입력",
                template == RpcTemplate::Manual,
                false,
            ),
        ]));
        match template {
            RpcTemplate::QuickNode => {
                let status = if self.apikeys.has(KeyName::TplQuickNode) {
                    "설정됨"
                } else {
                    "없음"
                };
                items.push(Item::Help(format!(
                    "저장된 QuickNode 자격 정보: {status} (저장된 값은 다시 보이지 않습니다)"
                )));
                items.push(Item::LabeledRow(
                    "엔드포인트 이름".to_owned(),
                    vec![Ctl::edit(ids::QN_NAME_EDIT, "", 320, true, 256)],
                ));
                items.push(Item::Help(
                    "QuickNode 엔드포인트 주소 https://<이름>.quiknode.pro/… 의 <이름> 부분입니다. 대시보드의 주소 전체를 이 칸이나 토큰 칸에 붙여넣어도 됩니다(이름과 토큰을 알아서 나눕니다)."
                        .to_owned(),
                ));
                items.push(Item::LabeledRow(
                    "토큰".to_owned(),
                    vec![Ctl::edit(ids::QN_TOKEN_EDIT, "", 320, true, 256)],
                ));
                items.push(Item::Help(
                    "주소 끝의 긴 문자열입니다. 입력한 값은 가려지고, 저장하면 Windows가 이 사용자 계정에서만 풀 수 있게 암호화합니다."
                        .to_owned(),
                ));
            }
            RpcTemplate::Alchemy => {
                let status = if self.apikeys.has(KeyName::TplAlchemy) {
                    "설정됨"
                } else {
                    "없음"
                };
                items.push(Item::Help(format!(
                    "저장된 알케미 키: {status} (저장된 값은 다시 보이지 않습니다)"
                )));
                items.push(Item::LabeledRow(
                    "API 키".to_owned(),
                    vec![Ctl::edit(ids::ALCHEMY_KEY_EDIT, "", 320, true, 256)],
                ));
                items.push(Item::Help(
                    "알케미 대시보드의 API Key입니다. 입력한 값은 가려집니다.".to_owned(),
                ));
            }
            RpcTemplate::Manual => {
                items.push(Item::Help(
                    "직접 입력: 아래 '네트워크별 RPC 주소'에서 네트워크마다 '교체'로 https:// 주소를 넣으세요."
                        .to_owned(),
                ));
            }
        }
        let manual = template == RpcTemplate::Manual;
        items.push(Item::Row(vec![
            Ctl::primary(ids::TPL_SAVE, "저장").enabled(!manual),
            Ctl::button(ids::GENERATE, "네트워크 URL 생성").enabled(!manual),
            Ctl::danger(ids::TPL_DELETE, "자격 정보 삭제").enabled(!manual),
        ]));
        items.push(Item::Help(
            "'네트워크 URL 생성'은 저장한 자격 정보로 아래 목록의 주소를 한 번에 만듭니다. 이미 있는 주소는 덮어쓸지 따로 묻습니다."
                .to_owned(),
        ));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("네트워크별 RPC 주소".to_owned())));
        items.push(Item::Help(
            "주소에는 토큰이 들어 있어 가린 형태로만 보입니다. '테스트'는 그 주소가 올바른 네트워크를 가리키는지 한 번 확인합니다."
                .to_owned(),
        ));
        let mut networks = self.url_networks();
        networks.truncate(usize::from(ids::ROW_SPAN / 3));
        let last = networks.len().saturating_sub(1);
        for (row, network) in networks.into_iter().enumerate() {
            let url = self.apikeys.rpc_url(network);
            let state = url.as_ref().map_or_else(
                || "없음 — 이 네트워크는 아직 쓸 수 없습니다".to_owned(),
                |url| format!("설정됨  {}", mask_url(url)),
            );
            items.push(Item::Subtitle(format!(
                "{}  ({network})",
                self.network_name(network)
            )));
            items.push(Item::Help(state));
            let base =
                ids::ROW_BASE.saturating_add(u16::try_from(row).unwrap_or(0).saturating_mul(3));
            items.push(Item::Row(vec![
                Ctl::button(base, if url.is_some() { "교체" } else { "입력" }),
                Ctl::button(base.saturating_add(1), "테스트"),
                Ctl::danger(base.saturating_add(2), "삭제").enabled(url.is_some()),
            ]));
            if self.replace_target == Some(network) {
                items.push(Item::Row(vec![
                    Ctl::edit(ids::REPLACE_EDIT, "", 420, true, 2_048),
                    Ctl::primary(ids::REPLACE_SAVE, "저장"),
                    Ctl::button(ids::REPLACE_CANCEL, "취소"),
                ]));
                items.push(Item::Help(
                    "https:// 로 시작하는 전체 주소를 붙여넣으세요. 저장 전에 형식을 검사합니다."
                        .to_owned(),
                ));
            }
            if let Some((_, message, ok)) =
                self.rpc_messages.iter().find(|(id, _, _)| *id == network)
            {
                items.push(Item::Banner(
                    message.clone(),
                    if *ok { Tone::Success } else { Tone::Danger },
                ));
            }
            if row != last {
                items.push(Item::Rule);
            }
        }
        items.push(Item::CardEnd);
        let dormant = self.apikeys.dormant_names();
        if !dormant.is_empty() {
            items.push(Item::CardStart(Some("보관 중인 항목".to_owned())));
            items.push(Item::Help(format!(
                "이 버전에서 쓰지 않는 RPC 항목 {}개를 지우지 않고 보관하고 있습니다(등록되지 않은 체인의 주소나 다른 버전의 앱이 쓴 항목). 체인을 다시 추가하거나 다른 버전으로 돌아가면 다시 쓰입니다.",
                dormant.len()
            )));
            items.push(Item::Row(vec![Ctl::danger(
                ids::PRUNE_DORMANT,
                "보관 항목 삭제",
            )]));
            items.push(Item::CardEnd);
        }
    }

    fn other_section(&self, items: &mut Vec<Item>) {
        items.push(Item::CardStart(Some("브라우저 확장".to_owned())));
        items.push(Item::Text(self.extension_status().text().to_owned()));
        items.push(Item::Row(vec![Ctl::button(
            crate::ui::screens_reset::ids::EXT_OPEN,
            "Chrome 확장 설치 방법·폴더",
        )]));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("브라우저 연결".to_owned())));
        items.push(Item::Help(
            "크롬 확장과 이 앱을 잇는 설정입니다. 사이트의 연결·서명 요청은 언제나 이 앱의 승인 창에서 확인합니다."
                .to_owned(),
        ));
        items.push(Item::Row(vec![Ctl::check(
            ids::AUTOLAUNCH_TOGGLE,
            "dApp 요청 시 앱 자동 실행",
            self.settings.browser_auto_launch,
        )]));
        items.push(Item::Help(
            "끄면 앱이 꺼져 있을 때 사이트의 지갑 요청은 실패합니다.".to_owned(),
        ));
        items.push(Item::Row(vec![Ctl::check(
            ids::LOCALHOST_TOGGLE,
            "localhost dApp 허용 (개발용)",
            self.settings.allow_localhost_dapps,
        )]));
        items.push(Item::Help(
            "dApp을 직접 개발할 때만 켜세요. http://localhost·127.0.0.1 페이지가 연결을 요청할 수 있게 됩니다."
                .to_owned(),
        ));
        items.push(Item::Row(vec![Ctl::button(
            crate::ui::screens_sites::ids::SITES_OPEN,
            "연결된 사이트 보기",
        )]));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("진단".to_owned())));
        items.push(Item::Help("로그에는 비밀번호·니모닉·개인키·API 키·RPC 엔드포인트 URL이 없습니다. 주소와 거래 해시는 있을 수 있습니다.".to_owned()));
        items.push(Item::Row(vec![Ctl::button(
            ids::OPEN_LOG_FOLDER,
            "로그 폴더 열기",
        )]));
        if self.show_advanced {
            let level = self.settings.log_level;
            items.push(Item::LabeledRow(
                "로그 수준".to_owned(),
                vec![
                    Ctl::radio(ids::LOG_ERROR, "error", level == LogLevel::Error, true),
                    Ctl::radio(ids::LOG_WARN, "warn", level == LogLevel::Warn, false),
                    Ctl::radio(ids::LOG_INFO, "info", level == LogLevel::Info, false),
                    Ctl::radio(ids::LOG_DEBUG, "debug", level == LogLevel::Debug, false),
                ],
            ));
            items.push(Item::Help(
                "문제를 조사할 때만 debug로 바꾸세요. 기본값은 info입니다.".to_owned(),
            ));
        }
        self.advanced_toggle(items);
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("정보".to_owned())));
        items.push(Item::Field(
            "버전".to_owned(),
            env!("CARGO_PKG_VERSION").to_owned(),
        ));
        items.push(Item::Field(
            "데이터 폴더".to_owned(),
            self.paths.data.display().to_string(),
        ));
        items.push(Item::Row(vec![Ctl::button(
            ids::OPEN_DATA_FOLDER,
            "폴더 열기",
        )]));
        items.push(Item::Field(
            "단축키".to_owned(),
            "Ctrl+L 잠금 · Ctrl+1 / 2 / 3 체인 탭(EVM·Solana·Bitcoin) · Tab 다음 칸".to_owned(),
        ));
        items.push(Item::CardEnd);
    }

    #[expect(clippy::too_many_lines, reason = "one arm per overlay")]
    fn confirm(&self, kind: Confirm, items: &mut Vec<Item>) {
        let btc = self.btc.confirm;
        let (title, text, yes) = match kind {
            Confirm::Btc => btc.map_or(("Bitcoin", String::new(), "확인"), |confirm| {
                confirm.texts()
            }),
            Confirm::CopyOn => (
                "복사 허용",
                "복사를 허용하면 복구 단어(니모닉)·개인키를 클립보드에 넣을 수 있습니다. 클립보드 기록·클라우드 동기화에서는 제외하고 30초 뒤 지우지만, 그 사이에는 다른 프로그램이 읽을 수 있습니다.".to_owned(),
                "허용",
            ),
            Confirm::LocalhostOn => (
                "localhost dApp 허용",
                "개발용 설정입니다. 켜면 http://localhost 와 http://127.0.0.1 페이지가 지갑 연결을 요청할 수 있습니다.".to_owned(),
                "켜기",
            ),
            Confirm::RevealMnemonic | Confirm::RevealKey => (
                if kind == Confirm::RevealMnemonic { "복구 단어 보기" } else { "개인키 보기" },
                "화면 근처의 사람이나 카메라가 볼 수 있습니다. 계속하려면 비밀번호를 입력하세요.".to_owned(),
                "계속",
            ),
            Confirm::Generate => ("네트워크 URL 생성", self.generate_text(), "생성"),
            Confirm::SidecarCorrupt => (
                "부가 파일 손상",
                format!("{} meta 파일을 이전 사본(.prev)으로 되돌리거나, 손상된 파일을 격리하고 새로 시작할 수 있습니다(계정 이름 등 메타 정보가 초기화됩니다).", ErrorCode::Vlt006.text()),
                "",
            ),
            Confirm::RemoveKey => (
                "가져온 개인키 삭제",
                T_REMOVE_KEY.to_owned(),
                "계속",
            ),
            Confirm::RemoveImported => (
                "가져온 개인키 삭제",
                crate::ui::screens_keys::T_REMOVE_IMPORTED.to_owned(),
                "계속",
            ),
            Confirm::RemoveYubiKey => ("YubiKey 기록 삭제", self.yk_remove_text(), "계속"),
            Confirm::RevealImported => (
                "개인키 보기",
                "화면 근처의 사람이나 카메라가 볼 수 있습니다. 계속하려면 비밀번호를 입력하세요.".to_owned(),
                "계속",
            ),
            Confirm::JournalCorrupt => (
                "거래 저널 손상",
                format!("{} 거래 저널을 새로 시작하면 진행 중 거래 기록이 사라질 수 있습니다. 손상된 파일은 격리(보존)합니다. 이전 사본(.prev)을 쓰려면 앱을 종료하고 직접 확인하세요.", ErrorCode::Vlt006.text()),
                "격리하고 새로 시작",
            ),
            Confirm::ChainPin => ("체인 추가 — 제네시스 고정", self.chain_pin_text(), "고정하고 저장"),
            Confirm::ChainRepin => ("다시 고정", self.chain_repin_text(), "다시 고정"),
            Confirm::ChainDelete => (
                "체인 삭제",
                "체인 정의, RPC URL, 수수료 상한을 지웁니다. 이 체인의 토큰·활동 기록은 남고, 같은 chainId를 다시 추가하면 다시 보입니다.".to_owned(),
                "삭제",
            ),
            Confirm::BookDelete => (
                "주소록 항목 삭제",
                self.book_delete_text(),
                "삭제",
            ),
            Confirm::TokenDelete => (
                "토큰 삭제",
                T_TOKEN_DELETE.to_owned(),
                "삭제",
            ),
            Confirm::DisconnectAll => (
                "모든 사이트 연결 해제",
                "연결된 모든 사이트의 연결을 해제합니다. 사이트는 다시 연결을 요청해야 계정을 볼 수 있습니다.".to_owned(),
                "모두 해제",
            ),
            Confirm::Discard => ("거래 폐기", T_DISCARD.to_owned(), "폐기"),
            Confirm::LlmOn => (
                "AI 설명 켜기",
                self.llm_notice_text().unwrap_or_default(),
                "켜기",
            ),
            Confirm::PruneDormant => (
                "보관 항목 삭제",
                format!(
                    "이 버전에서 쓰지 않는 항목 {}개({})를 apikeys.dpapi에서 지웁니다. 나중에 그 체인을 다시 추가하거나 다른 버전의 앱을 쓰면 주소·자격 정보를 다시 입력해야 합니다.",
                    self.apikeys.dormant_names().len(),
                    self.apikeys.dormant_names().join(", ")
                ),
                "삭제",
            ),
        };
        let destructive = matches!(
            kind,
            Confirm::PruneDormant
                | Confirm::ChainDelete
                | Confirm::BookDelete
                | Confirm::TokenDelete
                | Confirm::DisconnectAll
                | Confirm::Discard
                | Confirm::RemoveKey
                | Confirm::RemoveImported
                | Confirm::RemoveYubiKey
                | Confirm::JournalCorrupt
        );
        items.push(Item::Title(title.to_owned()));
        items.push(Item::CardStart(None));
        items.push(Item::Text(text));
        if kind == Confirm::RemoveKey {
            self.remove_key_balance(items);
        }
        if kind == Confirm::TokenDelete
            && let Some((label, address)) = self.token_delete_target()
        {
            items.push(Item::Field("토큰".to_owned(), label));
            items.push(Item::Help("컨트랙트 주소".to_owned()));
            items.push(Item::Mono(yw_core::evm::display::format_address(&address)));
        }
        if matches!(kind, Confirm::RemoveImported | Confirm::RevealImported)
            && let Some((label, address)) = self.imported_target_text()
        {
            items.push(Item::Field("계정".to_owned(), label));
            items.push(Item::Mono(address));
        }
        if kind == Confirm::Generate {
            items.push(Item::Row(vec![Ctl::check(
                ids::OVERWRITE_CHECK,
                "기존 URL 덮어쓰기",
                self.overwrite_checked,
            )]));
        }
        if matches!(kind, Confirm::ChainRepin | Confirm::LlmOn) {
            let (check_id, check_text, checked) = if kind == Confirm::LlmOn {
                (
                    crate::ui::screens_llm::ids::NOTICE_CHECK,
                    "이해했습니다",
                    self.llm_ui.notice_checked,
                )
            } else {
                (
                    crate::ui::screens_evm::ids::REPIN_CHECK,
                    "새 제네시스 해시를 공식 자료로 확인했습니다",
                    self.evm.repin.as_ref().is_some_and(|repin| repin.checked),
                )
            };
            items.push(Item::Row(vec![Ctl::check(check_id, check_text, checked)]));
            items.push(Item::Row(vec![
                Ctl::primary(ids::CONFIRM_YES, yes).enabled(checked),
                Ctl::button(ids::CONFIRM_NO, "취소"),
            ]));
            items.push(Item::CardEnd);
            return;
        }
        if kind == Confirm::SidecarCorrupt {
            items.push(Item::Row(vec![
                Ctl::primary(ids::SIDECAR_PREV, "이전 사본(.prev) 사용"),
                Ctl::danger(ids::SIDECAR_FRESH, "격리하고 새로 시작"),
            ]));
        } else {
            let no = match (kind, btc) {
                (Confirm::Btc, Some(confirm)) => confirm.no_label(),
                _ => "취소",
            };
            items.push(Item::Row(vec![
                if destructive {
                    Ctl::danger(ids::CONFIRM_YES, yes)
                } else {
                    Ctl::primary(ids::CONFIRM_YES, yes)
                },
                Ctl::button(ids::CONFIRM_NO, no),
            ]));
        }
        items.push(Item::CardEnd);
    }

    /// The balance check of the imported key about to be removed (the selected EVM network's
    /// native balance as last read; other networks and tokens are not checked).
    fn remove_key_balance(&self, items: &mut Vec<Item>) {
        let chain_id = self.settings.evm_chain_id;
        let account = self.pending_remove.and_then(|id| {
            self.meta.as_ref()?.evm_raw_accounts.iter().find_map(|raw| {
                (raw.record_id == *id.as_bytes())
                    .then(|| yw_core::evm::address::parse_address(&raw.address).ok())
                    .flatten()
                    .map(|address| (raw.label.clone(), address))
            })
        });
        let Some((label, address)) = account else {
            return;
        };
        items.push(Item::Field("계정".to_owned(), label));
        items.push(Item::Mono(format_address(&address)));
        let network = self.network_label(chain_id);
        match self.native_balance(chain_id, &address) {
            Some(balance) if !balance.is_zero() => items.push(Item::Banner(
                format!(
                    "이 계정에 잔액이 있습니다: {} ({network}). 지우기 전에 다른 계정으로 옮기거나, 설정 → 보안 → '개인키 보기'로 개인키를 먼저 내보내세요.",
                    self.native_text(chain_id, &balance)
                ),
                Tone::HighRisk,
            )),
            Some(_) => items.push(Item::Help(format!(
                "{network} 잔액: 0. 다른 네트워크와 토큰 잔액은 여기서 확인하지 않았습니다."
            ))),
            None => items.push(Item::Banner(
                format!(
                    "이 계정의 잔액을 확인하지 못했습니다({network}). 자산이 남아 있을 수 있으니 개인키를 먼저 내보내세요."
                ),
                Tone::Warn,
            )),
        }
    }

    fn generate_text(&self) -> String {
        let (targets, skipped) = self.generation_plan();
        let mut text = "선택한 템플릿으로 아래 네트워크의 RPC URL을 만듭니다. 이미 URL이 있는 네트워크는 '기존 URL 덮어쓰기'를 켰을 때만 바꿉니다.".to_owned();
        for network in targets {
            let existing = if self.apikeys.has(KeyName::Rpc(network)) {
                " — 기존 URL 있음"
            } else {
                ""
            };
            let _ = write!(
                text,
                "\n· {} ({network}){existing}",
                self.network_name(network)
            );
        }
        if !skipped.is_empty() {
            text.push_str("\n건너뜀(템플릿 항목 없음):");
            for network in skipped {
                let _ = write!(text, "\n· {} ({network})", self.network_name(network));
            }
        }
        text
    }
}
