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
use crate::app::{App, AppMode, Confirm, Screen, SettingsSection, TestState};
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
    /// The EVM network card's failure band: `이 네트워크 RPC 테스트` (2026-11-10).
    pub const EVM_RPC_TEST: u16 = 16_711;
    /// The Solana network card's failure band: `이 네트워크 RPC 테스트`.
    pub const SOL_RPC_TEST: u16 = 16_712;
    /// The EVM failure band's `RPC 설정 열기` (that network's row, `open_rpc_row(_, false)`).
    pub const EVM_RPC_ROW: u16 = 16_713;
    /// The Solana failure band's `RPC 설정 열기`.
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
pub const CREATE_STEPS: [&str; 3] = ["비밀번호 정하기", "복구 단어 적기", "백업 확인"];
/// Steps of the import flow (S05 → W01 → W05 → S06, spec/04 §2.4).
pub const IMPORT_STEPS: [&str; 3] = ["비밀번호 정하기", "복구 단어 입력", "첫 주소 확인"];

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
pub fn back_main() -> Item {
    Item::Row(vec![Ctl::link(ids::BACK_MAIN, "← 메인으로")])
}

/// S08 `QuickNode 주소`'s help (2026-11-10).
pub const T_DONE_QUICKNODE: &str = "QuickNode 대시보드의 엔드포인트 주소(https://….quiknode.pro/…/)를 통째로 붙여넣으세요. 쓸 체인(Ethereum·Arbitrum·Base·Solana·Bitcoin 등)은 대시보드에서 그 엔드포인트에 켜 두어야 합니다. 입력은 가려지고, 이 Windows 사용자만 풀 수 있게 암호화해 저장합니다.";
/// The `RPC 공급자` card's `QuickNode` note (2026-11-10): a chain not enabled on the endpoint
/// fails its test.
pub const T_QUICKNODE_CHAINS: &str = "QuickNode는 대시보드에서 쓸 체인(Ethereum·Arbitrum·Base·Solana·Bitcoin 등)을 엔드포인트에 하나씩 켜야 그 네트워크가 작동합니다.";

/// T-FIRST-1 (S01, three plain sentences).
pub const T_FIRST: [&str; 3] = [
    "Your Wallet은 이 PC에서만 쓰는 개인용 암호화폐 지갑입니다.",
    "돈을 보내거나 사이트에 서명할 때는 언제나 이 앱의 확인 창에서 내용을 보고 직접 승인합니다.",
    "지갑을 만들 때 받는 복구 단어 24개가 유일한 백업입니다. 종이에 적어 안전한 곳에 보관하세요.",
];

/// T-BACKUP-FAIL (W10 after a wrong answer, spec/04 §2.3): the same four positions are asked
/// again, and the paper may be what is wrong. `words_again`: closing W10 leads back to the words
/// (S04 or the recovery-phrase list); the new `YubiKey` wallet's W10 has no way back to them.
#[must_use]
pub fn backup_retry_text(positions: [u8; 4], words_again: bool) -> String {
    let [a, b, c, d] = positions;
    let next = if words_again {
        "종이에 잘못 적었을 수 있으니, 이 창을 닫고 복구 단어를 다시 보면서 이 네 단어를 종이와 대조해 고치세요."
    } else {
        "종이의 이 네 단어를 다시 확인하세요. 종이가 틀렸는지 알 수 없다면 이 창을 닫아 만들기를 취소하고(단어는 지워집니다) 처음부터 다시 만드세요."
    };
    format!(
        "입력한 단어 중 종이와 다른 것이 있습니다. 같은 위치({a}·{b}·{c}·{d}번째)를 다시 묻습니다. {next}"
    )
}

/// The selected-account card of a network without an RPC address (spec/04 §2.6, 2026-11-08):
/// why there is no balance, in place of "RPC 연결을 확인하고 새로고침하세요".
#[must_use]
pub fn no_endpoint_text(network: &str) -> String {
    format!("이 네트워크({network})의 RPC 주소가 아직 없어 잔액을 읽을 수 없습니다.")
}

/// The selected-account card while its balance read failed (2026-11-10): the network card above
/// says why and what to do, once.
pub const T_BALANCE_FAILED: &str = "잔액을 읽지 못했습니다 — 위 네트워크 카드의 안내를 보세요.";
/// Under the big balance while the first read of the network is on its way.
pub const T_BALANCE_LOADING: &str = "잔액을 불러오는 중…";

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
pub fn balance_read_text(block: Option<u64>, at_unix_ms: Option<u64>) -> String {
    let when = at_unix_ms.map(|at| format!("{} 갱신", local_hh_mm(at)));
    match (block, when) {
        (Some(block), Some(when)) => format!("블록 {block} 기준 · {when}"),
        (Some(block), None) => format!("블록 {block} 기준"),
        (None, Some(when)) => when,
        (None, None) => String::new(),
    }
}

/// The network card's band of a failed balance read (2026-11-10): the code's whole §7 text, and
/// where the balance below comes from when there is one (`last` = "블록 N에서", "HH:MM에").
#[must_use]
pub fn balance_failure_text(code: ErrorCode, last: Option<&str>) -> String {
    match last {
        Some(last) => format!(
            "{} 아래 잔액은 {last} 마지막으로 읽은 값입니다.",
            code.text()
        ),
        None => code.text(),
    }
}

/// The empty activity cards (2026-11-08): received deposits are not listed (spec/04 §2.6).
pub const T_ACTIVITY_RECEIVED: &str =
    "받은 입금은 이 목록에 나오지 않습니다. 선택 계정의 잔액(새로고침)으로 확인하세요.";

/// T-ALT-PASS (every screen while `App::passphrase_unverified`, spec/04 §2.1): not dismissible.
pub const T_ALT_PASS: &str = "passphrase 확인값과 맞지 않는 passphrase로 연 지갑입니다. 오타라면 이 지갑은 원래 지갑이 아닌 다른(빈) 지갑이고, 여기로 받은 자산은 지금 입력한 passphrase와 대소문자·공백까지 정확히 같은 값을 다시 넣어야만 꺼낼 수 있습니다. 그래서 받기와 사이트 연결·서명을 막았습니다. 추가한 계정·계정 이름·주소록·연결 기록도 저장되지 않습니다. 잘못 입력했다면 잠그고 다시 여세요.";
/// Shown when `받기` is pressed in that mode.
pub const T_ALT_PASS_RECEIVE: &str = "확인되지 않은 passphrase로 연 지갑에서는 받기를 쓸 수 없습니다. 잠그고 passphrase를 다시 입력하세요.";
/// T-MAINNET: the main-screen badge of a network with real assets (EVM mainnets, Solana mainnet;
/// Bitcoin shows `BITCOIN MAINNET`, spec/08 §2).
pub const T_MAINNET: &str = "메인넷 — 실제 자산";
/// S10 `내 계정` help: only derived accounts come back from the recovery words.
pub const T_ACCOUNTS_BACKUP: &str = "보내기·받기에 쓸 계정을 고르세요. 경로(m/44'/60'/…)가 있는 계정은 복구 단어로 복구되지만, '가져온 개인키' 계정은 복구 단어로 복구되지 않으니 그 개인키를 따로 백업하세요.";
/// S10 `내 계정` help of a key-only wallet (no recovery words).
pub const T_ACCOUNTS_KEY_ONLY: &str = "보내기·받기에 쓸 계정을 고르세요. 이 지갑은 개인키로 시작해 복구 단어가 없습니다. 모든 계정은 '가져온 키'이며 각각의 원래 개인키가 유일한 백업입니다.";
/// The `내 계정` / `내 Solana 계정` help of a wallet without recovery words that has `YubiKey`
/// cards (2026-11-10: not the key-only text, which says the wallet started from a key).
pub const T_ACCOUNTS_YUBIKEY: &str = "보내기·받기에 쓸 계정을 고르세요. 이 지갑은 복구 단어를 저장하지 않습니다. [YubiKey] 계정의 키는 카드 안에만 있고, 백업은 등록할 때 적은 복구 단어입니다(복구 단어 없이 연결한 키는 그 카드와 같은 키를 가진 백업 카드).";
/// Its last sentence when the wallet also has imported keys.
pub const T_ACCOUNTS_IMPORTED: &str = "[가져온 키]는 원래 개인키가 백업입니다.";
/// Added to T-ACCOUNTS-BACKUP when a wallet with recovery words has `YubiKey` accounts.
pub const T_ACCOUNTS_YUBIKEY_WORDS: &str = "[YubiKey] 계정은 YubiKey를 등록할 때 쓴 복구 단어로 복구됩니다(이 지갑의 복구 단어와 다를 수 있음).";
/// The imported-key removal confirmation (export first: imported keys are not in the 24 words).
pub const T_REMOVE_KEY: &str = "선택한 가져온 개인키 계정을 이 지갑에서 지웁니다. 가져온 개인키는 복구 단어로 복구되지 않으므로, 지우고 나면 원래 개인키 없이는 이 계정의 자산에 다시 접근할 수 없습니다. 지우기 전에 설정 → 보안 → '개인키 보기'로 개인키를 내보내 안전하게 보관했는지 확인하세요. 계속하려면 비밀번호를 입력하세요.";
/// The EVM `폐기` confirmation: discarding only stops tracking; a resend may pay twice.
pub const T_DISCARD: &str = "폐기는 이 앱에서 추적만 멈추고 '폐기됨'으로 표시합니다. 네트워크에서 거래를 취소하지는 않습니다. 이미 전파된 거래라면 나중에 처리될 수 있고, 그 사이 같은 송금을 다시 보내면 두 거래가 모두 처리되어 두 번 지불될 수 있습니다. 확실히 막으려면 폐기 대신 '취소'(같은 nonce의 취소 거래)를 쓰고, 다시 보내기 전에 탐색기에서 이 거래가 사라졌는지 확인하세요.";
/// T-TOKEN-DELETE: `삭제` of a user-added EVM token (spec/04 §2.6); the label and the full
/// contract address follow it.
pub const T_TOKEN_DELETE: &str = "이 토큰을 이 네트워크의 토큰 목록에서 지웁니다. 토큰이나 잔액은 그대로이며 블록체인에는 아무것도 보내지 않습니다. 같은 컨트랙트 주소로 언제든 다시 추가할 수 있습니다. 지운 뒤 이 토큰의 활동 기록은 원시 단위로 보입니다.";
/// The `내 계정` row of a wallet's only account: its address and balance are on the hero card.
pub const T_SINGLE_ACCOUNT: &str = "주소와 잔액은 위 카드에 있습니다";
/// Under the off `숨기기` of a recovery phrase's account 0 (EVM, Solana; 2026-11-10).
pub const T_FIRST_ACCOUNT_KEPT: &str = "각 복구 단어의 첫 계정(…/0)은 숨길 수 없습니다.";
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
    app.meta_failed_items(items);
    app.journal_closed_items(items);
    if app.guard.pending.is_some() && app.screen != Screen::Confirm(Confirm::SettingsFile) {
        // What differs, in plain words with both values (2026-11-08); the safe choice is the
        // primary button and `파일 값 사용…` asks once more (spec/04 §6.7).
        items.push(Item::Banner(
            format!(
                "{}. 지금은 앱에 저장된 값을 씁니다. 직접 바꾼 것이 아니라면 '앱에 저장된 값으로 되돌리기'를 누르세요.",
                crate::settings::SETTINGS_TAMPERED_TEXT
            ),
            Tone::Warn,
        ));
        for line in app.settings_file_lines() {
            items.push(Item::Help(line));
        }
        items.push(Item::Row(vec![
            Ctl::primary(ids::SETTINGS_RESTORE, "앱에 저장된 값으로 되돌리기"),
            Ctl::button(ids::SETTINGS_ACCEPT_FILE, "파일 값 사용…"),
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
            "알림 닫기",
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

fn cap_value(text: &str) -> &str {
    if text.is_empty() { "기본값" } else { text }
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
        let mut lines = Vec::new();
        for kind in differing {
            match kind {
                crate::settings::Differing::AutoLock => lines.push(format!(
                    "자동 잠금: 지금 {}분 → 파일 {}분 (autoLockMinutes)",
                    current.auto_lock_minutes, file.auto_lock_minutes
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
                            caps.map_or("기본값", |caps| cap_value(pick(caps))).to_owned()
                        };
                        lines.push(format!(
                            "EVM 수수료 상한 — {}: maxFee {} → {} gwei · 우선 수수료 {} → {} gwei · 총 {} → {} (feeCaps)",
                            self.network_name(NetworkId::Eip155(id)),
                            part(now.as_ref(), |caps| &caps.max_fee_per_gas_gwei),
                            part(then.as_ref(), |caps| &caps.max_fee_per_gas_gwei),
                            part(now.as_ref(), |caps| &caps.max_priority_fee_per_gas_gwei),
                            part(then.as_ref(), |caps| &caps.max_priority_fee_per_gas_gwei),
                            part(now.as_ref(), |caps| &caps.max_total_fee),
                            part(then.as_ref(), |caps| &caps.max_total_fee),
                        ));
                    }
                }
                crate::settings::Differing::Indexer => {
                    let server = |bitcoin: &crate::settings::BitcoinSettings| {
                        format!(
                            "{} (mainnet {} · testnet4 {})",
                            indexer_name(bitcoin.indexer),
                            cap_value(&bitcoin.esplora_mainnet),
                            cap_value(&bitcoin.esplora_testnet4)
                        )
                    };
                    lines.push(format!(
                        "Bitcoin 주소 조회 서버: 지금 {} → 파일 {} (bitcoin.indexer/esploraBaseUrl) — 파일 값을 쓰면 주소 조회가 그 서버로 갑니다",
                        server(&current.bitcoin),
                        server(&file.bitcoin)
                    ));
                }
                crate::settings::Differing::NewChains => {
                    for chain in file.evm_chains.iter().filter(|chain| {
                        !current
                            .evm_chains
                            .iter()
                            .any(|known| known.chain_id == chain.chain_id)
                    }) {
                        lines.push(format!(
                            "새 사용자 체인: {} (chainId {}) — 앱이 제네시스를 고정한 적 없음 (evmChains)",
                            chain.name, chain.chain_id
                        ));
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
        let lines = self.backup_status_lines();
        if lines.is_empty() {
            items.push(Item::Help(
                "복구 단어(니모닉)는 지갑 전체의 백업입니다. 보기 전에 비밀번호를 다시 묻고, 화면 캡처에서 제외된 창에 보여줍니다."
                    .to_owned(),
            ));
        } else {
            // Several backups (2026-11-08): the first recovery phrase is no longer the
            // whole wallet's backup, so say what each part needs (status only, no values).
            items.push(Item::Subtitle(
                "백업 현황 — 이 지갑을 다시 열려면".to_owned(),
            ));
            for line in lines {
                items.push(Item::Text(line));
            }
            items.push(Item::Help(
                "이 PC의 비밀번호는 백업이 아닙니다. 보기 전에 비밀번호를 다시 묻고, 화면 캡처에서 제외된 창에 보여줍니다."
                    .to_owned(),
            ));
        }
        let several = self.several_mnemonics();
        let mut row = vec![
            Ctl::button(
                ids::REVEAL_MNEMONIC,
                if several {
                    "첫 복구 단어 보기"
                } else {
                    "복구 단어 보기"
                },
            )
            .enabled(public),
            Ctl::button(ids::REVEAL_KEY, "개인키 보기")
                .enabled(unlocked && !self.hardware_selected()),
        ];
        if several {
            row.push(Ctl::link(
                crate::ui::screens_mnemonics::ids::MAIN_LINK,
                "복구 단어 관리 ▸",
            ));
        }
        items.push(Item::Row(row));
    }

    /// The `내 계정` / `내 Solana 계정` help (2026-11-10): a wallet without recovery words that has
    /// `YubiKey` cards says where their keys' backup is (not the key-only text); a wallet with
    /// words and `YubiKey` accounts adds that those come back with the card's own words.
    #[must_use]
    pub(crate) fn accounts_help(
        &self,
        key_only: &str,
        words: &str,
        has_card: bool,
        imported: bool,
    ) -> String {
        if self.key_only() && !self.card.records.is_empty() {
            if imported {
                format!("{T_ACCOUNTS_YUBIKEY} {T_ACCOUNTS_IMPORTED}")
            } else {
                T_ACCOUNTS_YUBIKEY.to_owned()
            }
        } else if self.key_only() {
            key_only.to_owned()
        } else if has_card {
            format!("{words} {T_ACCOUNTS_YUBIKEY_WORDS}")
        } else {
            words.to_owned()
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
        let imported = self.imported_key_count();
        let mut lines = Vec::new();
        for info in &self.mn.infos {
            lines.push(format!(
                "· {} · {}단어{}{} · {}",
                self.mnemonic_label(info.id),
                info.words,
                if info.passphrase_used {
                    " + passphrase"
                } else {
                    ""
                },
                if info.primary {
                    " (첫 복구 단어)"
                } else {
                    ""
                },
                if info.backup_confirmed {
                    "백업 확인됨 ✓"
                } else {
                    "백업 확인 전 ⚠ — 설정 → 복구 단어에서 '백업 확인'"
                }
            ));
        }
        if imported > 0 {
            lines.push(format!(
                "· 가져온 개인키 {imported}개 — 복구 단어로 되찾을 수 없고, 각각 원래 개인키가 백업입니다"
            ));
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
                let title = slot.role.title();
                lines.push(
                    if yw_core::yubikey::plan::is_unknown_index(slot.role.index()) {
                        if holders.len() > 1 {
                            format!("· {title} — 복구 단어 없음, {cards}에 있음")
                        } else {
                            format!("· {title} — 복구 단어 없음, {cards}에만 있음 ⚠")
                        }
                    } else {
                        format!("· {title} — YubiKey {cards} · 복구 단어로 다시 만들 수 있음")
                    },
                );
            }
        }
        lines
    }
}

/// The one-line map under the settings tabs: what the selected section holds, and where the
/// things that are not in settings live (spec/04 §2.11).
#[must_use]
pub const fn settings_map(section: SettingsSection) -> &'static str {
    match section {
        SettingsSection::Security => {
            "이 구역: 자동 잠금 · 백업 현황 · 첫 복구 단어·개인키 보기와 복사 허용 · 비밀번호 변경 · 지갑 파일 상태 · 지갑 초기화. 복구 단어별 보기·백업 확인은 '복구 단어' 탭에 있습니다."
        }
        SettingsSection::Network => {
            "이 구역: RPC 공급자(QuickNode·알케미) · 네트워크별 RPC 주소(EVM·Solana·Bitcoin·Zcash) · rpc.json 가져오기(개발용, 파일이 있을 때 맨 아래)"
        }
        SettingsSection::Chains => {
            "이 구역: EVM 체인 목록과 체인 추가·편집 · Hyperliquid HyperCore 카드 켜기 · 수수료 상한(고급). 토큰 추가는 메인의 '토큰' 카드에 있습니다."
        }
        SettingsSection::Solana => {
            "이 구역: Solana 네트워크(mainnet·devnet) · 다른 경로 스캔 · 수수료 상한(고급)"
        }
        SettingsSection::Bitcoin => {
            "이 구역: Bitcoin 사용과 네트워크 · 주소 조회 서버(인덱서) · Esplora URL. Bitcoin 계정·주소 방식은 메인의 Bitcoin 탭에 있습니다."
        }
        SettingsSection::Ai => "이 구역: AI 설명(선택 기능) 켜기 · AI 공급자 · AI API 키",
        SettingsSection::Mnemonics => {
            "이 구역: 지갑의 복구 단어 목록 · 복구 단어 추가 가져오기 · 새 복구 단어 만들기 · 이름 바꾸기 · 단어 보기 · 백업 확인 · 지우기"
        }
        SettingsSection::YubiKey => {
            "이 구역: YubiKey 등록 · PIN 설정 · 슬롯 구성 바꾸기 · YubiKey의 키 지우기 · 계정별 YubiKey. 서명할 때는 승인 뒤 PIN 창이 저절로 열립니다."
        }
        SettingsSection::Other => {
            "이 구역: Chrome 확장 설치 · WalletConnect · 브라우저 연결 · 진단(로그) · 버전·데이터 폴더·단축키. Zcash는 메인의 Zcash 탭에서 켭니다."
        }
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
                    Ctl::button(
                        crate::ui::screens_sites::ids::SITES_OPEN,
                        "사이트·WalletConnect",
                    ),
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
        // The first two sentences are true for every path; the third (24 words are the only
        // backup) belongs to the new-wallet card (2026-11-08).
        for sentence in &T_FIRST[..2] {
            items.push(Item::Text((*sentence).to_owned()));
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
        // Two groups (2026-11-08): start something new, or bring back a wallet already used;
        // all five ways are on the first view of the default window.
        let enabled = !self.leftover;
        items.push(Item::CardStart(Some("새로 시작합니다".to_owned())));
        items.push(Item::Text(
            "새 지갑을 만들고 복구 단어 24개를 종이에 적습니다. 5분쯤 걸립니다.".to_owned(),
        ));
        items.push(Item::Help(T_FIRST[2].to_owned()));
        items.push(Item::Row(vec![
            Ctl::primary(ids::FIRST_CREATE, "새 지갑 만들기").enabled(enabled),
            Ctl::button(
                crate::ui::screens_yubikey::ids::NEW_WALLET,
                "YubiKey에 보관하는 새 지갑",
            )
            .enabled(enabled),
        ]));
        items.push(Item::Help(format!(
            "YubiKey에 보관하는 새 지갑: {} YubiKey 5(펌웨어 5.2.3 이상, Solana 계정은 5.7.4 이상)가 필요합니다.",
            crate::app_yubikey::T_YK_WALLET
        )));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            "이미 쓰던 지갑이 있습니다".to_owned(),
        )));
        items.push(Item::Row(vec![
            Ctl::button(ids::FIRST_IMPORT, "복구 단어로 가져오기").enabled(enabled),
            Ctl::button(crate::ui::screens_keys::ids::FIRST_KEY, "개인키로 시작하기")
                .enabled(enabled),
            Ctl::button(
                crate::ui::screens_yubikey::ids::CONNECT_NEW_WALLET,
                "YubiKey 연결하기 (복구 단어 없이)",
            )
            .enabled(enabled),
        ]));
        for line in [
            "· 복구 단어로 가져오기: 다른 지갑에서 쓰던 영어 복구 단어(니모닉) 12·15·18·21·24개로 그 지갑을 그대로 가져옵니다.".to_owned(),
            format!("· 개인키로 시작하기: {}", crate::ui::screens_keys::T_KEY_START_CARD),
            "· YubiKey 연결하기: 이미 키가 들어 있는 YubiKey(새 PC, 다시 설치)를 복구 단어 없이 연결합니다. 카드의 공개키만 읽고 아무것도 쓰지 않습니다.".to_owned(),
        ] {
            items.push(Item::Help(line));
        }
        items.push(Item::CardEnd);
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
        if let Some(done) = self.done_yubikey {
            let (text, backup) = match done {
                crate::app_yubikey::YkDone::Created(serial) => (
                    format!("YubiKey 지갑을 만들었습니다 (YubiKey #{serial})."),
                    "이 지갑의 백업은 방금 적은 복구 단어 24개입니다. 이 PC에는 저장하지 않았으니 종이를 안전하게 보관하세요.",
                ),
                crate::app_yubikey::YkDone::Connected(serial) => (
                    format!("YubiKey를 연결했습니다 (YubiKey #{serial})."),
                    "복구 단어 없이 카드의 공개키로 연결했습니다. 이 PC에는 개인키도 복구 단어도 없어 카드가 그 키의 유일한 사본일 수 있습니다 — 카드를 잃었을 때를 대비해 원래 백업(복구 단어 등)이 있는지 확인하세요.",
                ),
            };
            items.push(Item::Banner(text, Tone::Success));
            items.push(Item::Help(backup.to_owned()));
        } else if self.keys.done_start {
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
        // One '처음 설정' card (2026-11-10): RPC, the optional dApp connection, a first small
        // deposit; `지갑 열기` always below it.
        items.push(Item::CardStart(Some("처음 설정".to_owned())));
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
            "지갑 열기",
        )]));
    }

    /// S08 ① 블록체인 연결(RPC): the `QuickNode` address field while there is no address, the
    /// results of `연결하기`, or how many addresses there are and this run's tests.
    fn done_rpc_items(&self, items: &mut Vec<Item>) {
        items.push(Item::Subtitle("① 블록체인 연결(RPC)".to_owned()));
        if !self.done_tested.is_empty() {
            self.done_results(items);
            return;
        }
        if !self.apikeys.endpoints().is_empty() {
            let (configured, _, works, failed, _) = self.rpc_summary();
            items.push(Item::Text(format!(
                "RPC 주소 {configured}개 · 이번 실행 테스트: 작동 {works} · 실패 {failed}"
            )));
            items.push(Item::Row(vec![Ctl::button(ids::DONE_RPC, "RPC 설정 열기")]));
            return;
        }
        items.push(Item::Text(
            "잔액을 보고 돈을 보내려면 블록체인 노드에 연결할 RPC 주소가 필요합니다.".to_owned(),
        ));
        if self.settings.rpc_template == RpcTemplate::QuickNode {
            items.push(Item::LabeledRow(
                "QuickNode 주소".to_owned(),
                vec![Ctl::edit(ids::DONE_QN_EDIT, "", 520, true, 256)],
            ));
            items.push(Item::Help(T_DONE_QUICKNODE.to_owned()));
            if let Some(error) = &self.done_error {
                items.push(Item::Banner(error.clone(), Tone::Danger));
            }
            items.push(Item::Row(vec![
                Ctl::primary(ids::DONE_CONNECT, "연결하기"),
                Ctl::link(ids::DONE_RPC, "알케미·직접 입력은 설정에서 ▸"),
            ]));
        } else {
            items.push(Item::Help(
                "선택한 RPC 공급자의 자격 정보나 주소는 설정 → 네트워크(RPC)에서 넣습니다."
                    .to_owned(),
            ));
            items.push(Item::Row(vec![Ctl::button(ids::DONE_RPC, "RPC 설정하기")]));
        }
        if crate::app_rpc_import::rpc_json_path().is_some_and(|path| path.is_file()) {
            items.push(Item::Row(vec![Ctl::link(
                ids::DONE_RPC_JSON,
                "rpc.json이 있습니다 — 설정에서 가져오기 ▸",
            )]));
        }
    }

    /// S08 after `연결하기`: one line per network made (✓ works / ✗ with its §7 text and a link to
    /// its row / … testing), then the count.
    fn done_results(&self, items: &mut Vec<Item>) {
        let networks = self.url_networks();
        let mut works = 0_usize;
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
                            &format!("{name} 행 열기 ▸"),
                        )]));
                    }
                }
                Some((_, TestState::Testing)) | None => {
                    items.push(Item::Muted(format!("… {name} 테스트 중")));
                }
            }
        }
        items.push(Item::Subtitle(format!(
            "{}개 중 {works}개 작동",
            self.done_tested.len()
        )));
        if failed {
            items.push(Item::Help(
                "QuickNode 대시보드에서 그 체인을 켰는지 확인한 뒤 설정 → 네트워크(RPC)의 “모두 테스트”로 다시 확인하세요. 나머지는 지금 쓸 수 있습니다."
                    .to_owned(),
            ));
        }
        items.push(Item::Row(vec![Ctl::button(ids::DONE_RPC, "RPC 설정 열기")]));
    }

    /// S08 ② dApp 연결 (선택): the Chrome extension or `WalletConnect`.
    fn done_dapp_items(&self, items: &mut Vec<Item>) {
        items.push(Item::Subtitle("② dApp 연결 (선택, 둘 중 하나)".to_owned()));
        items.push(Item::Text(format!(
            "Chrome 확장: {}",
            self.extension_status().text()
        )));
        items.push(Item::Row(vec![Ctl::button(
            crate::ui::screens_reset::ids::EXT_OPEN,
            "설치 방법",
        )]));
        items.push(Item::Text(format!(
            "WalletConnect: {}",
            if self.settings.walletconnect_project.is_empty() {
                "Project ID 없음"
            } else {
                "설정됨"
            }
        )));
        items.push(Item::Row(vec![Ctl::button(ids::DONE_WC, "설정")]));
    }

    /// S08 ③ 첫 입금 시험: receive on the wallet's first chain (EVM when it has an account).
    fn done_deposit_items(&self, items: &mut Vec<Item>) {
        items.push(Item::Subtitle("③ 첫 입금 시험".to_owned()));
        let evm = self.selected_account().is_some();
        let mut text = "실제 자산은 소액으로 받기 → 보내기를 한 번 해 보세요.".to_owned();
        if evm {
            if self.settings.evm_chain_id == SEPOLIA {
                text.push_str(" EVM 탭은 Sepolia 테스트넷으로 시작합니다.");
            } else {
                let _ = write!(
                    text,
                    " 지금 EVM 네트워크: {}.",
                    self.network_name(NetworkId::Eip155(self.settings.evm_chain_id))
                );
            }
        }
        items.push(Item::Text(text));
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
            items.push(Item::Row(vec![Ctl::button(id, "받기")]));
        }
    }

    /// S08 after an import or "개인키로 시작하기": why a wallet that held funds may show none
    /// (the network, accounts not searched, chains off).
    fn done_balance_card(&self, items: &mut Vec<Item>) {
        let mut lines: Vec<Item> = Vec::new();
        if self.selected_account().is_some() {
            if self.settings.evm_chain_id == SEPOLIA {
                lines.push(Item::Text(
                    "· EVM 탭은 Sepolia 테스트넷으로 시작합니다 — 쓰던 네트워크를 고르세요"
                        .to_owned(),
                ));
                lines.push(Item::Row(vec![Ctl::button(
                    ids::DONE_MAINNET,
                    "Ethereum 메인넷으로 보기",
                )]));
            } else {
                lines.push(Item::Text(format!(
                    "· EVM 탭은 지금 {}입니다 — 다른 네트워크는 메인 화면의 네트워크 칩에서 고르세요",
                    self.network_name(NetworkId::Eip155(self.settings.evm_chain_id))
                )));
            }
        }
        if self.done_imported {
            lines.push(Item::Text(
                "· 계정은 자동으로 찾지 않습니다. 이전 지갑에서 계정을 여러 개 썼다면 “내 계정 → 계정 추가”를 차례로 누르세요. Solana의 다른 경로는 Solana 탭 “다른 경로 스캔”."
                    .to_owned(),
            ));
            let bitcoin = !self.settings.bitcoin.enabled;
            let zcash = !self.settings.zcash.enabled;
            let off = match (bitcoin, zcash) {
                (true, true) => Some(
                    "· Bitcoin·Zcash는 꺼져 있습니다 — 설정 → Bitcoin, Zcash 탭에서 켜면 보입니다(Bitcoin은 네이티브 세그윗 계정 0부터).",
                ),
                (true, false) => Some(
                    "· Bitcoin은 꺼져 있습니다 — 설정 → Bitcoin에서 켜면 보입니다(네이티브 세그윗 계정 0부터).",
                ),
                (false, true) => Some("· Zcash는 꺼져 있습니다 — Zcash 탭에서 켜면 보입니다."),
                (false, false) => None,
            };
            if let Some(line) = off {
                lines.push(Item::Text(line.to_owned()));
            }
        }
        if lines.is_empty() {
            return;
        }
        items.push(Item::CardStart(Some("잔액이 안 보이면".to_owned())));
        items.extend(lines);
        items.push(Item::CardEnd);
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
                    items.push(Item::Help(format!(
                        "블록 {block} 기준 · 갱신 실패 {}",
                        code.code()
                    )));
                }
            }
            (Some(value), Some(_)) => {
                items.push(Item::DisplayMuted(self.native_text(chain_id, &value)));
                items.push(Item::Help(T_BALANCE_FAILED.to_owned()));
            }
            (Some(value), None) => {
                items.push(Item::Display(self.native_text(chain_id, &value)));
                if let Some(block) = block {
                    items.push(Item::Help(balance_read_text(
                        Some(block),
                        state.and_then(|state| state.updated_unix_ms),
                    )));
                }
            }
            (None, _) if !endpoint => {
                items.push(Item::Display("잔액 —".to_owned()));
                items.push(Item::Help(no_endpoint_text(
                    &self.network_name(NetworkId::Eip155(chain_id)),
                )));
            }
            (None, Some(_)) if !blocked => {
                items.push(Item::Display("잔액 —".to_owned()));
                items.push(Item::Help(T_BALANCE_FAILED.to_owned()));
            }
            (None, Some(_)) => {
                items.push(Item::Display("잔액 —".to_owned()));
                items.push(Item::Help(
                    "잔액을 아직 읽지 못했습니다. RPC 연결을 확인하고 새로고침하세요.".to_owned(),
                ));
            }
            (None, None) => {
                items.push(Item::Display("잔액 —".to_owned()));
                items.push(Item::Help(T_BALANCE_LOADING.to_owned()));
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
            items.push(Item::Help(format!(
                "토큰: {} (아래 토큰 카드)",
                tokens.join(" · ")
            )));
        }
        items.push(Item::Mono(format_address(&address)));
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        let mut row = vec![
            Ctl::primary(crate::ui::screens_evm::ids::SEND_OPEN, "보내기").enabled(unlocked),
            Ctl::primary(crate::ui::screens_evm::ids::RECEIVE_OPEN, "받기"),
        ];
        if endpoint {
            row.push(Ctl::link(crate::ui::screens_evm::ids::REFRESH, "새로고침"));
        } else {
            // Nothing to refresh without an address: that network's row with its field open
            // (spec/04 §2.6, 2026-11-10).
            row.push(Ctl::button(ids::EVM_RPC_OPEN, "RPC 설정하기"));
        }
        items.push(Item::Row(row));
        items.push(Item::CardEnd);
    }

    #[expect(clippy::too_many_lines, reason = "the S10 sections in order")]
    fn main_screen(&self, items: &mut Vec<Item>) {
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
        self.evm_balance_failure(items);
        items.push(Item::Help(self.evm_status_line()));
        items.push(Item::CardEnd);
        if self.account_rows().is_empty() && self.meta.is_some() {
            self.no_accounts_card(yw_core::keyimport::ImportChain::Evm, items);
            return;
        }
        self.evm_hero(items);
        items.push(Item::CardStart(Some("내 계정".to_owned())));
        let selected = self.selected_pref();
        let rows = self.account_rows();
        let has_card = rows
            .iter()
            .any(|(pref, ..)| matches!(pref, EvmAccountPref::Hardware(_)));
        let imported = self
            .meta
            .as_ref()
            .is_some_and(|meta| !meta.evm_raw_accounts.is_empty());
        items.push(Item::Help(self.accounts_help(
            T_ACCOUNTS_KEY_ONLY,
            T_ACCOUNTS_BACKUP,
            has_card,
            imported,
        )));
        let single = rows.len() == 1;
        for (row, (pref, label, address, path)) in rows
            .into_iter()
            .take(usize::from(ids::ACCOUNT_SPAN))
            .enumerate()
        {
            let is_selected = selected == Some(pref);
            let shown_label = match pref {
                EvmAccountPref::Record(_) => format!("{label}  [가져온 키]"),
                EvmAccountPref::Hardware(_) => format!("{label}  [YubiKey]"),
                EvmAccountPref::Index(_) => match self
                    .several_mnemonics()
                    .then(|| self.primary_mnemonic_label())
                    .flatten()
                {
                    Some(source) => format!("{label}  [{source}]"),
                    None => label.clone(),
                },
                EvmAccountPref::Mnemonic(id, _) => format!(
                    "{label}  [{}]",
                    self.mnemonic_label(yw_core::vault::RecordId::from_bytes(id))
                ),
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
            if single && is_selected {
                // One account: its address and balance are the hero card's (review D3).
                items.push(Item::Help(format!("{path} · {T_SINGLE_ACCOUNT}")));
            } else {
                let balance = self.balance_text(&address);
                let shown = yw_core::evm::address::parse_address(&address)
                    .map_or_else(|_| address.clone(), |parsed| format_address(&parsed));
                items.push(Item::Mono(shown));
                items.push(Item::Help(match balance {
                    Some(balance) => format!("{path} · {balance}"),
                    None => path,
                }));
            }
            if is_selected {
                if self.rename == Some(pref) {
                    items.push(Item::Row(vec![
                        Ctl::edit(ids::RENAME_EDIT, &label, 260, false, 64),
                        Ctl::primary(ids::RENAME_SAVE, "저장"),
                        Ctl::button(ids::RENAME_CANCEL, "취소"),
                    ]));
                } else {
                    let mut row_ctls = vec![Ctl::button(ids::RENAME, "이름 바꾸기")];
                    let mut first_of_phrase = false;
                    match pref {
                        EvmAccountPref::Index(index) | EvmAccountPref::Mnemonic(_, index) => {
                            first_of_phrase = index == 0;
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
                    if first_of_phrase {
                        // Why `숨기기` is off (2026-11-10).
                        items.push(Item::Help(T_FIRST_ACCOUNT_KEPT.to_owned()));
                    }
                }
            }
            items.push(Item::Gap(4));
        }
        self.hidden_items(crate::app_hidden::Family::Evm, items);
        items.push(Item::Rule);
        let mut actions = Vec::new();
        if !self.key_only() {
            actions
                .push(Ctl::button(ids::ADD_ACCOUNT, "계정 추가").enabled(self.can_add_account()));
        }
        actions.push(
            Ctl::button(ids::IMPORT_KEY, "개인키 가져오기")
                .enabled(self.can_import(yw_core::keyimport::ImportChain::Evm)),
        );
        actions.push(Ctl::link(
            crate::ui::screens_mnemonics::ids::MAIN_LINK,
            "복구 단어 추가·관리",
        ));
        items.push(Item::Row(actions));
        self.mn_pick_row(items);
        items.push(Item::CardEnd);
        self.evm_main_sections(items);
    }

    /// The top link of settings and S13: `← 처음 설정으로` while they were opened from S08's
    /// '처음 설정' card ([`App::done_return`], spec/04 §2.3), else `← 메인으로`.
    #[must_use]
    pub fn back_row(&self) -> Item {
        if self.done_return {
            Item::Row(vec![Ctl::link(ids::BACK_DONE, "← 처음 설정으로")])
        } else {
            back_main()
        }
    }

    fn settings_screen(&self, section: SettingsSection, items: &mut Vec<Item>) {
        items.push(self.back_row());
        items.push(Item::Title("설정".to_owned()));
        items.push(Item::Row(vec![
            Ctl::tab(
                ids::SECTION_SECURITY,
                "보안",
                section == SettingsSection::Security,
            )
            .width(68),
            // Keys and backups first and fixed widths (2026-11-08): the nine tabs keep one row
            // at the default 960 DIP window.
            Ctl::tab(
                crate::ui::screens_mnemonics::ids::SECTION_MNEMONICS,
                "복구 단어",
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
                "네트워크(RPC)",
                section == SettingsSection::Network,
            )
            .width(120),
            Ctl::tab(
                crate::ui::screens_evm::ids::SECTION_CHAINS,
                "EVM 체인",
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
                "AI 설명",
                section == SettingsSection::Ai,
            )
            .width(80),
            Ctl::tab(
                ids::SECTION_OTHER,
                "브라우저·정보",
                section == SettingsSection::Other,
            )
            .width(108),
        ]));
        items.push(Item::Help(settings_map(section).to_owned()));
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
            // No recovery words: what brings this wallet back is said anyway (2026-11-10).
            let lines = self.backup_status_all();
            if !lines.is_empty() {
                items.push(Item::Subtitle(
                    "백업 현황 — 이 지갑을 다시 열려면".to_owned(),
                ));
                for line in lines {
                    items.push(Item::Text(line));
                }
            }
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
            self.backup_card_rows(unlocked, public, items);
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
            "이 PC의 지갑 파일을 데이터 폴더 안의 reset- 폴더로 옮기고(지우지 않음) 처음 화면으로 돌아갑니다. 다시 쓰려면 복구 단어·원래 개인키, 또는 YubiKey(“YubiKey 연결하기 (복구 단어 없이)”)가 필요합니다."
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
        // A pending rpc.json import review stays first (it waits for a decision), and so does the
        // advice to delete the plaintext file right after an import.
        if self.rpc_import.on_top() {
            self.rpc_import_section(items);
        }
        items.push(Item::CardStart(Some("RPC 공급자".to_owned())));
        if !self.rpc_import.on_top()
            && crate::app_rpc_import::rpc_json_path().is_some_and(|path| path.is_file())
        {
            items.push(Item::Text(
                "rpc.json이 있습니다 — 맨 아래 “rpc.json에서 가져오기”로 한 번에 넣을 수 있습니다."
                    .to_owned(),
            ));
        }
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
        let stored = self.template_stored();
        let status = if stored { "설정됨" } else { "없음" };
        match template {
            RpcTemplate::QuickNode => {
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
                items.push(Item::Help(T_QUICKNODE_CHAINS.to_owned()));
            }
            RpcTemplate::Alchemy => {
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
                    "직접 입력: 아래 '네트워크별 RPC 주소'에서 네트워크마다 '입력'으로 https:// 주소를 넣으세요."
                        .to_owned(),
                ));
            }
        }
        let manual = template == RpcTemplate::Manual;
        items.push(Item::Row(vec![
            Ctl::primary(ids::GENERATE, "저장하고 RPC 주소 만들기").enabled(!manual),
            Ctl::button(ids::TPL_SAVE, "자격 정보만 저장").enabled(!manual),
            Ctl::danger(ids::TPL_DELETE, "자격 정보 삭제").enabled(!manual && stored),
        ]));
        if self.rpc_removed == Some(crate::app::RpcRemoved::Template) {
            items.push(Item::Banner(
                "자격 정보를 지웠습니다. 이미 만든 네트워크별 RPC 주소는 그대로입니다.".to_owned(),
                Tone::Success,
            ));
        }
        items.push(Item::Help(
            "'저장하고 RPC 주소 만들기'는 위 칸의 자격 정보를 저장하고 아래 목록의 주소를 한 번에 만든 뒤 하나씩 테스트합니다. 이미 있는 주소는 덮어쓸지 따로 묻습니다."
                .to_owned(),
        ));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("네트워크별 RPC 주소".to_owned())));
        self.rpc_summary_items(items);
        items.push(Item::Help(
            "주소에는 토큰이 들어 있어 가린 형태로만 보입니다. '테스트'는 그 주소가 올바른 네트워크를 가리키는지 한 번 확인합니다."
                .to_owned(),
        ));
        let mut networks = self.url_networks();
        networks.truncate(usize::from(ids::ROW_SPAN / 3));
        let last = networks.len().saturating_sub(1);
        // The note above an open field: the stored credentials can make the empty addresses.
        let template_name = match template {
            RpcTemplate::QuickNode => Some("QuickNode"),
            RpcTemplate::Alchemy => Some("알케미"),
            RpcTemplate::Manual => None,
        };
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
                if let Some(name) = template_name.filter(|_| {
                    stored
                        && crate::apikeys::template_entry(template, network, &self.settings)
                            .is_some()
                }) {
                    items.push(Item::Help(format!(
                        "{name} 자격 정보가 저장되어 있습니다 — 위 “저장하고 RPC 주소 만들기”로 비어 있는 주소를 한 번에 만들 수 있습니다."
                    )));
                }
                items.push(Item::Row(vec![
                    Ctl::edit(ids::REPLACE_EDIT, "", 420, true, 2_048),
                    Ctl::primary(ids::REPLACE_SAVE, "저장"),
                    Ctl::button(ids::REPLACE_CANCEL, "취소"),
                ]));
                items.push(Item::Help(
                    "https:// 로 시작하는 전체 주소를 붙여넣으세요. 저장 전에 형식을 검사하고, 저장하면 바로 테스트합니다."
                        .to_owned(),
                ));
            }
            if let Some((_, message, state)) =
                self.rpc_messages.iter().find(|(id, _, _)| *id == network)
            {
                items.push(Item::Banner(message.clone(), state.tone()));
            }
            if self.rpc_removed == Some(crate::app::RpcRemoved::Url(network)) {
                items.push(Item::Banner(
                    "RPC 주소를 지웠습니다.".to_owned(),
                    Tone::Success,
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
        let (configured, total, works, failed, untested) = self.rpc_summary();
        items.push(Item::Text(format!(
            "RPC 주소 {configured}/{total}개 설정 · 이번 실행 테스트: 작동 {works} · 실패 {failed} · 안 함 {untested}"
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
            items.push(Item::LabeledRow("실패한 네트워크".to_owned(), links));
        }
        let tests = &self.rpc_tests;
        let label = if tests.busy() {
            format!(
                "테스트 중 {}/{}",
                tests.done.saturating_add(1).min(tests.total.max(1)),
                tests.total.max(1)
            )
        } else {
            "모두 테스트".to_owned()
        };
        items.push(Item::Row(vec![
            Ctl::button(ids::TEST_ALL, &label).enabled(configured > 0 && !tests.busy()),
        ]));
    }

    fn other_section(&self, items: &mut Vec<Item>) {
        items.push(Item::CardStart(Some("브라우저 확장".to_owned())));
        items.push(Item::Text(self.extension_status().text().to_owned()));
        items.push(Item::Help(
            crate::ui::screens_reset::T_EXT_COMPAT_SHORT.to_owned(),
        ));
        items.push(Item::Row(vec![Ctl::button(
            crate::ui::screens_reset::ids::EXT_OPEN,
            "Chrome 확장 설치 방법·폴더",
        )]));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("WalletConnect".to_owned())));
        items.push(Item::Help(
            "확장 없이 dApp의 WalletConnect QR·링크로 연결합니다(EVM). 처음 한 번 Reown Project ID가 필요하고, 연결·세션 관리는 '연결된 사이트 · WalletConnect' 화면에서 합니다."
                .to_owned(),
        ));
        items.push(Item::Field(
            "상태".to_owned(),
            if self.settings.walletconnect_project.is_empty() {
                "Project ID 없음 — 꺼져 있음".to_owned()
            } else {
                format!("Project ID 설정됨 · 세션 {}개", self.wc.sessions.len())
            },
        ));
        items.push(Item::Row(vec![Ctl::button(
            crate::ui::screens_sites::ids::SITES_OPEN,
            "연결된 사이트 · WalletConnect 열기",
        )]));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("브라우저 연결".to_owned())));
        items.push(Item::Help(
            "Chrome 확장과 이 앱을 잇는 설정입니다. 사이트의 연결·서명 요청은 언제나 이 앱의 승인 창에서 확인합니다."
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
        // The installed commit says which build runs (2026-11-10, `build_info`).
        items.push(Item::Field(
            "버전".to_owned(),
            crate::build_info::version_text(self.install_commit.as_deref()),
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
            "Ctrl+L 잠금 · Ctrl+1 / 2 / 3 / 4 체인 탭(EVM·Solana·Bitcoin·Zcash) · F5 새로고침 · Ctrl+, 설정 · Esc 뒤로·취소 · Tab 다음 칸 · PgUp / PgDn 한 쪽 스크롤 · Ctrl+Home / End 맨 위·맨 아래"
                .to_owned(),
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
        let btc = self.btc.confirm;
        let (title, text, yes) = match kind {
            Confirm::Btc => btc.map_or(("Bitcoin", String::new(), "확인"), |confirm| {
                confirm.texts()
            }),
            Confirm::CopyOn => (
                "복사 허용",
                "복사를 허용하면 복구 단어(니모닉)·개인키를 클립보드에 넣을 수 있습니다. 클립보드 기록·클라우드 동기화에서는 제외하고 30초 뒤 지우지만, 그 사이에는 다른 프로그램이 읽을 수 있습니다. 그 전에 앱이 비정상 종료되면 다음에 앱을 열 때 지우며, 그때까지는 클립보드에 남습니다.".to_owned(),
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
            Confirm::Generate => ("RPC 주소 만들기", self.generate_text(), "만들기"),
            Confirm::RpcUrlDelete(network) => (
                "RPC 주소 지우기",
                self.rpc_delete_text(network),
                "지우기",
            ),
            Confirm::TemplateDelete => ("자격 정보 지우기", self.template_delete_text(), "지우기"),
            Confirm::LlmKeyDelete => (
                "AI API 키 지우기",
                "저장된 AI 설명용 API 키를 지웁니다. 저장된 키는 다시 볼 수 없어, AI 설명을 다시 쓰려면 키를 다시 넣어야 합니다.".to_owned(),
                "지우기",
            ),
            Confirm::YkAbandon => (
                "YubiKey 지갑 만들기를 그만둘까요?",
                crate::app_yubikey::T_YK_ABANDON.to_owned(),
                "그만두기",
            ),
            Confirm::YkPinLater => (
                "PIN을 나중에 설정할까요?",
                "PIN을 설정하기 전에는 이 YubiKey로 서명하지 않습니다. 나중에 설정 → YubiKey에서 바꿀 수 있습니다."
                    .to_owned(),
                "나중에",
            ),
            // Drawn above.
            Confirm::SidecarCorrupt | Confirm::JournalCorrupt => ("", String::new(), ""),
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
            Confirm::ChainPin => ("체인 추가 — 제네시스 고정", self.chain_pin_text(), "고정하고 저장"),
            Confirm::ChainRepin => ("다시 고정", self.chain_repin_text(), "다시 고정"),
            Confirm::ChainDelete => (
                "체인 삭제",
                "체인 정의, RPC 주소, 수수료 상한을 지웁니다. 이 체인의 토큰·활동 기록은 남고, 같은 chainId를 다시 추가하면 다시 보입니다.".to_owned(),
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
                if self.wc.sessions.is_empty() {
                    "연결된 모든 사이트의 연결을 해제합니다. 사이트는 다시 연결을 요청해야 계정을 볼 수 있습니다.".to_owned()
                } else {
                    format!(
                        "연결된 모든 사이트의 연결을 해제하고 WalletConnect 세션 {}개도 끊습니다(dApp 쪽 연결도 끊깁니다). 사이트는 다시 연결을 요청해야 계정을 볼 수 있습니다.",
                        self.wc.sessions.len()
                    )
                },
                "모두 해제",
            ),
            Confirm::SettingsFile => (
                "설정 파일 값 사용",
                "settings.json의 아래 값을 그대로 씁니다. 이 PC에서 직접 바꾼 경우에만 고르세요. 모르는 변경이면 '취소'를 누른 뒤 '앱에 저장된 값으로 되돌리기'를 누르세요."
                    .to_owned(),
                "파일 값 사용",
            ),
            Confirm::WcDisconnectAll => (
                "모든 WalletConnect 세션 끊기",
                format!(
                    "WalletConnect 세션 {}개를 모두 끊을까요? 다시 쓰려면 dApp마다 QR이나 링크로 새로 연결해야 합니다.",
                    self.wc.sessions.len()
                ),
                "모두 끊기",
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
                    items.push(Item::Subtitle("지워지는 계정".to_owned()));
                    crate::ui::removed::removed_items(&[account], items)
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
            items.push(Item::Field("토큰".to_owned(), label));
            items.push(Item::Help("컨트랙트 주소".to_owned()));
            items.push(Item::Mono(yw_core::evm::display::format_address(&address)));
        }
        if kind == Confirm::RevealImported
            && let Some((label, address)) = self.imported_target_text()
        {
            items.push(Item::Field("계정".to_owned(), label));
            items.push(Item::Mono(address));
        }
        if kind == Confirm::Generate {
            items.push(Item::Row(vec![Ctl::check(
                ids::OVERWRITE_CHECK,
                "기존 주소 덮어쓰기",
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
        if kind == Confirm::YkAbandon {
            // Going on is the main choice; giving up discards the words (spec/10 §7.1-1).
            items.push(Item::Row(vec![
                Ctl::primary(ids::CONFIRM_NO, "계속 만들기"),
                Ctl::danger(ids::CONFIRM_YES, yes),
            ]));
            items.push(Item::CardEnd);
            return;
        }
        if kind == Confirm::YkPinLater {
            // Setting the PIN now is the main choice (back to the result and its PIN card).
            items.push(Item::Row(vec![
                Ctl::primary(ids::CONFIRM_NO, "지금 PIN 설정"),
                Ctl::button(ids::CONFIRM_YES, yes),
            ]));
            items.push(Item::CardEnd);
            return;
        }
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
        let again = match self.settings.rpc_template {
            RpcTemplate::Manual => "“입력”으로 다시 넣어야 합니다".to_owned(),
            template => format!(
                "“저장하고 RPC 주소 만들기”({} 자격 정보: {}) 또는 “입력”으로 다시 넣어야 합니다",
                if template == RpcTemplate::QuickNode {
                    "QuickNode"
                } else {
                    "알케미"
                },
                if self.template_stored() {
                    "설정됨"
                } else {
                    "없음"
                }
            ),
        };
        format!(
            "{} ({network})의 RPC 주소를 지웁니다. 저장된 주소는 다시 볼 수 없어, 다시 쓰려면 {again}. 이 네트워크에 확정 전 거래가 있으면 주소를 다시 넣을 때까지 상태 확인이 멈춥니다.",
            self.network_name(network)
        )
    }

    /// `TemplateDelete`'s text (2026-11-10).
    fn template_delete_text(&self) -> String {
        let what = if self.settings.rpc_template == RpcTemplate::Alchemy {
            "알케미 API 키"
        } else {
            "QuickNode 자격 정보(엔드포인트 이름·토큰)"
        };
        format!(
            "저장된 {what}를 지웁니다. 저장된 값은 다시 볼 수 없습니다. 이미 만든 네트워크별 RPC 주소는 그대로이고, 새 체인 주소를 만들 때 다시 넣어야 합니다."
        )
    }

    fn generate_text(&self) -> String {
        let (targets, skipped) = self.generation_plan();
        let mut text = "선택한 템플릿으로 아래 네트워크의 RPC 주소를 만듭니다. 이미 주소가 있는 네트워크는 '기존 주소 덮어쓰기'를 켰을 때만 바꿉니다.".to_owned();
        for network in targets {
            let existing = if self.apikeys.has(KeyName::Rpc(network)) {
                " — 기존 주소 있음"
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
