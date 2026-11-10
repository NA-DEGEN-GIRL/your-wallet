//! S22 `지갑 초기화` (spec/04 §2.20), S23 `Chrome 확장 설치` (§2.21), their entry links, and
//! T-WAIT-STALLED (a wait past `app_reset::WAIT_TIMEOUT_MS`).

use crate::app::{App, AppMode};
use crate::app_extension::{CHROME_EXTENSIONS_URL, expected_dir, extension_dir};
use crate::app_reset::RESET_PHRASE;
use crate::store::reset::FOLDER_PREFIX;
use crate::ui::main_window::{Ctl, Item, Tone};

/// Command ids (block 13,400–13,449, `ui::command_ids`).
pub mod ids {
    /// `지갑 초기화…` (S07, S09, S04, S01 with T-LEFTOVER, settings → 보안, T-WAIT-STALLED).
    pub const RESET_OPEN: u16 = 13_400;
    /// S22 confirmation field.
    pub const RESET_PHRASE: u16 = 13_401;
    /// S22 `설정과 API 키도 함께 옮기기`.
    pub const RESET_SETTINGS_CHECK: u16 = 13_402;
    /// S22 hold area (2 s).
    pub const RESET_HOLD: u16 = 13_403;
    /// S22 `취소`.
    pub const RESET_CANCEL: u16 = 13_404;
    /// T-WAIT-STALLED `다시 불러오기`.
    pub const WAIT_RETRY: u16 = 13_410;
    /// `Chrome 확장 설치` (settings, S08, S13).
    pub const EXT_OPEN: u16 = 13_420;
    /// S23 `← 돌아가기`.
    pub const EXT_BACK: u16 = 13_421;
    /// S23 `폴더 열기`.
    pub const EXT_OPEN_FOLDER: u16 = 13_422;
    /// S23 `경로 복사`.
    pub const EXT_COPY_PATH: u16 = 13_423;
    /// S23 `chrome://extensions 주소 복사`.
    pub const EXT_COPY_URL: u16 = 13_424;

    /// Every fixed id of this module.
    pub const FIXED: &[u16] = &[
        RESET_OPEN,
        RESET_PHRASE,
        RESET_SETTINGS_CHECK,
        RESET_HOLD,
        RESET_CANCEL,
        WAIT_RETRY,
        EXT_OPEN,
        EXT_BACK,
        EXT_OPEN_FOLDER,
        EXT_COPY_PATH,
        EXT_COPY_URL,
    ];
}

/// T-WAIT-STALLED.
pub const T_WAIT_STALLED: &str = "30초가 지나도 불러오기가 끝나지 않았습니다. '다시 불러오기'를 누르거나, '잠금'을 누른 뒤 다시 잠금 해제해 보세요. 그래도 안 되면 앱을 종료했다가 다시 실행하세요. 계속되면 로그 폴더의 yw-app.log를 확인하고, 복구 단어(또는 원래 개인키)가 있다면 잠금 화면의 '지갑 초기화…'로 처음부터 시작할 수 있습니다.";
/// T-META-FAILED: a meta load failed (other than a damaged file, E-VLT-006's overlay).
pub const T_META_FAILED: &str = "계정 이름·주소록·연결한 사이트·보안 설정 기록이 담긴 meta 파일(meta.ywm)을 불러오지 못했습니다. 파일은 그대로 두었고, 불러오기에 성공할 때까지 이 파일에 아무것도 쓰지 않습니다. '다시 불러오기'를 누르거나, '잠금'을 누른 뒤 다시 잠금 해제해 보세요. 계속 실패하면 디스크 공간과 백신의 파일 차단을 확인하고 로그 폴더의 yw-app.log를 보세요. 그래도 안 되면 앱을 종료하고 데이터 폴더를 통째로 백업한 뒤 복구 안내(recovery-guide)를 따르세요.";
/// T-RESET-INTRO (S22 danger banner).
pub const T_RESET_INTRO: &str = "이 PC의 지갑 파일을 옮겨 두고 처음 화면으로 돌아갑니다. 자산은 블록체인에 그대로 있지만, 이 지갑을 다시 쓰려면 복구 단어(니모닉) — 여러 개면 각각 — 또는 원래 개인키가 있어야 합니다. YubiKey의 키는 카드에 남아 'YubiKey 연결하기 (복구 단어 없이)'로 다시 연결할 수 있습니다.";
/// T-RESET-NOUNLOCK.
pub const T_RESET_NOUNLOCK: &str =
    "비밀번호를 잊었어도 진행할 수 있습니다. 잠금 해제 없이 파일만 옮깁니다.";
/// T-RESET-MOVE.
pub const T_RESET_MOVE: &str = "지갑 파일(vault.ywv와 이전 사본 .prev, meta.ywm, journal.ywj, 격리된 손상 파일)을 지우지 않고 데이터 폴더 안의 새 폴더로 옮깁니다. 옮긴 파일은 예전 비밀번호로 계속 열리며, 되돌리는 방법은 복구 안내(recovery-guide)와 새 폴더의 README-reset.txt에 있습니다.";
/// T-RESET-YUBIKEY.
pub const T_RESET_YUBIKEY: &str = "YubiKey를 쓰는 지갑이었다면 YubiKey 안의 키는 그대로 남습니다. 초기화는 YubiKey를 지우거나 바꾸지 않습니다. 다시 쓰려면 복구 단어로 지갑을 가져온 뒤 YubiKey를 다시 등록하거나, 복구 단어 없이 첫 화면의 'YubiKey 연결하기 (복구 단어 없이)'로 카드의 키를 다시 연결하세요.";
/// T-RESET-SETTINGS.
pub const T_RESET_SETTINGS: &str = "설정(settings.json)과 저장한 API 키·RPC 주소(apikeys.dpapi)는 기본으로 그대로 둡니다. 새 지갑에서도 같은 RPC 설정을 씁니다.";
/// T-RESET-IN-FLIGHT.
pub const T_RESET_IN_FLIGHT: &str = "보내는 중인 거래가 있습니다. 초기화해도 이미 보낸 거래는 블록체인에서 계속 처리되지만, 이 앱에서는 결과를 더 볼 수 없습니다. 끝난 뒤에 초기화하는 것을 권합니다.";
/// T-EXT-COMPAT (2026-11-08): where the compatibility modes are, for a dApp whose wallet list
/// shows only `MetaMask`/`Phantom`/… (S23, S13 empty state, settings → 브라우저 확장).
pub const T_EXT_COMPAT: &str = "dApp의 지갑 목록에 Your Wallet이 없으면: Chrome 툴바의 Your Wallet 아이콘 → 'MetaMask처럼 보이기'(Solana는 'Phantom처럼 보이기', Bitcoin은 'UniSat처럼'·'Xverse처럼 보이기')를 고르고 dApp 탭을 새로고침하세요. 그때는 실제 MetaMask 등 같은 종류의 확장을 꺼 두세요.";
/// The short form of T-EXT-COMPAT (S13 empty state, settings).
pub const T_EXT_COMPAT_SHORT: &str = "지갑 목록에 Your Wallet이 없는 dApp은 Chrome의 Your Wallet 아이콘에서 'MetaMask처럼 보이기'(Solana는 'Phantom처럼', Bitcoin은 'UniSat'·'Xverse처럼')를 고른 뒤 탭을 새로고침하세요.";
/// T-EXT-MISSING.
pub const T_EXT_MISSING: &str = "확장 폴더를 찾지 못했습니다. 설치 프로그램(install.cmd)을 다시 실행하면 앱 폴더 안에 extension 폴더가 만들어집니다.";

impl App {
    /// The `계정을 불러오는 중…` line of S12 (EVM, Solana) — or T-WAIT-STALLED once the wait is
    /// too long.
    pub(crate) fn accounts_loading(&self, items: &mut Vec<Item>) {
        if self.wait.meta_failed.is_some() {
            // T-META-FAILED with its buttons is at the top of the screen.
            items.push(Item::Muted(
                "계정 목록을 불러오지 못했습니다. 위 안내를 보세요.".to_owned(),
            ));
        } else if self.wait.stalled {
            self.wait_stalled(items);
        } else {
            items.push(Item::Muted("계정을 불러오는 중…".to_owned()));
        }
    }

    /// T-META-FAILED with its next steps, on every screen of an open session while no meta
    /// could be loaded.
    pub(crate) fn meta_failed_items(&self, items: &mut Vec<Item>) {
        let Some(code) = self.wait.meta_failed else {
            return;
        };
        if !matches!(self.mode, AppMode::BackupPending | AppMode::Unlocked { .. }) {
            return;
        }
        // E-VLT-006: the file did not open or this build cannot read it. Its own overlay (and the
        // choice being carried out) says so; once closed, this form says nothing was changed.
        let unreadable = code == crate::errors::ErrorCode::Vlt006;
        if unreadable
            && matches!(
                self.screen,
                crate::app::Screen::Confirm(crate::app::Confirm::SidecarCorrupt)
                    | crate::app::Screen::Processing(_)
            )
        {
            return;
        }
        let text = if unreadable {
            crate::app_sidecar::T_META_CLOSED
        } else {
            T_META_FAILED
        };
        items.push(Item::Banner(
            format!("{text} ({})", code.code()),
            Tone::Danger,
        ));
        let mut row = vec![Ctl::primary(ids::WAIT_RETRY, "다시 불러오기")];
        // S10's toolbar has `잠금` already.
        if self.screen != crate::app::Screen::Main {
            row.push(Ctl::button(crate::ui::screens::ids::LOCK, "잠금"));
        }
        row.push(Ctl::button(
            crate::ui::screens::ids::OPEN_LOG_FOLDER,
            "로그 폴더 열기",
        ));
        items.push(Item::Row(row));
    }

    /// T-WAIT-STALLED with its next steps.
    pub(crate) fn wait_stalled(&self, items: &mut Vec<Item>) {
        items.push(Item::Banner(T_WAIT_STALLED.to_owned(), Tone::Danger));
        let mut row = Vec::new();
        if matches!(self.mode, AppMode::BackupPending | AppMode::Unlocked { .. }) {
            row.push(Ctl::primary(ids::WAIT_RETRY, "다시 불러오기"));
        }
        row.push(Ctl::button(crate::ui::screens::ids::LOCK, "잠금"));
        row.push(Ctl::button(
            crate::ui::screens::ids::OPEN_LOG_FOLDER,
            "로그 폴더 열기",
        ));
        row.push(Ctl::link(ids::RESET_OPEN, "지갑 초기화…"));
        items.push(Item::Row(row));
    }

    /// The `지갑 초기화…` entry link with its one-line help (S07, S09, S04).
    pub(crate) fn reset_link(items: &mut Vec<Item>, help: &str) {
        items.push(Item::Gap(8));
        items.push(Item::Help(help.to_owned()));
        items.push(Item::Row(vec![Ctl::link(ids::RESET_OPEN, "지갑 초기화…")]));
    }

    /// S22.
    pub(crate) fn reset_screen(&self, items: &mut Vec<Item>) {
        items.push(Item::Title("지갑 초기화".to_owned()));
        items.push(Item::Banner(T_RESET_INTRO.to_owned(), Tone::HighRisk));
        if self.sends_in_flight() {
            items.push(Item::Banner(T_RESET_IN_FLIGHT.to_owned(), Tone::Warn));
        }
        items.push(Item::CardStart(Some("무엇을 하나요".to_owned())));
        items.push(Item::Text(T_RESET_NOUNLOCK.to_owned()));
        items.push(Item::Text(T_RESET_MOVE.to_owned()));
        items.push(Item::Field(
            "옮길 곳".to_owned(),
            format!(
                "{}\\{FOLDER_PREFIX}<날짜시각(UTC)>",
                self.paths.data.display()
            ),
        ));
        let files = if self.reset.files.is_empty() {
            "(옮길 지갑 파일이 없습니다)".to_owned()
        } else {
            self.reset.files.join(", ")
        };
        items.push(Item::Field("옮길 파일".to_owned(), files));
        let yubikey = !self.card.records.is_empty();
        items.push(Item::Help(T_RESET_YUBIKEY.to_owned()));
        if yubikey {
            items.push(Item::Banner(
                "이 지갑에는 YubiKey가 등록되어 있습니다. YubiKey와 그 PIN은 그대로 두세요."
                    .to_owned(),
                Tone::Info,
            ));
        }
        items.push(Item::Help(T_RESET_SETTINGS.to_owned()));
        items.push(Item::Row(vec![Ctl::check(
            ids::RESET_SETTINGS_CHECK,
            "설정과 API 키도 함께 옮기기 (앱 설정을 처음 상태로)",
            self.reset.include_settings,
        )]));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("확인".to_owned())));
        items.push(Item::Text(format!(
            "계속하려면 아래 칸에 '{RESET_PHRASE}'를 입력한 뒤, 빨간 버튼을 2초 동안 누르고 있으세요."
        )));
        items.push(Item::LabeledRow(
            "확인 문구".to_owned(),
            vec![Ctl::edit(ids::RESET_PHRASE, "", 160, false, 16)],
        ));
        let label = if !self.reset.phrase_ok {
            format!("'{RESET_PHRASE}'를 입력하면 누를 수 있습니다")
        } else if self.reset.holding.is_some() {
            "계속 누르고 있으세요…".to_owned()
        } else {
            "2초 동안 눌러 초기화".to_owned()
        };
        items.push(Item::Hold {
            id: ids::RESET_HOLD,
            label,
            progress: self.reset.progress,
            enabled: self.reset.phrase_ok,
        });
        items.push(Item::Row(vec![Ctl::button(ids::RESET_CANCEL, "취소")]));
        items.push(Item::CardEnd);
    }

    /// S23.
    pub(crate) fn extension_screen(&self, items: &mut Vec<Item>) {
        items.push(Item::Row(vec![Ctl::link(ids::EXT_BACK, "← 돌아가기")]));
        items.push(Item::Title("Chrome 확장 설치".to_owned()));
        items.push(Item::Help(
            "dApp 사이트가 이 지갑을 쓰려면 Chrome에 Your Wallet 확장을 한 번 설치해야 합니다. 확장은 요청을 이 앱에 전달할 뿐이고, 승인은 언제나 이 앱의 창에서 합니다."
                .to_owned(),
        ));
        let status = self.extension_status();
        items.push(Item::Field(
            "연결 상태".to_owned(),
            status.text().to_owned(),
        ));
        items.push(Item::CardStart(Some("설치 방법".to_owned())));
        for line in [
            "1. Chrome 주소창에 chrome://extensions 를 입력합니다 (아래 '주소 복사' 후 붙여넣기).",
            "2. 오른쪽 위 '개발자 모드'를 켭니다.",
            "3. '압축해제된 확장 프로그램을 로드합니다'를 누르고 아래 확장 폴더를 선택합니다.",
            "4. 퍼즐 모양 아이콘에서 Your Wallet을 고정해 두면 편합니다.",
            "5. Chrome 툴바의 Your Wallet 아이콘을 눌러 '연결됨'이 보이면 끝입니다 (위 '연결 상태'도 바뀝니다).",
        ] {
            items.push(Item::Text(line.to_owned()));
        }
        items.push(Item::Help(T_EXT_COMPAT.to_owned()));
        items.push(Item::Help(
            "앱을 업데이트한 뒤에는 chrome://extensions의 Your Wallet 카드에서 '새로고침'(↻)을 누르세요."
                .to_owned(),
        ));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("확장 폴더".to_owned())));
        let found = extension_dir();
        if let Some(dir) = &found {
            items.push(Item::Mono(dir.display().to_string()));
        } else {
            items.push(Item::Banner(T_EXT_MISSING.to_owned(), Tone::Warn));
            if let Some(expected) = expected_dir() {
                items.push(Item::Field(
                    "있어야 할 곳".to_owned(),
                    expected.display().to_string(),
                ));
            }
        }
        items.push(Item::Row(vec![
            Ctl::primary(ids::EXT_OPEN_FOLDER, "폴더 열기").enabled(found.is_some()),
            Ctl::button(ids::EXT_COPY_PATH, "경로 복사").enabled(found.is_some()),
            Ctl::button(
                ids::EXT_COPY_URL,
                &format!("{CHROME_EXTENSIONS_URL} 주소 복사"),
            ),
        ]));
        items.push(Item::Help(
            "Chrome은 다른 프로그램이 chrome:// 주소를 여는 것을 막습니다. 주소를 복사한 뒤 Chrome 주소창에 붙여넣으세요."
                .to_owned(),
        ));
        items.push(Item::CardEnd);
    }

    /// The `Chrome 확장 설치` link of S08 and S13 while no extension has connected.
    pub(crate) fn extension_link(&self, items: &mut Vec<Item>) {
        use crate::app_extension::ExtensionStatus;
        if matches!(
            self.extension_status(),
            ExtensionStatus::Never | ExtensionStatus::Unknown
        ) {
            items.push(Item::Row(vec![Ctl::link(
                ids::EXT_OPEN,
                "브라우저에서 쓰려면: Chrome 확장 설치 방법",
            )]));
        }
    }
}
