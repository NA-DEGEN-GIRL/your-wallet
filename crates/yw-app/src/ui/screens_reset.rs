//! S22 `지갑 초기화` (spec/04 §2.20), S23 `Chrome 확장 설치` (§2.21), their entry links, and
//! T-WAIT-STALLED (a wait past `app_reset::WAIT_TIMEOUT_MS`).

use crate::app::{App, AppMode};
use crate::app_extension::{CHROME_EXTENSIONS_URL, expected_dir, extension_dir};
use crate::app_reset::RESET_PHRASE;
use crate::store::reset::FOLDER_PREFIX;
use crate::ui::main_window::{Ctl, Item, Tone};
use yw_core::lang::Lang;

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
    /// S23 `탐색기에서 폴더 열기`.
    pub const EXT_OPEN_FOLDER: u16 = 13_422;
    /// S23 `확장 폴더 경로 복사`.
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

/// The fixed texts of S22, S23 and T-WAIT-STALLED (spec/04 §2.20–§2.21, spec/14).
pub mod text {
    yw_core::texts! {
        /// T-WAIT-STALLED.
        T_WAIT_STALLED = "30초가 지나도 불러오기가 끝나지 않았습니다. '다시 불러오기'를 누르거나, '잠금'을 누른 뒤 다시 잠금 해제해 보세요. 그래도 안 되면 앱을 종료했다가 다시 실행하세요. 계속되면 로그 폴더의 yw-app.log를 확인하세요. 처음부터 다시 쓰려면 복구 단어·원래 개인키, 또는 YubiKey(“YubiKey 연결하기 (복구 단어 없이)”)가 필요합니다 — 있다면 잠금 화면의 '지갑 초기화…'로 시작할 수 있습니다."
            / "Loading has not finished after 30 seconds. Press 'Reload', or press 'Lock' and unlock again. If that does not help, quit the app and start it again. If it keeps happening, check yw-app.log in the log folder. To start over you need your recovery words or original private keys, or a YubiKey (“Connect a YubiKey (no recovery words)”) — if you have them, you can start with 'Reset wallet…' on the lock screen.";
        /// T-META-FAILED: a meta load failed (other than a damaged file, E-VLT-006's overlay).
        T_META_FAILED = "계정 이름·주소록·연결한 사이트·보안 설정 기록이 담긴 meta 파일(meta.ywm)을 불러오지 못했습니다. 파일은 그대로 두었고, 불러오기에 성공할 때까지 이 파일에 아무것도 쓰지 않습니다. '다시 불러오기'를 누르거나, '잠금'을 누른 뒤 다시 잠금 해제해 보세요. 계속 실패하면 디스크 공간과 백신의 파일 차단을 확인하고 로그 폴더의 yw-app.log를 보세요. 그래도 안 되면 앱을 종료하고 데이터 폴더를 통째로 백업한 뒤 복구 안내(recovery-guide)를 따르세요."
            / "The meta file (meta.ywm), which holds account names, the address book, connected sites and the security settings record, could not be loaded. The file was left as it is, and nothing is written to it until a load succeeds. Press 'Reload', or press 'Lock' and unlock again. If it keeps failing, check the disk space and whether antivirus software blocks the file, and look at yw-app.log in the log folder. If that does not help, quit the app, back up the whole data folder and follow the recovery guide (recovery-guide).";
        /// T-RESET-INTRO (S22 danger banner).
        T_RESET_INTRO = "이 PC의 지갑 파일을 옮겨 두고 처음 화면으로 돌아갑니다. 자산은 블록체인에 그대로 있지만, 이 지갑을 다시 쓰려면 복구 단어(니모닉) — 여러 개면 각각 — 또는 원래 개인키가 있어야 합니다. YubiKey의 키는 카드에 남아 'YubiKey 연결하기 (복구 단어 없이)'로 다시 연결할 수 있습니다."
            / "Moves this PC's wallet files aside and returns to the first screen. Your assets stay on the blockchain, but to use this wallet again you need its recovery words (mnemonic) — each of them if there are several — or the original private keys. YubiKey keys stay on the card and can be connected again with 'Connect a YubiKey (no recovery words)'.";
        /// T-RESET-NOUNLOCK.
        T_RESET_NOUNLOCK = "비밀번호를 잊었어도 진행할 수 있습니다. 잠금 해제 없이 파일만 옮깁니다."
            / "You can go ahead even if you forgot the password. Only the files are moved, without unlocking.";
        /// T-RESET-MOVE.
        T_RESET_MOVE = "지갑 파일(vault.ywv와 이전 사본 .prev, meta.ywm, journal.ywj, 격리된 손상 파일)을 지우지 않고 데이터 폴더 안의 새 폴더로 옮깁니다. 옮긴 파일은 예전 비밀번호로 계속 열리며, 되돌리는 방법은 복구 안내(recovery-guide)와 새 폴더의 README-reset.txt에 있습니다."
            / "The wallet files (vault.ywv and its earlier copy .prev, meta.ywm, journal.ywj, quarantined damaged files) are moved, not deleted, to a new folder inside the data folder. The moved files still open with the old password; how to undo is in the recovery guide (recovery-guide) and in README-reset.txt in the new folder.";
        /// T-RESET-YUBIKEY.
        T_RESET_YUBIKEY = "YubiKey를 쓰는 지갑이었다면 YubiKey 안의 키는 그대로 남습니다. 초기화는 YubiKey를 지우거나 바꾸지 않습니다. 다시 쓰려면 복구 단어로 지갑을 가져온 뒤 YubiKey를 다시 등록하거나, 복구 단어 없이 첫 화면의 'YubiKey 연결하기 (복구 단어 없이)'로 카드의 키를 다시 연결하세요."
            / "If the wallet used a YubiKey, the keys on the YubiKey stay as they are. A reset does not erase or change the YubiKey. To use it again, import the wallet from the recovery words and enrol the YubiKey again, or connect the card's keys again without recovery words with 'Connect a YubiKey (no recovery words)' on the first screen.";
        /// T-RESET-SETTINGS.
        T_RESET_SETTINGS = "설정(settings.json)과 저장한 API 키·RPC 주소(apikeys.dpapi)는 기본으로 그대로 둡니다. 새 지갑에서도 같은 RPC 설정을 씁니다."
            / "The settings (settings.json) and the saved API keys and RPC addresses (apikeys.dpapi) stay by default. A new wallet uses the same RPC settings.";
        /// T-RESET-IN-FLIGHT.
        T_RESET_IN_FLIGHT = "보내는 중인 거래가 있습니다. 초기화해도 이미 보낸 거래는 블록체인에서 계속 처리되지만, 이 앱에서는 결과를 더 볼 수 없습니다. 끝난 뒤에 초기화하는 것을 권합니다."
            / "A transaction is being sent. Transactions already sent are still processed on the blockchain after a reset, but this app can no longer show their results. Resetting after they finish is recommended.";
        /// T-EXT-COMPAT (2026-11-08): where the compatibility modes are.
        T_EXT_COMPAT = "dApp의 지갑 목록에 Your Wallet이 없으면: Chrome 툴바의 Your Wallet 아이콘 → 'MetaMask처럼 보이기'(Solana는 'Phantom처럼 보이기', Bitcoin은 'UniSat처럼'·'Xverse처럼 보이기')를 고르고 dApp 탭을 새로고침하세요. 그때는 실제 MetaMask 등 같은 종류의 확장을 꺼 두세요."
            / "If Your Wallet is not in a dApp's wallet list: choose the Your Wallet icon in the Chrome toolbar → 'Appear as MetaMask' (Solana: 'Appear as Phantom', Bitcoin: 'Appear as UniSat' or 'Appear as Xverse') and refresh the dApp tab. Turn off the real MetaMask or other extensions of the same kind while doing so.";
        /// The short form of T-EXT-COMPAT (S13 empty state, settings).
        T_EXT_COMPAT_SHORT = "지갑 목록에 Your Wallet이 없는 dApp은 Chrome의 Your Wallet 아이콘에서 'MetaMask처럼 보이기'(Solana는 'Phantom처럼', Bitcoin은 'UniSat'·'Xverse처럼')를 고른 뒤 탭을 새로고침하세요."
            / "For a dApp whose wallet list lacks Your Wallet, choose 'Appear as MetaMask' (Solana: 'as Phantom', Bitcoin: 'as UniSat' or 'as Xverse') from the Your Wallet icon in Chrome, then refresh the tab.";
        /// S23 step 5 (2026-11-10).
        T_EXT_STEP_5 = "5. dApp 사이트를 열고(설치 전에 열어 둔 탭은 새로고침) “지갑 연결”에서 Your Wallet을 고르세요. 이 앱에 연결 창이 뜨면 설치가 끝난 것입니다 — 그 뒤로는 툴바의 Your Wallet 아이콘과 위 “연결 상태”에 연결됨이 보입니다. 그 전에는 아이콘이 “확인 불가”로 보이는 것이 정상입니다."
            / "5. Open a dApp site (refresh tabs opened before the install) and choose Your Wallet under “Connect wallet”. When the connect window appears in this app, the install is done — from then on the Your Wallet toolbar icon and “Connection status” above show connected. Before that, the icon showing “unknown” is normal.";
        /// T-EXT-MISSING.
        T_EXT_MISSING = "확장 폴더를 찾지 못했습니다. 설치 프로그램(install.cmd)을 다시 실행하면 앱 폴더 안에 extension 폴더가 만들어집니다."
            / "The extension folder was not found. Running the installer (install.cmd) again creates the extension folder inside the app folder.";
        /// S12 while the meta failed.
        ACCOUNTS_FAILED = "계정 목록을 불러오지 못했습니다. 위 안내를 보세요."
            / "The account list could not be loaded. See the notice above.";
        /// S12 while the meta loads.
        ACCOUNTS_LOADING = "계정을 불러오는 중…" / "Loading accounts…";
        /// T-META-FAILED / T-WAIT-STALLED button.
        RELOAD = "다시 불러오기" / "Reload";
        /// T-META-FAILED / T-WAIT-STALLED button.
        LOCK = "잠금" / "Lock";
        /// T-META-FAILED / T-WAIT-STALLED button.
        OPEN_LOG_FOLDER = "로그 폴더 열기" / "Open log folder";
        /// The reset entry link.
        RESET_LINK = "지갑 초기화…" / "Reset wallet…";
        /// S22 title.
        RESET_TITLE = "지갑 초기화" / "Reset wallet";
        /// S22 card while unlocked.
        BACKUP_STATUS = "백업 현황 — 이 지갑을 다시 열려면" / "Backup status — to open this wallet again";
        /// S22 card.
        WHAT_IT_DOES = "무엇을 하나요" / "What it does";
        /// S22 field.
        MOVE_TO = "옮길 곳" / "Moves to";
        /// S22 folder name placeholder after the prefix.
        STAMP_PLACEHOLDER = "<날짜시각(UTC)>" / "<date-time (UTC)>";
        /// S22 field.
        FILES_TO_MOVE = "옮길 파일" / "Files to move";
        /// S22 when there is nothing to move.
        NO_FILES = "(옮길 지갑 파일이 없습니다)" / "(no wallet files to move)";
        /// S22 with enrolled cards.
        YUBIKEY_ENROLLED = "이 지갑에는 YubiKey가 등록되어 있습니다. YubiKey와 그 PIN은 그대로 두세요."
            / "A YubiKey is enrolled in this wallet. Leave the YubiKey and its PIN as they are.";
        /// S22 check box.
        MOVE_SETTINGS = "설정과 API 키도 함께 옮기기 (앱 설정을 처음 상태로)"
            / "Also move the settings and API keys (app settings back to defaults)";
        /// S22 card.
        CONFIRM = "확인" / "Confirm";
        /// S22 instruction: {0} the phrase (with its Korean object particle in Korean).
        TYPE_PHRASE(1) = "계속하려면 아래 칸에 '{0}'를 입력한 뒤, 빨간 버튼을 2초 동안 누르고 있으세요."
            / "To continue, type '{0}' in the box below, then hold the red button for 2 seconds.";
        /// S22 field label.
        PHRASE_LABEL = "확인 문구" / "Confirmation";
        /// S22 hold area while the phrase is missing: {0} the phrase.
        HOLD_NEEDS_PHRASE(1) = "'{0}'를 입력하면 누를 수 있습니다" / "Type '{0}' to enable";
        /// S22 hold area while held.
        HOLD_KEEP = "계속 누르고 있으세요…" / "Keep holding…";
        /// S22 hold area.
        HOLD_TO_RESET = "2초 동안 눌러 초기화" / "Hold 2 seconds to reset";
        /// S22 button.
        CANCEL = "취소" / "Cancel";
        /// S23 back link.
        BACK = "← 돌아가기" / "← Back";
        /// S23 title.
        EXT_TITLE = "Chrome 확장 설치" / "Install the Chrome extension";
        /// S23 intro.
        EXT_INTRO = "dApp 사이트가 이 지갑을 쓰려면 Chrome에 Your Wallet 확장을 한 번 설치해야 합니다. 확장은 요청을 이 앱에 전달할 뿐이고, 승인은 언제나 이 앱의 창에서 합니다."
            / "For dApp sites to use this wallet, install the Your Wallet extension in Chrome once. The extension only passes requests to this app; approvals always happen in this app's windows.";
        /// S23 field.
        EXT_STATUS = "연결 상태" / "Connection status";
        /// S23 card.
        EXT_HOW = "설치 방법" / "How to install";
        /// S23 step 1.
        EXT_STEP_1 = "1. Chrome 주소창에 chrome://extensions 를 입력합니다 (아래 'chrome://extensions 주소 복사' 후 붙여넣기)."
            / "1. Enter chrome://extensions in the Chrome address bar (use 'Copy chrome://extensions' below, then paste).";
        /// S23 step 2.
        EXT_STEP_2 = "2. 오른쪽 위 '개발자 모드'를 켭니다." / "2. Turn on 'Developer mode' at the top right.";
        /// S23 when the pinned id cannot be read.
        EXT_ID_UNKNOWN = "(확인할 수 없음)" / "(cannot be checked)";
        /// S23 step 3: {0} the extension id.
        EXT_STEP_3(1) = "3. '압축해제된 확장 프로그램을 로드합니다'를 누르고 아래 확장 폴더를 선택합니다. 카드에 보이는 ID가 {0}인지 확인하세요(다르면 그 카드를 삭제하세요 — 앱이 연결을 받지 않습니다)."
            / "3. Press 'Load unpacked' and select the extension folder below. Check that the ID on the card is {0} (if it differs, remove that card — the app does not accept its connection).";
        /// S23 step 4.
        EXT_STEP_4 = "4. 퍼즐 모양 아이콘에서 Your Wallet을 고정해 두면 편합니다."
            / "4. Pinning Your Wallet from the puzzle-piece icon is convenient.";
        /// S23 update note.
        EXT_UPDATE = "앱을 업데이트한 뒤에는 chrome://extensions의 Your Wallet 카드에서 '새로고침'(↻)을 누르세요."
            / "After updating the app, press 'Reload' (↻) on the Your Wallet card in chrome://extensions.";
        /// S23 card.
        EXT_FOLDER = "확장 폴더" / "Extension folder";
        /// S23 field when the folder is missing.
        EXT_EXPECTED = "있어야 할 곳" / "Expected at";
        /// S23 button.
        EXT_COPY_PATH = "확장 폴더 경로 복사" / "Copy extension folder path";
        /// S23 button: {0} `chrome://extensions`.
        EXT_COPY_URL(1) = "{0} 주소 복사" / "Copy {0}";
        /// S23 link.
        EXT_OPEN_FOLDER = "탐색기에서 폴더 열기" / "Open folder in Explorer";
        /// S23 note.
        EXT_CHROME_BLOCKS = "Chrome은 다른 프로그램이 chrome:// 주소를 여는 것을 막습니다. 주소를 복사한 뒤 Chrome 주소창에 붙여넣으세요."
            / "Chrome blocks other programs from opening chrome:// addresses. Copy the address and paste it into the Chrome address bar.";
        /// S08/S13 link.
        EXT_LINK = "브라우저에서 쓰려면: Chrome 확장 설치 방법"
            / "To use it in the browser: how to install the Chrome extension";
    }
}

pub use text::{
    T_EXT_COMPAT, T_EXT_COMPAT_SHORT, T_EXT_MISSING, T_EXT_STEP_5, T_META_FAILED,
    T_RESET_IN_FLIGHT, T_RESET_INTRO, T_RESET_MOVE, T_RESET_NOUNLOCK, T_RESET_SETTINGS,
    T_RESET_YUBIKEY, T_WAIT_STALLED,
};

impl App {
    /// The `계정을 불러오는 중…` line of S12 (EVM, Solana) — or T-WAIT-STALLED once the wait is
    /// too long.
    pub(crate) fn accounts_loading(&self, items: &mut Vec<Item>) {
        if self.wait.meta_failed.is_some() {
            // T-META-FAILED with its buttons is at the top of the screen.
            items.push(Item::Muted(
                text::ACCOUNTS_FAILED.get(self.settings.language).to_owned(),
            ));
        } else if self.wait.stalled {
            self.wait_stalled(items);
        } else {
            items.push(Item::Muted(
                text::ACCOUNTS_LOADING
                    .get(self.settings.language)
                    .to_owned(),
            ));
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
        let lang = self.settings.language;
        let band = if unreadable {
            crate::app_sidecar::text::META_CLOSED.get(lang)
        } else {
            T_META_FAILED.get(lang)
        };
        items.push(Item::Banner(
            format!("{band} ({})", code.code()),
            Tone::Danger,
        ));
        let mut row = vec![Ctl::primary(ids::WAIT_RETRY, text::RELOAD.get(lang))];
        // S10's toolbar has `잠금` already.
        if self.screen != crate::app::Screen::Main {
            row.push(Ctl::button(
                crate::ui::screens::ids::LOCK,
                text::LOCK.get(lang),
            ));
        }
        row.push(Ctl::button(
            crate::ui::screens::ids::OPEN_LOG_FOLDER,
            text::OPEN_LOG_FOLDER.get(lang),
        ));
        items.push(Item::Row(row));
    }

    /// T-WAIT-STALLED with its next steps.
    pub(crate) fn wait_stalled(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Banner(
            T_WAIT_STALLED.get(lang).to_owned(),
            Tone::Danger,
        ));
        let mut row = Vec::new();
        if matches!(self.mode, AppMode::BackupPending | AppMode::Unlocked { .. }) {
            row.push(Ctl::primary(ids::WAIT_RETRY, text::RELOAD.get(lang)));
        }
        row.push(Ctl::button(
            crate::ui::screens::ids::LOCK,
            text::LOCK.get(lang),
        ));
        row.push(Ctl::button(
            crate::ui::screens::ids::OPEN_LOG_FOLDER,
            text::OPEN_LOG_FOLDER.get(lang),
        ));
        row.push(Ctl::link(ids::RESET_OPEN, text::RESET_LINK.get(lang)));
        items.push(Item::Row(row));
    }

    /// The `지갑 초기화…` entry link with its one-line help (S07, S09, S04).
    pub(crate) fn reset_link(lang: Lang, items: &mut Vec<Item>, help: &str) {
        items.push(Item::Gap(8));
        items.push(Item::Help(help.to_owned()));
        items.push(Item::Row(vec![Ctl::link(
            ids::RESET_OPEN,
            text::RESET_LINK.get(lang),
        )]));
    }

    /// S22.
    pub(crate) fn reset_screen(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Title(text::RESET_TITLE.get(lang).to_owned()));
        // Unlocked: what brings this wallet back, before anything is moved (2026-11-10; the
        // lines of settings → 보안).
        if matches!(self.mode, crate::app::AppMode::Unlocked { .. }) {
            let lines = self.backup_status_all();
            if !lines.is_empty() {
                items.push(Item::CardStart(Some(
                    text::BACKUP_STATUS.get(lang).to_owned(),
                )));
                for line in lines {
                    items.push(Item::Text(line));
                }
                items.push(Item::CardEnd);
            }
        }
        items.push(Item::Banner(
            T_RESET_INTRO.get(lang).to_owned(),
            Tone::HighRisk,
        ));
        if self.sends_in_flight() {
            items.push(Item::Banner(
                T_RESET_IN_FLIGHT.get(lang).to_owned(),
                Tone::Warn,
            ));
        }
        items.push(Item::CardStart(Some(
            text::WHAT_IT_DOES.get(lang).to_owned(),
        )));
        items.push(Item::Text(T_RESET_NOUNLOCK.get(lang).to_owned()));
        items.push(Item::Text(T_RESET_MOVE.get(lang).to_owned()));
        items.push(Item::Field(
            text::MOVE_TO.get(lang).to_owned(),
            format!(
                "{}\\{FOLDER_PREFIX}{}",
                self.paths.data.display(),
                text::STAMP_PLACEHOLDER.get(lang)
            ),
        ));
        let files = if self.reset.files.is_empty() {
            text::NO_FILES.get(lang).to_owned()
        } else {
            self.reset.files.join(", ")
        };
        items.push(Item::Field(text::FILES_TO_MOVE.get(lang).to_owned(), files));
        let yubikey = !self.card.records.is_empty();
        items.push(Item::Help(T_RESET_YUBIKEY.get(lang).to_owned()));
        if yubikey {
            items.push(Item::Banner(
                text::YUBIKEY_ENROLLED.get(lang).to_owned(),
                Tone::Info,
            ));
        }
        items.push(Item::Help(T_RESET_SETTINGS.get(lang).to_owned()));
        items.push(Item::Row(vec![Ctl::check(
            ids::RESET_SETTINGS_CHECK,
            text::MOVE_SETTINGS.get(lang),
            self.reset.include_settings,
        )]));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(text::CONFIRM.get(lang).to_owned())));
        let phrase = RESET_PHRASE.get(lang);
        items.push(Item::Text(text::TYPE_PHRASE.fill(lang, [phrase])));
        items.push(Item::LabeledRow(
            text::PHRASE_LABEL.get(lang).to_owned(),
            vec![Ctl::edit(ids::RESET_PHRASE, "", 160, false, 16)],
        ));
        let label = if !self.reset.phrase_ok {
            text::HOLD_NEEDS_PHRASE.fill(lang, [phrase])
        } else if self.reset.holding.is_some() {
            text::HOLD_KEEP.get(lang).to_owned()
        } else {
            text::HOLD_TO_RESET.get(lang).to_owned()
        };
        items.push(Item::Hold {
            id: ids::RESET_HOLD,
            label,
            progress: self.reset.progress,
            enabled: self.reset.phrase_ok,
        });
        items.push(Item::Row(vec![Ctl::button(
            ids::RESET_CANCEL,
            text::CANCEL.get(lang),
        )]));
        items.push(Item::CardEnd);
    }

    /// S23.
    pub(crate) fn extension_screen(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Row(vec![Ctl::link(
            ids::EXT_BACK,
            text::BACK.get(lang),
        )]));
        items.push(Item::Title(text::EXT_TITLE.get(lang).to_owned()));
        items.push(Item::Help(text::EXT_INTRO.get(lang).to_owned()));
        let status = self.extension_status();
        items.push(Item::Field(
            text::EXT_STATUS.get(lang).to_owned(),
            status.text_in(lang).to_owned(),
        ));
        items.push(Item::CardStart(Some(text::EXT_HOW.get(lang).to_owned())));
        items.push(Item::Text(text::EXT_STEP_1.get(lang).to_owned()));
        items.push(Item::Text(text::EXT_STEP_2.get(lang).to_owned()));
        // The id the app accepts (`extension-id.txt`, compiled in, spec/05 §2.3).
        let id = crate::browser::pinned_extension_id().unwrap_or(text::EXT_ID_UNKNOWN.get(lang));
        items.push(Item::Text(text::EXT_STEP_3.fill(lang, [id])));
        items.push(Item::Text(text::EXT_STEP_4.get(lang).to_owned()));
        items.push(Item::Text(T_EXT_STEP_5.get(lang).to_owned()));
        items.push(Item::Help(T_EXT_COMPAT.get(lang).to_owned()));
        items.push(Item::Help(text::EXT_UPDATE.get(lang).to_owned()));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(text::EXT_FOLDER.get(lang).to_owned())));
        let found = extension_dir();
        if let Some(dir) = &found {
            items.push(Item::Mono(dir.display().to_string()));
        } else {
            items.push(Item::Banner(T_EXT_MISSING.get(lang).to_owned(), Tone::Warn));
            if let Some(expected) = expected_dir() {
                items.push(Item::Field(
                    text::EXT_EXPECTED.get(lang).to_owned(),
                    expected.display().to_string(),
                ));
            }
        }
        // The folder picker takes the copied path (2026-11-10): copying is the main step.
        items.push(Item::Row(vec![
            Ctl::primary(ids::EXT_COPY_PATH, text::EXT_COPY_PATH.get(lang))
                .enabled(found.is_some()),
            Ctl::button(
                ids::EXT_COPY_URL,
                &text::EXT_COPY_URL.fill(lang, [CHROME_EXTENSIONS_URL]),
            ),
            Ctl::link(ids::EXT_OPEN_FOLDER, text::EXT_OPEN_FOLDER.get(lang))
                .enabled(found.is_some()),
        ]));
        items.push(Item::Help(text::EXT_CHROME_BLOCKS.get(lang).to_owned()));
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
                text::EXT_LINK.get(self.settings.language),
            )]));
        }
    }
}

#[cfg(test)]
mod tests {
    use yw_core::lang::{Lang, has_hangul};

    use crate::apikeys::ApiKeys;
    use crate::app::{App, Paths};
    use crate::settings::Settings;
    use crate::ui::main_window::Item;

    /// Every fixed text of `items` (titles, lines, field labels, control labels); field values
    /// are data (paths, file names) and left out.
    fn fixed_texts(items: &[Item]) -> Vec<String> {
        let mut out = Vec::new();
        for item in items {
            match item {
                Item::Title(text)
                | Item::Text(text)
                | Item::Muted(text)
                | Item::Help(text)
                | Item::Banner(text, _)
                | Item::CardStart(Some(text)) => out.push(text.clone()),
                Item::Field(label, _) | Item::Hold { label, .. } => out.push(label.clone()),
                Item::LabeledRow(label, ctls) => {
                    out.push(label.clone());
                    out.extend(ctls.iter().map(|ctl| ctl.text.clone()));
                }
                Item::Row(ctls) => out.extend(ctls.iter().map(|ctl| ctl.text.clone())),
                _ => {}
            }
        }
        out
    }

    fn app(lang: Lang) -> (App, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "yw-reset-screen-{}-{}",
            std::process::id(),
            yw_win::time::monotonic_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let settings = Settings {
            language: lang,
            ..Settings::default()
        };
        let app = App::new(
            Paths {
                data: dir.clone(),
                logs: dir.join("logs"),
            },
            true,
            settings,
            ApiKeys::default(),
        );
        (app, dir)
    }

    /// S22, S23 and T-WAIT-STALLED in English have no Hangul (spec/14); the confirmation phrase
    /// is the language's own.
    #[test]
    fn english_reset_and_extension_screens() {
        let (mut app, dir) = app(Lang::En);
        let mut items = Vec::new();
        app.reset_screen(&mut items);
        app.reset.phrase_ok = true;
        app.reset_screen(&mut items);
        app.extension_screen(&mut items);
        app.extension_link(&mut items);
        app.wait_stalled(&mut items);
        App::reset_link(Lang::En, &mut items, "help");
        let texts = fixed_texts(&items);
        assert!(texts.iter().any(|text| text == "Reset wallet"), "{texts:?}");
        for text in &texts {
            assert!(!has_hangul(text), "{text}");
        }
        assert!(crate::app_reset::phrase_matches(Lang::En, " reset "));
        assert!(!crate::app_reset::phrase_matches(Lang::En, "초기화"));
        assert!(crate::app_reset::phrase_matches(Lang::Ko, "초기화"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
