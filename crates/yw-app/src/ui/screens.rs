//! Screen contents S01–S15 (spec/04 §2, M3 subset) as [`Item`] lists, and the command ids of
//! their controls. Fixed sentences follow spec/04 §2.16; nothing from RPC or the OS is shown.

use core::fmt::Write as _;

use yw_core::evm::chain::SEPOLIA;

use crate::apikeys::{KeyName, mask_url};
use crate::app::{App, AppMode, Confirm, Screen, SettingsSection};
use crate::errors::ErrorCode;
use crate::meta::EvmAccountPref;
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
    /// S02 다음.
    pub const CREATE_NEXT: u16 = 110;
    /// S02/S05 취소.
    pub const INTRO_CANCEL: u16 = 111;
    /// S05 다음.
    pub const IMPORT_NEXT: u16 = 120;
    /// S06 맞습니다.
    pub const IMPORT_CORRECT: u16 = 130;
    /// S06 다릅니다.
    pub const IMPORT_WRONG: u16 = 131;
    /// S07 잠금 해제.
    pub const UNLOCK: u16 = 140;
    /// S04 니모닉 보고 백업 확인.
    pub const BACKUP_CHECK: u16 = 150;
    /// 잠금.
    pub const LOCK: u16 = 151;
    /// S08 RPC 엔드포인트 설정.
    pub const DONE_RPC: u16 = 160;
    /// S08 계속 / 나중에.
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
    /// ← 메인.
    pub const BACK_MAIN: u16 = 202;
    /// 배너 닫기.
    pub const DISMISS_BANNERS: u16 = 203;
    /// Network radios base.
    pub const NETWORK_BASE: u16 = 210;
    /// Network radios span.
    pub const NETWORK_SPAN: u16 = 40;
    /// 계정 추가.
    pub const ADD_ACCOUNT: u16 = 260;
    /// 개인키 가져오기.
    pub const IMPORT_KEY: u16 = 261;
    /// Account selection base.
    pub const ACCOUNT_BASE: u16 = 300;
    /// Account selection span.
    pub const ACCOUNT_SPAN: u16 = 120;
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
    /// 니모닉 보기.
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
    /// URL rows base (4 ids per row: 교체, 테스트, 삭제).
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
}

fn header(app: &App, items: &mut Vec<Item>) {
    for banner in &app.banners {
        items.push(Item::Banner(banner.text.clone(), Tone::Danger));
    }
    if let Some(info) = &app.info {
        items.push(Item::Banner(info.clone(), Tone::Info));
    }
    if !app.banners.is_empty() || app.info.is_some() {
        items.push(Item::Row(vec![Ctl::button(
            ids::DISMISS_BANNERS,
            "알림 닫기",
        )]));
    }
}

/// The items of the current screen.
impl App {
    /// Builds the current screen.
    #[must_use]
    #[expect(clippy::too_many_lines, reason = "one arm per screen")]
    pub fn items(&self) -> Vec<Item> {
        let mut items = Vec::new();
        header(self, &mut items);
        match &self.screen {
            Screen::Starting => items.push(Item::Muted("지갑을 불러오는 중…".to_owned())),
            Screen::FirstRun => self.first_run(&mut items),
            Screen::CreateIntro => {
                items.push(Item::Title("새 지갑 만들기".to_owned()));
                items.push(Item::Text("다음 화면에 24단어 니모닉과 첫 주소가 표시됩니다. 종이(또는 금속)에만 적고 사진·클라우드·메신저에 남기지 마세요. 화면 공유·녹화를 끄고 주변에 사람이나 카메라가 없는지 확인하세요.".to_owned()));
                items.push(Item::Row(vec![
                    Ctl::button(ids::CREATE_NEXT, "다음"),
                    Ctl::button(ids::INTRO_CANCEL, "취소"),
                ]));
            }
            Screen::Processing(text) => {
                items.push(Item::Title("처리 중".to_owned()));
                items.push(Item::Text((*text).to_owned()));
            }
            Screen::BackupPending => {
                items.push(Item::Title("백업 확인 필요".to_owned()));
                items.push(Item::Banner(
                    "백업 확인이 끝나지 않았습니다. 확인 전에는 보내기·서명·dApp 승인을 쓸 수 없습니다.".to_owned(),
                    Tone::Warn,
                ));
                items.push(Item::Row(vec![
                    Ctl::button(ids::BACKUP_CHECK, "니모닉 보고 백업 확인"),
                    Ctl::button(ids::LOCK, "잠금"),
                ]));
                items.push(Item::Row(vec![Ctl::button(
                    crate::ui::screens_evm::ids::RECEIVE_OPEN,
                    "받기",
                )]));
            }
            Screen::ImportIntro => {
                items.push(Item::Title("기존 지갑 가져오기".to_owned()));
                items.push(Item::Text("12·15·18·21·24단어 BIP39 영어 니모닉을 가져옵니다. EVM 개인키는 지갑을 만든 뒤 메인 화면의 '개인키 가져오기'에서 가져옵니다.".to_owned()));
                items.push(Item::Row(vec![
                    Ctl::button(ids::IMPORT_NEXT, "다음"),
                    Ctl::button(ids::INTRO_CANCEL, "취소"),
                ]));
            }
            Screen::ImportAddress(address) => {
                items.push(Item::Title("첫 주소 확인".to_owned()));
                items.push(Item::Text("가져온 지갑의 첫 주소입니다. 이전 지갑에서 쓰던 주소와 전체가 같은지 확인하세요.".to_owned()));
                items.push(Item::Mono(address.clone()));
                items.push(Item::Row(vec![
                    Ctl::button(ids::IMPORT_CORRECT, "맞습니다"),
                    Ctl::button(ids::IMPORT_WRONG, "다릅니다"),
                ]));
            }
            Screen::Locked => {
                items.push(Item::Title("Your Wallet".to_owned()));
                items.push(Item::Text("지갑이 잠겨 있습니다.".to_owned()));
                if let Some(pending) = self.unlock_pending_text() {
                    items.push(Item::Banner(pending, Tone::Info));
                }
                items.push(Item::Row(vec![Ctl::button(ids::UNLOCK, "잠금 해제")]));
            }
            Screen::PassMismatch => {
                items.push(Item::Title("passphrase 확인".to_owned()));
                items.push(Item::Banner(
                    "passphrase가 다를 수 있습니다. 다른 passphrase는 다른(빈) 지갑을 엽니다."
                        .to_owned(),
                    Tone::Warn,
                ));
                items.push(Item::Row(vec![Ctl::check(
                    ids::MISMATCH_CHECK,
                    "다른 passphrase는 다른(빈) 지갑을 엽니다",
                    self.mismatch_checked,
                )]));
                items.push(Item::Row(vec![
                    Ctl::button(ids::MISMATCH_RETRY, "다시 입력"),
                    Ctl::button(ids::MISMATCH_CONTINUE, "이 passphrase로 계속")
                        .enabled(self.mismatch_checked),
                ]));
            }
            Screen::Done => {
                items.push(Item::Title("완료".to_owned()));
                items.push(Item::Text("지갑을 쓸 수 있습니다.".to_owned()));
                if self.apikeys.endpoints().is_empty() {
                    items.push(Item::Text("저장된 RPC 엔드포인트가 없습니다. 잔액 조회와 보내기에는 네트워크별 RPC URL이 필요합니다.".to_owned()));
                    items.push(Item::Row(vec![
                        Ctl::button(ids::DONE_RPC, "RPC 엔드포인트 설정"),
                        Ctl::button(ids::DONE_CONTINUE, "나중에"),
                    ]));
                } else {
                    items.push(Item::Row(vec![Ctl::button(ids::DONE_CONTINUE, "계속")]));
                }
            }
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
        }
        items
    }

    fn first_run(&self, items: &mut Vec<Item>) {
        items.push(Item::Title("Your Wallet".to_owned()));
        items.push(Item::Text(
            "이 PC에 지갑이 없습니다. 새로 만들거나 기존 니모닉으로 가져오세요.".to_owned(),
        ));
        if self.leftover {
            items.push(Item::Banner(
                "이전 지갑의 파일이 데이터 폴더에 남아 있습니다. 앱을 종료하고 파일을 다른 곳으로 옮긴 뒤 다시 실행하세요.".to_owned(),
                Tone::Warn,
            ));
            items.push(Item::Mono(self.paths.data.display().to_string()));
            items.push(Item::Row(vec![Ctl::button(
                ids::OPEN_DATA_FOLDER,
                "폴더 열기",
            )]));
        }
        items.push(Item::Row(vec![
            Ctl::button(ids::FIRST_CREATE, "새 지갑 만들기").enabled(!self.leftover),
            Ctl::button(ids::FIRST_IMPORT, "기존 지갑 가져오기").enabled(!self.leftover),
        ]));
    }

    fn recovery(&self, items: &mut Vec<Item>) {
        items.push(Item::Title("지갑 파일 복구".to_owned()));
        let prev = match self.mode {
            AppMode::Corrupt { prev_available } => {
                items.push(Item::Text(ErrorCode::Vlt002.text()));
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
            items.push(Item::Muted(
                "이전 사본으로 복구하면 마지막 변경(예: 가져온 개인키)이 사라질 수 있습니다."
                    .to_owned(),
            ));
        }
        items.push(Item::Mono(self.paths.data.display().to_string()));
        let mut row = Vec::new();
        if prev {
            row.push(Ctl::button(ids::RECOVER, "이전 사본으로 복구"));
        }
        row.push(Ctl::button(ids::OPEN_DATA_FOLDER, "폴더 열기"));
        row.push(Ctl::button(ids::EXIT, "종료"));
        items.push(Item::Row(row));
    }

    #[expect(clippy::too_many_lines, reason = "the S10 sections in order")]
    fn main_screen(&self, items: &mut Vec<Item>) {
        items.push(Item::Row(vec![
            Ctl::button(ids::OPEN_SETTINGS, "설정"),
            Ctl::button(crate::ui::screens_evm::ids::BOOK_OPEN, "주소록"),
            Ctl::button(crate::ui::screens_sites::ids::SITES_OPEN, "연결된 사이트"),
            Ctl::button(ids::LOCK, "잠금 (Ctrl+L)"),
        ]));
        if matches!(
            self.mode,
            AppMode::Unlocked {
                alt_passphrase: true
            }
        ) {
            items.push(Item::Banner(
                "가져올 때와 다른 passphrase로 연 지갑입니다. 계정 이름·주소록·연결 기록이 저장되지 않습니다.".to_owned(),
                Tone::Warn,
            ));
        }
        self.tab_row(items);
        if self.sol_tab_active() {
            self.sol_main_screen(items);
            return;
        }
        items.push(Item::Title("EVM".to_owned()));
        let chains = self.settings.registered_evm();
        let radios: Vec<Ctl> = chains
            .iter()
            .enumerate()
            .map(|(index, chain_id)| {
                Ctl::radio(
                    ids::NETWORK_BASE.saturating_add(u16::try_from(index).unwrap_or(0)),
                    &self.network_label(*chain_id),
                    *chain_id == self.settings.evm_chain_id,
                    index == 0,
                )
            })
            .collect();
        items.push(Item::LabeledRow("네트워크".to_owned(), radios));
        if self.settings.evm_chain_id == SEPOLIA {
            items.push(Item::Banner(
                "테스트넷 — 실제 자산이 아닙니다".to_owned(),
                Tone::Testnet,
            ));
        }
        self.evm_banners(items);
        items.push(Item::Muted(self.evm_status_line()));
        items.push(Item::Row(vec![Ctl::button(
            crate::ui::screens_evm::ids::REFRESH,
            "새로고침",
        )]));
        items.push(Item::Rule);
        items.push(Item::Text("계정".to_owned()));
        let selected = self.meta.as_ref().map(|meta| meta.prefs.evm_account);
        for (row, (pref, label, address, path)) in self.account_rows().into_iter().enumerate() {
            let is_selected = selected == Some(pref);
            items.push(Item::Row(vec![
                Ctl::radio(
                    ids::ACCOUNT_BASE.saturating_add(u16::try_from(row).unwrap_or(0)),
                    &label,
                    is_selected,
                    row == 0,
                )
                .width(360),
            ]));
            let balance = self.balance_text(&address);
            items.push(Item::Mono(address));
            items.push(Item::Muted(match balance {
                Some(balance) => format!("{path} · {balance}"),
                None => path,
            }));
            if is_selected {
                if self.rename == Some(pref) {
                    items.push(Item::Row(vec![
                        Ctl::edit(ids::RENAME_EDIT, &label, 260, false, 64),
                        Ctl::button(ids::RENAME_SAVE, "저장"),
                        Ctl::button(ids::RENAME_CANCEL, "취소"),
                    ]));
                } else {
                    let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
                    let mut row_ctls = vec![
                        Ctl::button(crate::ui::screens_evm::ids::SEND_OPEN, "보내기")
                            .enabled(unlocked),
                        Ctl::button(crate::ui::screens_evm::ids::RECEIVE_OPEN, "받기"),
                        Ctl::button(ids::RENAME, "이름 바꾸기"),
                    ];
                    match pref {
                        EvmAccountPref::Index(index) => {
                            row_ctls.push(Ctl::button(ids::HIDE, "숨기기").enabled(index != 0));
                        }
                        EvmAccountPref::Record(_) => {
                            row_ctls.push(Ctl::button(ids::REMOVE_KEY, "삭제"));
                        }
                    }
                    items.push(Item::Row(row_ctls));
                }
            }
            items.push(Item::Gap(4));
        }
        items.push(Item::Row(vec![
            Ctl::button(ids::ADD_ACCOUNT, "계정 추가").enabled(
                self.meta
                    .as_ref()
                    .and_then(crate::meta::Meta::next_index)
                    .is_some(),
            ),
            Ctl::button(ids::IMPORT_KEY, "개인키 가져오기"),
        ]));
        self.evm_main_sections(items);
    }

    fn settings_screen(&self, section: SettingsSection, items: &mut Vec<Item>) {
        items.push(Item::Row(vec![
            Ctl::button(ids::BACK_MAIN, "← 메인"),
            Ctl::button(ids::SECTION_SECURITY, "보안")
                .enabled(section != SettingsSection::Security),
            Ctl::button(ids::SECTION_NETWORK, "네트워크")
                .enabled(section != SettingsSection::Network),
            Ctl::button(crate::ui::screens_evm::ids::SECTION_CHAINS, "EVM 체인")
                .enabled(section != SettingsSection::Chains),
            Ctl::button(crate::ui::screens_sol::ids::SECTION_SOL, "Solana")
                .enabled(section != SettingsSection::Solana),
            Ctl::button(ids::SECTION_OTHER, "브라우저·진단·정보")
                .enabled(section != SettingsSection::Other),
        ]));
        match section {
            SettingsSection::Security => self.security_section(items),
            SettingsSection::Network => self.network_section(items),
            SettingsSection::Chains => self.chains_section(items),
            SettingsSection::Solana => self.sol_settings_section(items),
            SettingsSection::Other => self.other_section(items),
        }
    }

    fn security_section(&self, items: &mut Vec<Item>) {
        items.push(Item::Title("보안".to_owned()));
        items.push(Item::LabeledRow(
            "자동 잠금(분, 1–60)".to_owned(),
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
        items.push(Item::Row(vec![Ctl::check(
            ids::COPY_TOGGLE,
            "니모닉·개인키 복사 허용",
            self.settings.allow_secret_copy,
        )]));
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        let public = unlocked || self.mode == AppMode::BackupPending;
        items.push(Item::Row(vec![
            Ctl::button(ids::REVEAL_MNEMONIC, "니모닉 보기").enabled(public),
            Ctl::button(ids::REVEAL_KEY, "개인키 보기").enabled(unlocked),
            Ctl::button(ids::CHANGE_PASSWORD, "비밀번호 변경").enabled(public),
        ]));
        items.push(Item::Muted(
            "개인키 보기는 메인 화면에서 선택한 계정의 키를 보여줍니다.".to_owned(),
        ));
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the RPC provider form and the URL rows"
    )]
    fn network_section(&self, items: &mut Vec<Item>) {
        items.push(Item::Title("RPC 공급자".to_owned()));
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
                items.push(Item::Muted(format!(
                    "저장된 QuickNode 자격 정보: {status} (저장된 값은 다시 보이지 않습니다)"
                )));
                items.push(Item::LabeledRow(
                    "엔드포인트 이름".to_owned(),
                    vec![Ctl::edit(ids::QN_NAME_EDIT, "", 320, true, 128)],
                ));
                items.push(Item::LabeledRow(
                    "토큰".to_owned(),
                    vec![Ctl::edit(ids::QN_TOKEN_EDIT, "", 320, true, 256)],
                ));
            }
            RpcTemplate::Alchemy => {
                let status = if self.apikeys.has(KeyName::TplAlchemy) {
                    "설정됨"
                } else {
                    "없음"
                };
                items.push(Item::Muted(format!(
                    "저장된 알케미 키: {status} (저장된 값은 다시 보이지 않습니다)"
                )));
                items.push(Item::LabeledRow(
                    "키".to_owned(),
                    vec![Ctl::edit(ids::ALCHEMY_KEY_EDIT, "", 320, true, 256)],
                ));
            }
            RpcTemplate::Manual => {
                items.push(Item::Muted(
                    "직접 입력: 아래 네트워크 URL 목록의 `교체`로 URL을 넣으세요.".to_owned(),
                ));
            }
        }
        let manual = template == RpcTemplate::Manual;
        items.push(Item::Row(vec![
            Ctl::button(ids::TPL_SAVE, "저장").enabled(!manual),
            Ctl::button(ids::TPL_DELETE, "삭제").enabled(!manual),
            Ctl::button(ids::GENERATE, "네트워크 URL 생성").enabled(!manual),
        ]));
        items.push(Item::Rule);
        items.push(Item::Title("네트워크 URL".to_owned()));
        for (row, network) in self.url_networks().into_iter().enumerate() {
            let url = self.apikeys.rpc_url(network);
            let state = url.as_ref().map_or_else(
                || "없음".to_owned(),
                |url| format!("설정됨  {}", mask_url(url)),
            );
            items.push(Item::Text(format!(
                "{}  ({network})",
                self.network_name(network)
            )));
            items.push(Item::Muted(state));
            let base =
                ids::ROW_BASE.saturating_add(u16::try_from(row).unwrap_or(0).saturating_mul(4));
            items.push(Item::Row(vec![
                Ctl::button(base, "교체"),
                Ctl::button(base.saturating_add(1), "테스트"),
                Ctl::button(base.saturating_add(2), "삭제").enabled(url.is_some()),
            ]));
            if self.replace_target == Some(network) {
                items.push(Item::Row(vec![
                    Ctl::edit(ids::REPLACE_EDIT, "", 420, true, 2_048),
                    Ctl::button(ids::REPLACE_SAVE, "저장"),
                    Ctl::button(ids::REPLACE_CANCEL, "취소"),
                ]));
            }
            if let Some((_, message, ok)) =
                self.rpc_messages.iter().find(|(id, _, _)| *id == network)
            {
                items.push(Item::Banner(
                    message.clone(),
                    if *ok { Tone::Info } else { Tone::Danger },
                ));
            }
        }
        items.push(Item::Muted("URL에는 토큰이 들어 있어 화면에는 가린 형태만 보입니다. Bitcoin 네트워크는 M8에서 목록에 추가됩니다.".to_owned()));
    }

    fn other_section(&self, items: &mut Vec<Item>) {
        items.push(Item::Title("브라우저".to_owned()));
        items.push(Item::Row(vec![Ctl::check(
            ids::LOCALHOST_TOGGLE,
            "localhost dApp 허용",
            self.settings.allow_localhost_dapps,
        )]));
        items.push(Item::Row(vec![Ctl::check(
            ids::AUTOLAUNCH_TOGGLE,
            "dApp 요청 시 앱 자동 실행",
            self.settings.browser_auto_launch,
        )]));
        items.push(Item::Rule);
        items.push(Item::Title("진단".to_owned()));
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
        items.push(Item::Row(vec![Ctl::button(
            ids::OPEN_LOG_FOLDER,
            "로그 폴더 열기",
        )]));
        items.push(Item::Muted("로그에는 비밀번호·니모닉·개인키·API 키·RPC 엔드포인트 URL이 없습니다. 주소와 거래 해시는 있을 수 있습니다.".to_owned()));
        items.push(Item::Rule);
        items.push(Item::Title("정보".to_owned()));
        items.push(Item::Text(format!("버전 {}", env!("CARGO_PKG_VERSION"))));
        items.push(Item::Mono(self.paths.data.display().to_string()));
        items.push(Item::Row(vec![Ctl::button(
            ids::OPEN_DATA_FOLDER,
            "폴더 열기",
        )]));
    }

    fn confirm(&self, kind: Confirm, items: &mut Vec<Item>) {
        let (title, text, yes) = match kind {
            Confirm::CopyOn => (
                "복사 허용",
                "복사를 허용하면 니모닉·개인키를 클립보드에 넣을 수 있습니다. 클립보드 기록·클라우드 동기화에서는 제외하고 30초 뒤 지우지만, 그 사이에는 다른 프로그램이 읽을 수 있습니다.".to_owned(),
                "허용",
            ),
            Confirm::LocalhostOn => (
                "localhost dApp 허용",
                "개발용 설정입니다. 켜면 http://localhost 와 http://127.0.0.1 페이지가 지갑 연결을 요청할 수 있습니다.".to_owned(),
                "켜기",
            ),
            Confirm::RevealMnemonic | Confirm::RevealKey => (
                if kind == Confirm::RevealMnemonic { "니모닉 보기" } else { "개인키 보기" },
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
                "선택한 가져온 개인키를 지갑에서 지웁니다. 계속하려면 비밀번호를 입력하세요.".to_owned(),
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
                "선택한 주소록 항목을 지웁니다.".to_owned(),
                "삭제",
            ),
            Confirm::DisconnectAll => (
                "모든 사이트 연결 해제",
                "연결된 모든 사이트의 연결을 해제합니다. 사이트는 다시 연결을 요청해야 계정을 볼 수 있습니다.".to_owned(),
                "모두 해제",
            ),
            Confirm::Discard => (
                "거래 폐기",
                "이 거래를 폐기로 표시하고 추적을 멈춥니다. 이미 네트워크에 전파됐다면 나중에 처리될 수 있습니다.".to_owned(),
                "폐기",
            ),
        };
        items.push(Item::Title(title.to_owned()));
        items.push(Item::Text(text));
        if kind == Confirm::Generate {
            items.push(Item::Row(vec![Ctl::check(
                ids::OVERWRITE_CHECK,
                "기존 URL 덮어쓰기",
                self.overwrite_checked,
            )]));
        }
        if kind == Confirm::ChainRepin {
            let checked = self.evm.repin.as_ref().is_some_and(|repin| repin.checked);
            items.push(Item::Row(vec![Ctl::check(
                crate::ui::screens_evm::ids::REPIN_CHECK,
                "새 제네시스 해시를 공식 자료로 확인했습니다",
                checked,
            )]));
            items.push(Item::Row(vec![
                Ctl::button(ids::CONFIRM_YES, yes).enabled(checked),
                Ctl::button(ids::CONFIRM_NO, "취소"),
            ]));
            return;
        }
        if kind == Confirm::SidecarCorrupt {
            items.push(Item::Row(vec![
                Ctl::button(ids::SIDECAR_PREV, "이전 사본(.prev) 사용"),
                Ctl::button(ids::SIDECAR_FRESH, "격리하고 새로 시작"),
            ]));
        } else {
            items.push(Item::Row(vec![
                Ctl::button(ids::CONFIRM_YES, yes),
                Ctl::button(ids::CONFIRM_NO, "취소"),
            ]));
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
