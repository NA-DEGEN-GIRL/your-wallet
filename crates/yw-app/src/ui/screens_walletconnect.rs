//! The `WalletConnect` panel at the top of S13 연결된 사이트 (spec/13 §6): `WalletConnect 연결`
//! (paste a `wc:` URI, `클립보드 이미지에서 QR 읽기`, `이미지 파일에서 QR 읽기`), the Reown
//! Project ID, the relay state, and the `WalletConnect 세션` cards (peer name, claimed URL,
//! `연결 확인 중` until the dApp confirms, Verify state, accounts, chains, expiry) with
//! `연결 해제` and `모든 WalletConnect 세션 끊기`.

use crate::app::App;
use crate::ui::main_window::{Ctl, Item, Tone};
use crate::walletconnect::VerifyStatus;

/// Control ids (16,000–16,099; the whole map is `ui::command_ids`).
pub mod ids {
    /// URI edit.
    pub const URI_EDIT: u16 = 16_000;
    /// 연결.
    pub const PAIR: u16 = 16_001;
    /// 클립보드 이미지에서 QR 읽기.
    pub const CLIPBOARD_QR: u16 = 16_002;
    /// Image path edit.
    pub const FILE_EDIT: u16 = 16_003;
    /// 이미지 파일에서 QR 읽기.
    pub const FILE_QR: u16 = 16_004;
    /// Project id edit.
    pub const PROJECT_EDIT: u16 = 16_005;
    /// Project id save.
    pub const PROJECT_SAVE: u16 = 16_006;
    /// `모든 WalletConnect 세션 끊기`.
    pub const DISCONNECT_ALL: u16 = 16_007;
    /// `Project ID 바꾸기 ▸` / `접기 ▾` (a saved id).
    pub const PROJECT_TOGGLE: u16 = 16_008;
    /// `클립보드에서 연결` (a copied `wc:` link, else a copied QR image).
    pub const CLIPBOARD_CONNECT: u16 = 16_009;
    /// `다른 방법 (이미지 파일) ▸` / `접기 ▾`.
    pub const FILE_TOGGLE: u16 = 16_010;
    /// `dashboard.reown.com 주소 복사` (copies the address, opens nothing).
    pub const REOWN_COPY: u16 = 16_011;
    /// Session row buttons (`연결 해제`).
    pub const ROW_BASE: u16 = 16_020;
    /// Row span (the engine keeps at most 64 sessions).
    pub const ROW_SPAN: u16 = 64;
    /// Every fixed id of this module.
    pub const FIXED: &[u16] = &[
        URI_EDIT,
        PAIR,
        CLIPBOARD_QR,
        FILE_EDIT,
        FILE_QR,
        PROJECT_EDIT,
        PROJECT_SAVE,
        DISCONNECT_ALL,
        PROJECT_TOGGLE,
        CLIPBOARD_CONNECT,
        FILE_TOGGLE,
        REOWN_COPY,
    ];
}

/// The setup card's one help (no Project ID yet): what it is for and where the ID comes from.
pub const T_WC_SETUP_INTRO: &str = "확장 프로그램 없이 dApp에 연결하려면(EVM) Reown Project ID를 한 번 저장하세요. dashboard.reown.com에서 무료 프로젝트를 만들면 받는 32자리 값이고 비밀값이 아닙니다. 프로젝트의 허용 출처(allowlist)는 비워 둡니다.";
/// What `WalletConnect` is for and how a pairing starts (the panel with a Project ID).
pub const T_WC_INTRO: &str = "확장 프로그램 대신 WalletConnect로 dApp에 연결합니다(EVM). 연결과 서명은 확장과 같은 이 앱의 승인 창에서 확인합니다.";
/// The two steps above `클립보드에서 연결` (2026-11-08).
pub const T_WC_STEPS: [&str; 2] = [
    "1. dApp의 WalletConnect 창에서 '링크 복사'를 누르거나, QR을 Win+Shift+S로 캡처합니다.",
    "2. '클립보드에서 연결'을 누릅니다. 클립보드는 이 버튼을 누를 때만 읽습니다.",
];

fn local_time(seconds: u64) -> String {
    let unix_ms = seconds.saturating_mul(1_000);
    let local = yw_win::time::local_wall_ms(unix_ms);
    let text = crate::logging::format_utc(local.unwrap_or(unix_ms));
    let short = text.get(..16).unwrap_or(&text).replace('T', " ");
    if local.is_some() {
        short
    } else {
        format!("{short} UTC")
    }
}

impl App {
    /// The `WalletConnect` panel (drawn first on S13). Without a Project ID it is a short setup
    /// card (the ID only; the pairing inputs appear once it is saved); with one, the pairing
    /// inputs come first and the saved ID is one line with `Project ID 바꾸기 ▸`.
    pub(crate) fn wc_panel(&self, items: &mut Vec<Item>) {
        let has_project = !self.settings.walletconnect_project.is_empty();
        if !has_project {
            self.wc_setup_card(items);
            self.wc_session_cards(items);
            return;
        }
        items.push(Item::CardStart(Some("WalletConnect 연결".to_owned())));
        items.push(Item::Help(T_WC_INTRO.to_owned()));
        for step in T_WC_STEPS {
            items.push(Item::Text(step.to_owned()));
        }
        items.push(Item::Row(vec![Ctl::primary(
            ids::CLIPBOARD_CONNECT,
            "클립보드에서 연결",
        )]));
        items.push(Item::LabeledRow(
            "또는 연결 주소 (wc:…)".to_owned(),
            vec![
                Ctl::edit(ids::URI_EDIT, &self.wc.uri_text, 420, false, 2_048),
                Ctl::button(ids::PAIR, "연결"),
            ],
        ));
        items.push(Item::Row(vec![Ctl::link(
            ids::FILE_TOGGLE,
            if self.wc.file_open {
                "다른 방법 (이미지 파일) 접기 ▾"
            } else {
                "다른 방법 (이미지 파일) ▸"
            },
        )]));
        if self.wc.file_open {
            items.push(Item::LabeledRow(
                "이미지 파일 경로".to_owned(),
                vec![
                    Ctl::edit(ids::FILE_EDIT, &self.wc.file_text, 420, false, 1_024),
                    Ctl::button(ids::FILE_QR, "이미지 파일에서 QR 읽기"),
                ],
            ));
        }
        if let Some(notice) = &self.wc.notice {
            items.push(Item::Banner(notice.clone(), Tone::Info));
        }
        items.push(Item::Field("릴레이".to_owned(), self.wc.status.text()));
        let editing = self.wc.project_open || self.wc.project_text.is_some();
        items.push(Item::Field(
            "Reown Project ID".to_owned(),
            self.settings.walletconnect_project.clone(),
        ));
        items.push(Item::Row(vec![Ctl::link(
            ids::PROJECT_TOGGLE,
            if editing {
                "Project ID 바꾸기 접기 ▾"
            } else {
                "Project ID 바꾸기 ▸"
            },
        )]));
        if editing {
            self.wc_project_row(items, false);
        }
        items.push(Item::CardEnd);
        self.wc_session_cards(items);
    }

    /// The setup card shown while no Project ID is saved — the default, and the lasting state of
    /// a wallet that only uses the extension, so it is three rows and the site list stays in the
    /// first view (2026-11-12; before: relay line, two step headings and a description of the
    /// controls that were not there yet).
    fn wc_setup_card(&self, items: &mut Vec<Item>) {
        items.push(Item::CardStart(Some(
            "WalletConnect (선택) — 꺼져 있음".to_owned(),
        )));
        items.push(Item::Help(T_WC_SETUP_INTRO.to_owned()));
        self.wc_project_row(items, true);
        if let Some(notice) = &self.wc.notice {
            items.push(Item::Banner(notice.clone(), Tone::Info));
        }
        items.push(Item::CardEnd);
    }

    /// The Project ID input and `저장`; then, in the setup card, the link that copies where to
    /// get the ID, and behind `Project ID 바꾸기 ▸` the help for changing it.
    fn wc_project_row(&self, items: &mut Vec<Item>, setup: bool) {
        let project = self
            .wc
            .project_text
            .clone()
            .unwrap_or_else(|| self.settings.walletconnect_project.clone());
        let mut row = vec![
            Ctl::edit(ids::PROJECT_EDIT, &project, 300, false, 64),
            if setup {
                Ctl::primary(ids::PROJECT_SAVE, "저장")
            } else {
                Ctl::button(ids::PROJECT_SAVE, "저장")
            },
        ];
        if setup {
            // The address only goes to the clipboard: the app opens no web page (2026-11-10).
            row.push(Ctl::link(ids::REOWN_COPY, "dashboard.reown.com 주소 복사"));
        }
        items.push(Item::LabeledRow("Reown Project ID".to_owned(), row));
        if !setup {
            items.push(Item::Help(
                "dashboard.reown.com에서 무료 프로젝트를 만들고 그 Project ID(32자리)를 넣습니다. 비밀값이 아닙니다. 프로젝트의 허용 출처(allowlist)는 비워 두세요. 비우고 저장하면 WalletConnect가 꺼집니다."
                    .to_owned(),
            ));
        }
    }

    fn wc_session_cards(&self, items: &mut Vec<Item>) {
        let mut rows = self.wc.rows.borrow_mut();
        rows.clear();
        if self.wc.sessions.is_empty() {
            return;
        }
        let labels = self.own_accounts();
        for session in &self.wc.sessions {
            items.push(Item::CardStart(Some(format!(
                "{}  ·  WalletConnect 세션",
                session.peer.display_name()
            ))));
            items.push(Item::Field(
                "사이트 주소".to_owned(),
                format!("{} (사이트가 주장한 주소)", session.peer.display_url()),
            ));
            if !session.acknowledged {
                // Approved here, not yet confirmed by the dApp (spec/13 §5.3): never shown as
                // simply "connected" while the dApp may not have it.
                items.push(Item::Field(
                    "상태".to_owned(),
                    "연결 확인 중 — dApp의 확인을 기다리는 중입니다. 몇 분 안에 확인되지 않으면 자동으로 끊습니다."
                        .to_owned(),
                ));
            }
            let tone = match session.verify {
                VerifyStatus::Valid => None,
                VerifyStatus::Unknown => Some(Tone::Warn),
                VerifyStatus::Invalid | VerifyStatus::Scam => Some(Tone::HighRisk),
            };
            let verify = format!("Verify: {}", session.verify.label());
            match tone {
                Some(tone) => items.push(Item::Banner(verify, tone)),
                None => items.push(Item::Field(
                    "Verify".to_owned(),
                    session.verify.label().to_owned(),
                )),
            }
            let chains: Vec<String> = session
                .chains
                .iter()
                .map(|id| {
                    self.settings
                        .evm_chain_name(*id)
                        .unwrap_or_else(|| format!("eip155:{id}"))
                })
                .collect();
            items.push(Item::Field("네트워크".to_owned(), chains.join(", ")));
            items.push(Item::Field(
                "연결 시각".to_owned(),
                local_time(session.created),
            ));
            items.push(Item::Field("만료".to_owned(), local_time(session.expiry)));
            // Under the times, before the accounts — where the site cards have it (2026-11-12).
            if let Some(id) = u16::try_from(rows.len())
                .ok()
                .filter(|offset| *offset < ids::ROW_SPAN)
                .map(|offset| ids::ROW_BASE + offset)
            {
                rows.push(session.topic);
                items.push(Item::Row(vec![Ctl::danger(id, "연결 해제").compact()]));
            }
            for account in &session.accounts {
                let label = labels
                    .iter()
                    .find(|(address, _)| address == account)
                    .map_or("", |(_, label)| label.as_str());
                items.push(Item::Help(label.to_owned()));
                items.push(Item::Mono(yw_core::evm::display::format_address(account)));
            }
            items.push(Item::CardEnd);
        }
        items.push(Item::Row(vec![Ctl::danger(
            ids::DISCONNECT_ALL,
            "모든 WalletConnect 세션 끊기",
        )]));
    }

    /// Commands of the panel.
    pub(crate) fn on_wc_command(&mut self, id: u16) -> bool {
        match id {
            ids::PAIR => {
                let text = self
                    .controls
                    .text(ids::URI_EDIT, 2_048)
                    .unwrap_or_else(|| self.wc.uri_text.clone());
                self.wc_pair(&text);
            }
            ids::CLIPBOARD_QR => self.wc_clipboard_qr(),
            ids::CLIPBOARD_CONNECT => self.wc_clipboard_connect(),
            ids::FILE_TOGGLE => self.wc.file_open = !self.wc.file_open,
            ids::FILE_QR => {
                if let Some(text) = self.controls.text(ids::FILE_EDIT, 1_024) {
                    self.wc.file_text = text;
                }
                self.wc_file_qr();
            }
            ids::PROJECT_SAVE => {
                if let Some(text) = self.controls.text(ids::PROJECT_EDIT, 64) {
                    self.wc.project_text = Some(text);
                }
                self.wc_save_project();
            }
            ids::DISCONNECT_ALL => {
                // Every session at once: confirmed first, like `모든 사이트 연결 해제`.
                if !self.wc.sessions.is_empty() {
                    self.set_screen(crate::app::Screen::Confirm(
                        crate::app::Confirm::WcDisconnectAll,
                    ));
                }
                return true;
            }
            ids::PROJECT_TOGGLE => {
                let open = self.wc.project_open || self.wc.project_text.is_some();
                self.wc.project_open = !open;
                self.wc.project_text = None;
            }
            ids::REOWN_COPY => {
                // Only the address string: no browser is started (2026-11-10).
                self.copy_text("https://dashboard.reown.com");
                if self.info.as_deref() == Some("복사했습니다.") {
                    self.info = Some(
                        "dashboard.reown.com 주소를 복사했습니다. 브라우저 주소창에 붙여넣으세요."
                            .to_owned(),
                    );
                }
            }
            _ => {
                let Some(offset) = id
                    .checked_sub(ids::ROW_BASE)
                    .filter(|offset| *offset < ids::ROW_SPAN)
                else {
                    return false;
                };
                let topic = self.wc.rows.borrow().get(usize::from(offset)).copied();
                if let Some(topic) = topic {
                    self.wc_disconnect(topic);
                }
            }
        }
        self.refresh();
        true
    }

    /// Edit changes of the panel.
    pub(crate) fn on_wc_edit_change(&mut self, id: u16) -> bool {
        match id {
            ids::URI_EDIT => {
                self.wc.uri_text = self.controls.text(id, 2_048).unwrap_or_default();
            }
            ids::FILE_EDIT => {
                self.wc.file_text = self.controls.text(id, 1_024).unwrap_or_default();
            }
            ids::PROJECT_EDIT => {
                self.wc.project_text = Some(self.controls.text(id, 64).unwrap_or_default());
            }
            _ => return false,
        }
        true
    }
}
