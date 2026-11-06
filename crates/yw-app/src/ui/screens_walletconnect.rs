//! The `WalletConnect` panel at the top of S13 연결된 사이트 (spec/13 §6): `WalletConnect 연결`
//! (paste a `wc:` URI, `클립보드 이미지에서 QR 읽기`, `이미지 파일에서 QR 읽기`), the Reown
//! Project ID, the relay state, and the `WalletConnect 세션` cards (peer name, claimed URL,
//! Verify state, accounts, chains, expiry) with `연결 해제` and `모든 WalletConnect 세션 끊기`.

use crate::app::App;
use crate::ui::main_window::{Ctl, Item, Tone};
use crate::walletconnect::VerifyStatus;

/// Control ids (14,500–14,599; the whole map is `ui::command_ids`).
pub mod ids {
    /// URI edit.
    pub const URI_EDIT: u16 = 14_500;
    /// 연결.
    pub const PAIR: u16 = 14_501;
    /// 클립보드 이미지에서 QR 읽기.
    pub const CLIPBOARD_QR: u16 = 14_502;
    /// Image path edit.
    pub const FILE_EDIT: u16 = 14_503;
    /// 이미지 파일에서 QR 읽기.
    pub const FILE_QR: u16 = 14_504;
    /// Project id edit.
    pub const PROJECT_EDIT: u16 = 14_505;
    /// Project id save.
    pub const PROJECT_SAVE: u16 = 14_506;
    /// `모든 WalletConnect 세션 끊기`.
    pub const DISCONNECT_ALL: u16 = 14_507;
    /// Session row buttons (`연결 해제`).
    pub const ROW_BASE: u16 = 14_520;
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
    ];
}

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
    /// The `WalletConnect` panel (drawn first on S13).
    pub(crate) fn wc_panel(&self, items: &mut Vec<Item>) {
        items.push(Item::CardStart(Some("WalletConnect 연결".to_owned())));
        items.push(Item::Help(
            "확장 프로그램 대신 WalletConnect로 dApp에 연결합니다. dApp의 'WalletConnect' 창에서 '링크 복사'를 누르고 아래에 붙여 넣거나, QR을 Win+Shift+S로 캡처한 뒤 '클립보드 이미지에서 QR 읽기'를 누르세요."
                .to_owned(),
        ));
        let has_project = !self.settings.walletconnect_project.is_empty();
        items.push(Item::LabeledRow(
            "연결 주소 (wc:…)".to_owned(),
            vec![
                Ctl::edit(ids::URI_EDIT, &self.wc.uri_text, 420, false, 2_048),
                Ctl::primary(ids::PAIR, "연결").enabled(has_project),
            ],
        ));
        items.push(Item::Row(vec![
            Ctl::button(ids::CLIPBOARD_QR, "클립보드 이미지에서 QR 읽기").enabled(has_project),
        ]));
        items.push(Item::LabeledRow(
            "이미지 파일 경로".to_owned(),
            vec![
                Ctl::edit(ids::FILE_EDIT, &self.wc.file_text, 420, false, 1_024),
                Ctl::button(ids::FILE_QR, "이미지 파일에서 QR 읽기").enabled(has_project),
            ],
        ));
        if let Some(notice) = &self.wc.notice {
            items.push(Item::Banner(notice.clone(), Tone::Info));
        }
        let status = if has_project {
            self.wc.status.text()
        } else {
            crate::walletconnect::worker::RelayStatus::NoProject.text()
        };
        items.push(Item::Field("릴레이".to_owned(), status));
        let project = self
            .wc
            .project_text
            .clone()
            .unwrap_or_else(|| self.settings.walletconnect_project.clone());
        items.push(Item::LabeledRow(
            "Reown Project ID".to_owned(),
            vec![
                Ctl::edit(ids::PROJECT_EDIT, &project, 300, false, 64),
                Ctl::button(ids::PROJECT_SAVE, "저장"),
            ],
        ));
        items.push(Item::Help(
            "WalletConnect 릴레이를 쓰려면 cloud.reown.com에서 무료 프로젝트를 만들고 그 Project ID(32자리)를 넣어야 합니다. 이 지갑에는 기본 ID가 들어 있지 않습니다. Project ID는 비밀값이 아닙니다."
                .to_owned(),
        ));
        items.push(Item::CardEnd);
        self.wc_session_cards(items);
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
                format!(
                    "{} (사이트가 주장한 주소)",
                    session.peer.display_url()
                ),
            ));
            let tone = match session.verify {
                VerifyStatus::Valid => None,
                VerifyStatus::Unknown => Some(Tone::Warn),
                VerifyStatus::Invalid | VerifyStatus::Scam => Some(Tone::HighRisk),
            };
            let verify = format!("Verify: {}", session.verify.label());
            match tone {
                Some(tone) => items.push(Item::Banner(verify, tone)),
                None => items.push(Item::Field("Verify".to_owned(), session.verify.label().to_owned())),
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
            items.push(Item::Field("연결 시각".to_owned(), local_time(session.created)));
            items.push(Item::Field("만료".to_owned(), local_time(session.expiry)));
            for account in &session.accounts {
                let label = labels
                    .iter()
                    .find(|(address, _)| address == account)
                    .map_or("", |(_, label)| label.as_str());
                items.push(Item::Help(label.to_owned()));
                items.push(Item::Mono(yw_core::evm::display::format_address(account)));
            }
            if let Some(id) = u16::try_from(rows.len())
                .ok()
                .filter(|offset| *offset < ids::ROW_SPAN)
                .map(|offset| ids::ROW_BASE + offset)
            {
                rows.push(session.topic);
                items.push(Item::Row(vec![Ctl::danger(id, "연결 해제")]));
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
            ids::DISCONNECT_ALL => self.wc_disconnect_all(),
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
