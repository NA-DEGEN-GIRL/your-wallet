//! The `WalletConnect` panel at the top of S13 연결된 사이트 (spec/13 §6): `WalletConnect 연결`
//! (paste a `wc:` URI, `클립보드 이미지에서 QR 읽기`, `이미지 파일에서 QR 읽기`), the Reown
//! Project ID, the relay state, and the `WalletConnect 세션` cards (peer name, claimed URL,
//! `연결 확인 중` until the dApp confirms, Verify state, accounts, chains, expiry) with
//! `연결 해제` and `모든 WalletConnect 세션 끊기`.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): moved here from yw-app `ui/screens_walletconnect.rs`
//! with the bodies unchanged (`impl App` builders became `impl Screen<'_>`, yw-app paths engine
//! paths); its control ids stay there (`ui::screens_walletconnect::ids`).

use super::Screen;
use crate::cmd::WcPress;
use crate::form::EditField;
use crate::screen::Tone;
use crate::screen::model::{Ctl, Item};
use crate::screen::rows as screen_rows;
use crate::walletconnect::VerifyStatus;

/// The panel's texts (spec/13 §6; English spec/14).
pub mod text {
    yw_core::texts! {
        /// The setup card's one help (no Project ID yet): what it is for and where the ID comes
        /// from.
        WC_SETUP_INTRO = "확장 프로그램 없이 dApp에 연결하려면(EVM) Reown Project ID를 한 번 저장하세요. dashboard.reown.com에서 무료 프로젝트를 만들면 받는 32자리 값이고 비밀값이 아닙니다. 프로젝트의 허용 출처(allowlist)는 비워 둡니다."
            / "To connect to dApps without the extension (EVM), save a Reown Project ID once. It is the 32-character value you get by creating a free project at dashboard.reown.com, and it is not a secret. Leave the project's allowed origins (allowlist) empty.";
        /// What `WalletConnect` is for and how a pairing starts (the panel with a Project ID).
        WC_INTRO = "확장 프로그램 대신 WalletConnect로 dApp에 연결합니다(EVM). 연결과 서명은 확장과 같은 이 앱의 승인 창에서 확인합니다."
            / "Connects to dApps with WalletConnect instead of the extension (EVM). Connections and signatures are checked in this app's approval window, as with the extension.";
        /// The two steps above `클립보드에서 연결` (2026-11-08).
        WC_STEP_1 = "1. dApp의 WalletConnect 창에서 '링크 복사'를 누르거나, QR을 Win+Shift+S로 캡처합니다."
            / "1. Press 'Copy link' in the dApp's WalletConnect window, or capture the QR code with Win+Shift+S.";
        WC_STEP_2 = "2. '클립보드에서 연결'을 누릅니다. 클립보드는 이 버튼을 누를 때만 읽습니다."
            / "2. Press 'Connect from clipboard'. The clipboard is read only when you press this button.";
        CARD_CONNECT = "WalletConnect 연결" / "WalletConnect connection";
        CLIPBOARD_CONNECT = "클립보드에서 연결" / "Connect from clipboard";
        URI_LABEL = "또는 연결 주소 (wc:…)" / "Or link (wc:…)";
        PAIR = "연결" / "Connect";
        FILE_FOLD = "다른 방법 (이미지 파일) 접기 ▾" / "Other way (image file): hide ▾";
        FILE_OPEN = "다른 방법 (이미지 파일) ▸" / "Other way (image file) ▸";
        FILE_LABEL = "이미지 파일 경로" / "Image file path";
        FILE_QR = "이미지 파일에서 QR 읽기" / "Read QR from image file";
        RELAY = "릴레이" / "Relay";
        PROJECT_FOLD = "Project ID 바꾸기 접기 ▾" / "Change Project ID: hide ▾";
        PROJECT_OPEN = "Project ID 바꾸기 ▸" / "Change Project ID ▸";
        CARD_SETUP = "WalletConnect (선택) — 꺼져 있음" / "WalletConnect (optional) — off";
        SAVE = "저장" / "Save";
        REOWN_COPY = "dashboard.reown.com 주소 복사" / "Copy dashboard.reown.com address";
        PROJECT_HELP = "dashboard.reown.com에서 무료 프로젝트를 만들고 그 Project ID(32자리)를 넣습니다. 비밀값이 아닙니다. 프로젝트의 허용 출처(allowlist)는 비워 두세요. 비우고 저장하면 WalletConnect가 꺼집니다."
            / "Create a free project at dashboard.reown.com and enter its Project ID (32 characters). It is not a secret. Leave the project's allowed origins (allowlist) empty. Saving it empty turns WalletConnect off.";
        SESSION_TITLE(1) = "{0}  ·  WalletConnect 세션" / "{0}  ·  WalletConnect session";
        SITE_URL = "사이트 주소" / "Site address";
        STATUS = "상태" / "Status";
        UNACKNOWLEDGED = "연결 확인 중 — dApp의 확인을 기다리는 중입니다. 몇 분 안에 확인되지 않으면 자동으로 끊습니다."
            / "Confirming the connection — waiting for the dApp to confirm. It is disconnected automatically if not confirmed within a few minutes.";
        NETWORK = "네트워크" / "Network";
        CREATED = "연결 시각" / "Connected at";
        EXPIRY = "만료" / "Expires";
        DISCONNECT = "연결 해제" / "Disconnect";
        DISCONNECT_ALL = "모든 WalletConnect 세션 끊기" / "Disconnect all WalletConnect sessions";
    }
}

fn local_time(facts: &dyn crate::screen::facts::ScreenFacts, seconds: u64) -> String {
    let unix_ms = seconds.saturating_mul(1_000);
    let local = facts.local_wall_ms(unix_ms);
    let text = crate::logging::format_utc(local.unwrap_or(unix_ms));
    let short = text.get(..16).unwrap_or(&text).replace('T', " ");
    if local.is_some() {
        short
    } else {
        format!("{short} UTC")
    }
}

impl Screen<'_> {
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
        let lang = self.settings.language;
        items.push(Item::CardStart(Some(
            text::CARD_CONNECT.get(lang).to_owned(),
        )));
        items.push(Item::Help(text::WC_INTRO.get(lang).to_owned()));
        for step in [text::WC_STEP_1, text::WC_STEP_2] {
            items.push(Item::Text(step.get(lang).to_owned()));
        }
        items.push(Item::Row(vec![Ctl::primary(
            WcPress::ClipboardConnect,
            text::CLIPBOARD_CONNECT.get(lang),
        )]));
        items.push(Item::LabeledRow(
            text::URI_LABEL.get(lang).to_owned(),
            vec![
                Ctl::edit(EditField::WcUri, &self.wc.uri_text, 420, false, 2_048),
                Ctl::button(WcPress::Pair, text::PAIR.get(lang)),
            ],
        ));
        items.push(Item::Row(vec![Ctl::link(
            WcPress::FileToggle,
            if self.wc.file_open {
                text::FILE_FOLD.get(lang)
            } else {
                text::FILE_OPEN.get(lang)
            },
        )]));
        if self.wc.file_open {
            items.push(Item::LabeledRow(
                text::FILE_LABEL.get(lang).to_owned(),
                vec![
                    Ctl::edit(EditField::WcFile, &self.wc.file_text, 420, false, 1_024),
                    Ctl::button(WcPress::FileQr, text::FILE_QR.get(lang)),
                ],
            ));
        }
        if let Some(notice) = &self.wc.notice {
            items.push(Item::Banner(notice.clone(), Tone::Info));
        }
        items.push(Item::Field(
            text::RELAY.get(lang).to_owned(),
            self.wc.status.text(lang),
        ));
        let editing = self.wc.project_open || self.wc.project_text.is_some();
        items.push(Item::Field(
            "Reown Project ID".to_owned(),
            self.settings.walletconnect_project.clone(),
        ));
        items.push(Item::Row(vec![Ctl::link(
            WcPress::ProjectToggle,
            if editing {
                text::PROJECT_FOLD.get(lang)
            } else {
                text::PROJECT_OPEN.get(lang)
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
        let lang = self.settings.language;
        items.push(Item::CardStart(Some(text::CARD_SETUP.get(lang).to_owned())));
        items.push(Item::Help(text::WC_SETUP_INTRO.get(lang).to_owned()));
        self.wc_project_row(items, true);
        if let Some(notice) = &self.wc.notice {
            items.push(Item::Banner(notice.clone(), Tone::Info));
        }
        items.push(Item::CardEnd);
    }

    /// The Project ID input and `저장`; then, in the setup card, the link that copies where to
    /// get the ID, and behind `Project ID 바꾸기 ▸` the help for changing it.
    fn wc_project_row(&self, items: &mut Vec<Item>, setup: bool) {
        let lang = self.settings.language;
        let project = self
            .wc
            .project_text
            .clone()
            .unwrap_or_else(|| self.settings.walletconnect_project.clone());
        let mut row = vec![
            Ctl::edit(EditField::WcProject, &project, 300, false, 64),
            if setup {
                Ctl::primary(WcPress::ProjectSave, text::SAVE.get(lang))
            } else {
                Ctl::button(WcPress::ProjectSave, text::SAVE.get(lang))
            },
        ];
        if setup {
            // The address only goes to the clipboard: the app opens no web page (2026-11-10).
            row.push(Ctl::link(WcPress::ReownCopy, text::REOWN_COPY.get(lang)));
        }
        items.push(Item::LabeledRow("Reown Project ID".to_owned(), row));
        if !setup {
            items.push(Item::Help(text::PROJECT_HELP.get(lang).to_owned()));
        }
    }

    fn wc_session_cards(&self, items: &mut Vec<Item>) {
        let mut rows = self.wc.rows.borrow_mut();
        rows.clear();
        if self.wc.sessions.is_empty() {
            return;
        }
        let lang = self.settings.language;
        let labels = self.own_accounts();
        for session in &self.wc.sessions {
            items.push(Item::CardStart(Some(
                text::SESSION_TITLE.fill(lang, [&session.peer.display_name(lang)]),
            )));
            items.push(Item::Field(
                text::SITE_URL.get(lang).to_owned(),
                crate::walletconnect::text::CLAIMED.fill(lang, [&session.peer.display_url(lang)]),
            ));
            if !session.acknowledged {
                // Approved here, not yet confirmed by the dApp (spec/13 §5.3): never shown as
                // simply "connected" while the dApp may not have it.
                items.push(Item::Field(
                    text::STATUS.get(lang).to_owned(),
                    text::UNACKNOWLEDGED.get(lang).to_owned(),
                ));
            }
            let tone = match session.verify {
                VerifyStatus::Valid => None,
                VerifyStatus::Unknown => Some(Tone::Warn),
                VerifyStatus::Invalid | VerifyStatus::Scam => Some(Tone::HighRisk),
            };
            let verify = format!("Verify: {}", session.verify.label(lang));
            match tone {
                Some(tone) => items.push(Item::Banner(verify, tone)),
                None => items.push(Item::Field(
                    "Verify".to_owned(),
                    session.verify.label(lang).to_owned(),
                )),
            }
            let chains: Vec<String> = session
                .chains
                .iter()
                .map(|id| {
                    self.settings
                        .evm_chain_name_in(lang, *id)
                        .unwrap_or_else(|| format!("eip155:{id}"))
                })
                .collect();
            items.push(Item::Field(
                text::NETWORK.get(lang).to_owned(),
                chains.join(", "),
            ));
            items.push(Item::Field(
                text::CREATED.get(lang).to_owned(),
                local_time(&self.facts(), session.created),
            ));
            items.push(Item::Field(
                text::EXPIRY.get(lang).to_owned(),
                local_time(&self.facts(), session.expiry),
            ));
            // Under the times, before the accounts — where the site cards have it (2026-11-12).
            if let Some(press) =
                screen_rows::row(rows.len(), screen_rows::WC_SESSIONS).map(WcPress::Disconnect)
            {
                rows.push(session.topic);
                items.push(Item::Row(vec![
                    Ctl::danger(press, text::DISCONNECT.get(lang)).compact(),
                ]));
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
            WcPress::DisconnectAll,
            text::DISCONNECT_ALL.get(lang),
        )]));
    }
}
