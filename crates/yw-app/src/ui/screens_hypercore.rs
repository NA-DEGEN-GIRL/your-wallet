//! `HyperCore` screen contents (spec/11 §8): the card on the EVM tab (S10), the transfer form
//! S-HC and the settings block under `EVM 체인`.

use yw_core::approval::escape_untrusted;
use yw_core::hypercore::{HcNetwork, WITHDRAW_FEE_USDC};

use crate::app::App;
use crate::app_hypercore::{HcAsset, HcFormKind};
use crate::ui::main_window::{Ctl, Item, Tone};

/// Command ids (13,450–13,499).
pub mod ids {
    /// 새로고침.
    pub const REFRESH: u16 = 13_450;
    /// 보내기(Core).
    pub const OPEN_SEND: u16 = 13_451;
    /// 현물↔선물 이동.
    pub const OPEN_CLASS: u16 = 13_452;
    /// Arbitrum으로 출금.
    pub const OPEN_WITHDRAW: u16 = 13_453;
    /// `HyperEVM으로` 이동.
    pub const OPEN_TO_EVM: u16 = 13_454;
    /// `HyperEVM에서` Core로 이동.
    pub const OPEN_FROM_EVM: u16 = 13_455;
    /// Network radio: mainnet (card and settings).
    pub const NET_MAINNET: u16 = 13_456;
    /// Network radio: testnet (card and settings).
    pub const NET_TESTNET: u16 = 13_457;
    /// Recipient edit.
    pub const TO_EDIT: u16 = 13_460;
    /// Amount edit.
    pub const AMOUNT_EDIT: u16 = 13_461;
    /// Look-alike acknowledgement.
    pub const ACK: u16 = 13_462;
    /// 검토.
    pub const REVIEW: u16 = 13_463;
    /// 취소.
    pub const CANCEL: u16 = 13_464;
    /// Direction spot → perp.
    pub const DIR_TO_PERP: u16 = 13_465;
    /// Direction perp → spot.
    pub const DIR_TO_SPOT: u16 = 13_466;
    /// Asset radio: perp USDC.
    pub const ASSET_PERP: u16 = 13_467;
    /// Settings: card on/off.
    pub const ENABLED: u16 = 13_490;
    /// Settings: testnet API edit.
    pub const API_EDIT: u16 = 13_491;
    /// Settings: save the testnet API.
    pub const API_SAVE: u16 = 13_492;
    /// Settings: official testnet API.
    pub const API_DEFAULT: u16 = 13_493;
    /// Asset radios of spot tokens (row = position in the list).
    pub const ASSET_BASE: u16 = 13_470;
    /// Asset radio span.
    pub const ASSET_SPAN: u16 = 20;

    /// Every fixed id of this module.
    pub const FIXED: &[u16] = &[
        REFRESH,
        OPEN_SEND,
        OPEN_CLASS,
        OPEN_WITHDRAW,
        OPEN_TO_EVM,
        OPEN_FROM_EVM,
        NET_MAINNET,
        NET_TESTNET,
        TO_EDIT,
        AMOUNT_EDIT,
        ACK,
        REVIEW,
        CANCEL,
        DIR_TO_PERP,
        DIR_TO_SPOT,
        ASSET_PERP,
        ENABLED,
        API_EDIT,
        API_SAVE,
        API_DEFAULT,
    ];
}

fn local_time(unix_ms: u64) -> String {
    let wall = yw_win::time::local_wall_ms(unix_ms);
    let text = crate::logging::format_utc(wall.unwrap_or(unix_ms));
    let short = text.get(..19).unwrap_or(&text).replace('T', " ");
    if wall.is_some() {
        short
    } else {
        format!("{short} UTC")
    }
}

fn network_row(network: HcNetwork) -> Item {
    Item::Row(vec![
        Ctl::radio(
            ids::NET_MAINNET,
            "메인넷",
            network == HcNetwork::Mainnet,
            true,
        ),
        Ctl::radio(
            ids::NET_TESTNET,
            "테스트넷",
            network == HcNetwork::Testnet,
            false,
        ),
    ])
}

impl App {
    /// The S10 `HyperCore` card (balances, actions, session activity).
    #[expect(
        clippy::too_many_lines,
        reason = "the card's sections in display order"
    )]
    pub fn hc_card(&self, items: &mut Vec<Item>) {
        if !self.hc_visible() {
            return;
        }
        let network = self.hc_network();
        items.push(Item::CardStart(Some(format!(
            "Hyperliquid {}",
            network.label()
        ))));
        if network == HcNetwork::Testnet {
            items.push(Item::Banner(
                "테스트넷 — 실제 자산이 아닙니다".to_owned(),
                Tone::Testnet,
            ));
        }
        items.push(network_row(network));
        items.push(Item::Help(
            "같은 EVM 주소의 HyperCore(Hyperliquid L1) 잔액입니다. 이 지갑은 전송만 하고 거래(주문)는 하지 않습니다."
                .to_owned(),
        ));
        match self.hc_balances() {
            Some(balances) => {
                items.push(Item::Field(
                    "선물(perp) USDC".to_owned(),
                    format!(
                        "계정 가치 {} · 출금 가능 {}{}",
                        balances.perp.account_value,
                        balances.perp.withdrawable,
                        if balances.perp.positions > 0 {
                            format!(" · 열린 포지션 {}개", balances.perp.positions)
                        } else {
                            String::new()
                        }
                    ),
                ));
                let rows = self.hc_spot_rows();
                if rows.is_empty() {
                    items.push(Item::Field("현물(spot)".to_owned(), "없음".to_owned()));
                }
                for (index, coin, total) in rows {
                    let hold = balances
                        .spot
                        .iter()
                        .find(|balance| balance.token == index)
                        .map(|balance| balance.hold.clone())
                        .filter(|hold| {
                            crate::app_hypercore::api_units(hold, 18)
                                .is_some_and(|units| !units.is_zero())
                        });
                    items.push(Item::Field(
                        format!("현물 {}", escape_untrusted(&coin).text),
                        match hold {
                            Some(hold) => format!("{total} (주문 보류 {hold})"),
                            None => total,
                        },
                    ));
                }
            }
            None if self.hypercore.loading => items.push(Item::Muted("불러오는 중…".to_owned())),
            None => items.push(Item::Muted("잔액을 아직 불러오지 않았습니다.".to_owned())),
        }
        if let Some(error) = &self.hypercore.error {
            items.push(Item::Banner(error.clone(), Tone::Warn));
        }
        items.push(Item::Row(vec![
            Ctl::button(ids::OPEN_SEND, "보내기(Core)"),
            Ctl::button(ids::OPEN_CLASS, "현물↔선물 이동"),
            Ctl::button(ids::OPEN_WITHDRAW, "Arbitrum으로 출금"),
        ]));
        items.push(Item::Row(vec![
            Ctl::button(ids::OPEN_TO_EVM, "HyperEVM으로 이동"),
            Ctl::button(ids::OPEN_FROM_EVM, "HyperEVM에서 Core로 이동"),
            Ctl::button(ids::REFRESH, "새로고침"),
        ]));
        let rows: Vec<_> = self
            .hypercore
            .activity
            .iter()
            .filter(|row| row.network == network)
            .collect();
        if !rows.is_empty() {
            items.push(Item::Rule);
            items.push(Item::Subtitle("HyperCore 활동 (이번 실행)".to_owned()));
            for row in rows {
                let to = row
                    .to
                    .map(|to| format!(" → {}", to.to_checksum()))
                    .unwrap_or_default();
                items.push(Item::Text(format!(
                    "{} · {} · {}{to}",
                    local_time(row.nonce),
                    row.kind.korean(),
                    row.amount
                )));
                items.push(Item::Help(format!(
                    "상태: {} · nonce {}",
                    row.status.text(),
                    row.nonce
                )));
            }
        }
        items.push(Item::CardEnd);
    }

    /// S-HC.
    #[expect(
        clippy::too_many_lines,
        reason = "one block per form kind of spec/11 §8"
    )]
    pub fn hc_screen(&self, items: &mut Vec<Item>) {
        let network = self.hc_network();
        let form = &self.hypercore.form;
        items.push(crate::ui::screens::back_main());
        let title = match form.kind {
            HcFormKind::Send => "보내기 (HyperCore)",
            HcFormKind::ClassTransfer => "현물↔선물 USDC 이동",
            HcFormKind::Withdraw => "Arbitrum으로 USDC 출금",
            HcFormKind::ToEvm => "HyperEVM으로 이동",
        };
        items.push(Item::Title(format!("{title} — {}", network.label())));
        if network == HcNetwork::Testnet {
            items.push(Item::Banner(
                "테스트넷 — 실제 자산이 아닙니다".to_owned(),
                Tone::Testnet,
            ));
        }
        if let Some(info) = &form.info {
            items.push(Item::Banner(info.clone(), Tone::Warn));
        }
        if let Some((account, _, label)) = self.selected_account() {
            items.push(Item::CardStart(Some("서명 계정".to_owned())));
            items.push(Item::Text(label));
            items.push(Item::Mono(account.to_checksum()));
            items.push(Item::CardEnd);
        }
        items.push(Item::CardStart(Some("내용".to_owned())));
        match form.kind {
            HcFormKind::Send => {
                let mut rows = vec![Item::Row(vec![Ctl::radio(
                    ids::ASSET_PERP,
                    &format!(
                        "USDC — 선물(perp) 잔액 (출금 가능 {})",
                        self.hc_balances()
                            .map_or_else(|| "?".to_owned(), |b| b.perp.withdrawable.clone())
                    ),
                    form.asset == HcAsset::PerpUsdc,
                    true,
                )])];
                for (row, (index, coin, total)) in self.hc_spot_rows().into_iter().enumerate() {
                    let Some(id) = u16::try_from(row)
                        .ok()
                        .filter(|row| *row < ids::ASSET_SPAN)
                        .map(|row| ids::ASSET_BASE.saturating_add(row))
                    else {
                        break;
                    };
                    rows.push(Item::Row(vec![Ctl::radio(
                        id,
                        &format!("현물 {} — {total}", escape_untrusted(&coin).text),
                        form.asset == HcAsset::Spot(index),
                        false,
                    )]));
                }
                items.extend(rows);
                self.hc_recipient_rows(items, "받는 주소 (HyperCore)");
            }
            HcFormKind::ClassTransfer => {
                items.push(Item::Row(vec![
                    Ctl::radio(
                        ids::DIR_TO_PERP,
                        "현물(spot) → 선물(perp)",
                        form.to_perp,
                        true,
                    ),
                    Ctl::radio(
                        ids::DIR_TO_SPOT,
                        "선물(perp) → 현물(spot)",
                        !form.to_perp,
                        false,
                    ),
                ]));
                items.push(Item::Help(
                    "같은 계정 안에서 USDC를 옮깁니다. 받는 주소는 없습니다.".to_owned(),
                ));
            }
            HcFormKind::Withdraw => {
                self.hc_recipient_rows(items, "받는 주소 (Arbitrum One)");
                items.push(Item::Banner(
                    format!(
                        "고정 출금 수수료 {WITHDRAW_FEE_USDC} USDC가 HyperCore에서 빠집니다. Arbitrum One에 USDC로 도착하며 약 5분 걸립니다."
                    ),
                    Tone::Info,
                ));
            }
            HcFormKind::ToEvm => {
                let tokens = self.hc_evm_tokens();
                if tokens.is_empty() {
                    items.push(Item::Muted(
                        "HyperEVM에 연결된 현물 토큰 잔액이 없습니다.".to_owned(),
                    ));
                }
                for (row, token) in tokens.iter().enumerate() {
                    let Some(id) = u16::try_from(row)
                        .ok()
                        .filter(|row| *row < ids::ASSET_SPAN)
                        .map(|row| ids::ASSET_BASE.saturating_add(row))
                    else {
                        break;
                    };
                    items.push(Item::Row(vec![Ctl::radio(
                        id,
                        &format!(
                            "{} (시스템 주소 {})",
                            escape_untrusted(&token.name).text,
                            token.system_address().to_checksum()
                        ),
                        form.asset == HcAsset::Spot(token.index),
                        row == 0,
                    )]));
                }
                items.push(Item::Help(
                    "토큰의 시스템 주소로 보내면 HyperEVM의 같은 주소(이 계정)로 들어갑니다. HyperCore에서 HYPE로 가스(200k gas)를 냅니다."
                        .to_owned(),
                ));
            }
        }
        items.push(Item::LabeledRow(
            "금액".to_owned(),
            vec![Ctl::edit(
                ids::AMOUNT_EDIT,
                &form.amount_text,
                240,
                false,
                40,
            )],
        ));
        if let Some(error) = &form.error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::primary(ids::REVIEW, "검토")
                .enabled(self.hc_can_review() && form.dirty_ms.is_none()),
            Ctl::button(ids::CANCEL, "취소"),
        ]));
    }

    fn hc_recipient_rows(&self, items: &mut Vec<Item>, label: &str) {
        let form = &self.hypercore.form;
        items.push(Item::LabeledRow(
            label.to_owned(),
            vec![Ctl::edit(ids::TO_EDIT, &form.to_text, 430, false, 64)],
        ));
        for note in &form.notes {
            items.push(Item::Banner(
                note.text(),
                if note.needs_ack() {
                    Tone::HighRisk
                } else if note.is_warning() {
                    Tone::Warn
                } else {
                    Tone::Info
                },
            ));
        }
        if form
            .notes
            .iter()
            .any(crate::flow::evm::form::AddressNote::needs_ack)
        {
            items.push(Item::Row(vec![Ctl::check(
                ids::ACK,
                "주소 전체를 직접 확인했습니다",
                form.ack,
            )]));
        }
    }

    /// Settings → `EVM 체인`: the `HyperCore` block.
    pub fn hc_settings_section(&self, items: &mut Vec<Item>) {
        let hypercore = &self.settings.hypercore;
        items.push(Item::CardStart(Some("Hyperliquid HyperCore".to_owned())));
        items.push(Item::Row(vec![Ctl::check(
            ids::ENABLED,
            "EVM 탭에 HyperCore 카드 보이기 (잔액·전송, 거래 없음)",
            hypercore.enabled,
        )]));
        items.push(network_row(hypercore.network));
        items.push(Item::Field(
            "메인넷 API".to_owned(),
            format!("{} (고정)", yw_core::hypercore::MAINNET_API),
        ));
        let text = self
            .hypercore
            .api_text
            .clone()
            .unwrap_or_else(|| hypercore.testnet_api.clone());
        items.push(Item::LabeledRow(
            "테스트넷 API".to_owned(),
            vec![
                Ctl::edit(ids::API_EDIT, &text, 360, false, 256),
                Ctl::button(ids::API_SAVE, "저장"),
                Ctl::button(ids::API_DEFAULT, "공식 주소로"),
            ],
        ));
        items.push(Item::Help(
            "HTTPS만 됩니다. /info와 /exchange가 이 주소 뒤에 붙습니다.".to_owned(),
        ));
        if let Some(message) = &self.hypercore.settings_message {
            items.push(Item::Banner(message.clone(), Tone::Info));
        }
        items.push(Item::CardEnd);
    }

    /// `HyperCore` commands; `false` when `id` is not one of them.
    pub fn on_hc_command(&mut self, id: u16) -> bool {
        match id {
            ids::REFRESH => {
                self.hc_refresh();
                self.refresh();
            }
            ids::OPEN_SEND => self.hc_open_form(HcFormKind::Send),
            ids::OPEN_CLASS => self.hc_open_form(HcFormKind::ClassTransfer),
            ids::OPEN_WITHDRAW => self.hc_open_form(HcFormKind::Withdraw),
            ids::OPEN_TO_EVM => self.hc_open_form(HcFormKind::ToEvm),
            ids::OPEN_FROM_EVM => self.hc_open_from_evm(),
            ids::NET_MAINNET | ids::NET_TESTNET => {
                let network = if id == ids::NET_MAINNET {
                    HcNetwork::Mainnet
                } else {
                    HcNetwork::Testnet
                };
                if network != self.settings.hypercore.network {
                    let mut settings = self.settings.clone();
                    settings.hypercore.network = network;
                    self.save_settings(settings, "hypercore");
                    self.hypercore.balances = None;
                    self.hypercore.error = None;
                    self.hc_refresh();
                }
            }
            ids::ACK => {
                self.hypercore.form.ack = !self.hypercore.form.ack;
                self.refresh();
            }
            ids::REVIEW => self.hc_review(),
            ids::CANCEL => self.set_screen(crate::app::Screen::Main),
            ids::DIR_TO_PERP | ids::DIR_TO_SPOT => {
                self.hypercore.form.to_perp = id == ids::DIR_TO_PERP;
                self.hc_validate();
                self.refresh();
            }
            ids::ASSET_PERP => {
                self.hypercore.form.asset = HcAsset::PerpUsdc;
                self.hc_validate();
                self.refresh();
            }
            ids::ENABLED => {
                let mut settings = self.settings.clone();
                settings.hypercore.enabled = !settings.hypercore.enabled;
                self.save_settings(settings, "hypercore");
                self.hc_refresh();
            }
            ids::API_SAVE | ids::API_DEFAULT => {
                let text = if id == ids::API_DEFAULT {
                    yw_core::hypercore::TESTNET_API.to_owned()
                } else {
                    self.hypercore
                        .api_text
                        .clone()
                        .unwrap_or_else(|| self.settings.hypercore.testnet_api.clone())
                };
                if let Some(api) = crate::settings::validate_hypercore_api(&text) {
                    let mut settings = self.settings.clone();
                    settings.hypercore.testnet_api = api;
                    self.hypercore.api_text = None;
                    self.hypercore.settings_message =
                        Some("테스트넷 API 주소를 저장했습니다.".to_owned());
                    self.save_settings(settings, "hypercore");
                } else {
                    self.hypercore.settings_message =
                        Some("HTTPS 주소가 아닙니다 (https://…, ?·# 없이).".to_owned());
                    self.refresh();
                }
            }
            other => {
                let Some(row) = other
                    .checked_sub(ids::ASSET_BASE)
                    .filter(|row| *row < ids::ASSET_SPAN)
                else {
                    return false;
                };
                let row = usize::from(row);
                let index = match self.hypercore.form.kind {
                    HcFormKind::ToEvm => self.hc_evm_tokens().get(row).map(|token| token.index),
                    _ => self.hc_spot_rows().get(row).map(|(index, ..)| *index),
                };
                if let Some(index) = index {
                    self.hypercore.form.asset = HcAsset::Spot(index);
                    self.hc_validate();
                    self.refresh();
                }
            }
        }
        true
    }

    /// `EN_CHANGE` of a `HyperCore` edit; `false` when `id` is not one of them.
    pub fn on_hc_edit_change(&mut self, id: u16) -> bool {
        if ![ids::TO_EDIT, ids::AMOUNT_EDIT, ids::API_EDIT].contains(&id) {
            return false;
        }
        let text = self.controls.text(id, 512).unwrap_or_default();
        let now = yw_win::time::monotonic_ms();
        match id {
            ids::TO_EDIT => {
                self.hypercore.form.to_text = text;
                self.hypercore.form.dirty_ms = Some(now);
            }
            ids::AMOUNT_EDIT => {
                self.hypercore.form.amount_text = text;
                self.hypercore.form.dirty_ms = Some(now);
            }
            _ => self.hypercore.api_text = Some(text),
        }
        true
    }
}
