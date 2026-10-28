//! Solana screen contents (M7; spec/04 §2.6–§2.8, §2.10, §2.11, spec/07 §3.3, §12.3): the S10
//! Solana tab, the SOL send form and its result, receive, the S15 Solana section, the recovery
//! scan and the Solana part of the address book. Addresses are always shown in full, in
//! 4-character groups (spec/07 §12.3); activity addresses have no copy or select buttons.

use yw_core::sol::address::grouped;
use yw_core::sol::recipient::KnownKind;
use yw_core::sol::rent::format_raw;
use yw_core::sol::{SolAddress, SolCluster};

use crate::app::{App, AppMode};
use crate::meta::Tab;
use crate::ui::main_window::{Ctl, Item, Tone};

/// Command ids of the Solana screens (7000 and up).
pub mod ids {
    /// Tab `EVM`.
    pub const TAB_EVM: u16 = 7_000;
    /// Tab `Solana`.
    pub const TAB_SOL: u16 = 7_001;
    /// Cluster mainnet radio.
    pub const CLUSTER_MAINNET: u16 = 7_002;
    /// Cluster devnet radio.
    pub const CLUSTER_DEVNET: u16 = 7_003;
    /// 새로고침.
    pub const REFRESH: u16 = 7_004;
    /// 보내기.
    pub const SEND_OPEN: u16 = 7_005;
    /// 받기.
    pub const RECEIVE_OPEN: u16 = 7_006;
    /// 이름 바꾸기.
    pub const RENAME: u16 = 7_007;
    /// 숨기기.
    pub const HIDE: u16 = 7_008;
    /// 계정 추가.
    pub const ADD_ACCOUNT: u16 = 7_009;
    /// 다른 경로 스캔.
    pub const SCAN_OPEN: u16 = 7_010;
    /// Rename edit.
    pub const RENAME_EDIT: u16 = 7_011;
    /// Rename save.
    pub const RENAME_SAVE: u16 = 7_012;
    /// Rename cancel.
    pub const RENAME_CANCEL: u16 = 7_013;
    /// 주소 복사.
    pub const COPY_ADDRESS: u16 = 7_014;
    /// Account radios.
    pub const ACCOUNT_BASE: u16 = 7_200;
    /// Account radio span.
    pub const ACCOUNT_SPAN: u16 = 100;
    /// Recipient edit.
    pub const SEND_TO_EDIT: u16 = 7_020;
    /// Amount edit.
    pub const SEND_AMOUNT_EDIT: u16 = 7_021;
    /// 최대.
    pub const SEND_MAX: u16 = 7_022;
    /// 검토.
    pub const SEND_REVIEW: u16 = 7_023;
    /// 취소.
    pub const SEND_CANCEL: u16 = 7_024;
    /// 주소록에서 선택.
    pub const SEND_PICK: u16 = 7_025;
    /// "다시 보내기" on the result screen (spec/07 §14.3).
    pub const SEND_AGAIN: u16 = 7_026;
    /// Picker rows.
    pub const SEND_PICK_BASE: u16 = 7_030;
    /// Picker span.
    pub const SEND_PICK_SPAN: u16 = 40;
    /// Settings Solana section.
    pub const SECTION_SOL: u16 = 7_100;
    /// Fee cap edit.
    pub const FEE_CAP_EDIT: u16 = 7_101;
    /// CU price cap edit.
    pub const CU_PRICE_EDIT: u16 = 7_102;
    /// Fee settings save.
    pub const FEE_SAVE: u16 = 7_103;
    /// Fee settings defaults.
    pub const FEE_DEFAULT: u16 = 7_104;
    /// Settings cluster mainnet.
    pub const SET_MAINNET: u16 = 7_105;
    /// Settings cluster devnet.
    pub const SET_DEVNET: u16 = 7_106;
    /// Scan: confirm and start.
    pub const SCAN_START: u16 = 7_110;
    /// Scan rows (2 ids per row: 계정 추가, 표준 계정으로 이동).
    pub const SCAN_ROW_BASE: u16 = 7_120;
    /// Scan rows span.
    pub const SCAN_ROW_SPAN: u16 = 240;
    /// Book address edit.
    pub const BOOK_ADDR_EDIT: u16 = 7_400;
    /// Book label edit.
    pub const BOOK_LABEL_EDIT: u16 = 7_401;
    /// Book verified check.
    pub const BOOK_VERIFIED: u16 = 7_402;
    /// Book add.
    pub const BOOK_SAVE: u16 = 7_403;
    /// Book rows (삭제).
    pub const BOOK_ROW_BASE: u16 = 7_410;
    /// Book rows span.
    pub const BOOK_ROW_SPAN: u16 = 500;
}

fn local_time(unix_ms: u64) -> String {
    let wall = yw_win::time::local_wall_ms(unix_ms);
    let text = crate::logging::format_utc(wall.unwrap_or(unix_ms));
    let short = text.get(..16).unwrap_or(&text).replace('T', " ");
    if wall.is_some() {
        short
    } else {
        format!("{short} UTC")
    }
}

fn status_word(word: &str) -> &'static str {
    match word {
        "succeeded" => "성공",
        "failed" => "실패",
        "expired" => "만료 (전송되지 않음)",
        _ => "종결",
    }
}

impl App {
    /// The chain tab row of S10 (spec/04 §2.6).
    pub fn tab_row(&self, items: &mut Vec<Item>) {
        let tab = self.meta.as_ref().map_or(Tab::Evm, |meta| meta.prefs.tab);
        items.push(Item::LabeledRow(
            "체인".to_owned(),
            vec![
                Ctl::radio(ids::TAB_EVM, "EVM", tab == Tab::Evm, true),
                Ctl::radio(ids::TAB_SOL, "Solana", tab == Tab::Sol, false),
                Ctl::radio(
                    crate::ui::screens_btc::ids::TAB_BTC,
                    "Bitcoin",
                    tab == Tab::Btc,
                    false,
                ),
            ],
        ));
    }

    fn sol_cluster_banner(&self, items: &mut Vec<Item>) {
        if self.sol_cluster() == SolCluster::Devnet {
            items.push(Item::Banner(
                "Solana devnet (테스트) — 실제 자산이 아닙니다".to_owned(),
                Tone::Testnet,
            ));
        }
    }

    /// The S10 Solana tab.
    #[expect(clippy::too_many_lines, reason = "the S10 Solana sections in order")]
    pub fn sol_main_screen(&self, items: &mut Vec<Item>) {
        let cluster = self.sol_cluster();
        items.push(Item::Title("Solana".to_owned()));
        items.push(Item::LabeledRow(
            "클러스터".to_owned(),
            vec![
                Ctl::radio(
                    ids::CLUSTER_MAINNET,
                    "Solana mainnet",
                    cluster == SolCluster::Mainnet,
                    true,
                ),
                Ctl::radio(
                    ids::CLUSTER_DEVNET,
                    "Solana devnet (테스트)",
                    cluster == SolCluster::Devnet,
                    false,
                ),
            ],
        ));
        self.sol_cluster_banner(items);
        if self.sol_journal_damaged() {
            items.push(Item::Banner(
                "거래 저널의 Solana 기록이 손상되어 Solana 보내기를 멈췄습니다. (E-VLT-006)"
                    .to_owned(),
                Tone::Danger,
            ));
        }
        let network = crate::network::NetworkId::Solana(self.settings.solana.cluster);
        let rpc = if self.sol_endpoint(cluster).is_err() {
            "엔드포인트 없음 (E-KEY-005)".to_owned()
        } else if let Some(code) = self.sol.balance_error.get(&cluster) {
            format!("오류 {}", code.code())
        } else if self.sol.balances.keys().any(|(known, _)| *known == cluster) {
            "연결됨 (genesis 확인)".to_owned()
        } else {
            "확인 전".to_owned()
        };
        items.push(Item::Muted(format!("RPC ({network}): {rpc}")));
        let mut row = vec![
            Ctl::button(ids::REFRESH, "새로고침"),
            Ctl::button(ids::SCAN_OPEN, "다른 경로 스캔"),
        ];
        if self.sol_endpoint(cluster).is_err() {
            row.push(Ctl::button(
                crate::ui::screens::ids::SECTION_NETWORK,
                "설정에서 URL 입력",
            ));
        }
        items.push(Item::Row(row));
        items.push(Item::Rule);
        items.push(Item::Text("계정 (m/44'/501'/i'/0')".to_owned()));
        let rows = self.sol_account_rows();
        if rows.is_empty() {
            items.push(Item::Muted(if self.sol.creating {
                "Solana 계정을 만드는 중…".to_owned()
            } else {
                "Solana 계정이 없습니다.".to_owned()
            }));
        }
        let selected = self.sol_selected().map(|(index, ..)| index);
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        for (row, (index, label, address)) in rows.into_iter().enumerate() {
            let is_selected = selected == Some(index);
            items.push(Item::Row(vec![
                Ctl::radio(
                    ids::ACCOUNT_BASE.saturating_add(u16::try_from(row).unwrap_or(0)),
                    &label,
                    is_selected,
                    row == 0,
                )
                .width(360),
            ]));
            items.push(Item::Mono(grouped(&address)));
            let balance = self.sol_balance(&address).map_or_else(
                || "잔액 알 수 없음".to_owned(),
                |lamports| {
                    format!(
                        "잔액 {} ({} lamports, RPC finalized)",
                        App::sol_text(lamports),
                        format_raw(lamports)
                    )
                },
            );
            items.push(Item::Muted(format!("m/44'/501'/{index}'/0' · {balance}")));
            if is_selected {
                if self.sol.rename == Some(index) {
                    items.push(Item::Row(vec![
                        Ctl::edit(ids::RENAME_EDIT, &label, 260, false, 64),
                        Ctl::button(ids::RENAME_SAVE, "저장"),
                        Ctl::button(ids::RENAME_CANCEL, "취소"),
                    ]));
                } else {
                    items.push(Item::Row(vec![
                        Ctl::button(ids::SEND_OPEN, "보내기").enabled(unlocked),
                        Ctl::button(ids::RECEIVE_OPEN, "받기"),
                        Ctl::button(ids::RENAME, "이름 바꾸기"),
                        Ctl::button(ids::HIDE, "숨기기").enabled(index != 0),
                    ]));
                }
            }
            items.push(Item::Gap(4));
        }
        items.push(Item::Row(vec![
            Ctl::button(ids::ADD_ACCOUNT, "계정 추가").enabled(
                !self.sol.creating
                    && self
                        .meta
                        .as_ref()
                        .and_then(crate::meta::Meta::next_sol_index)
                        .is_some(),
            ),
        ]));
        items.push(Item::Rule);
        items.push(Item::Text("활동 (이 지갑이 보낸 거래)".to_owned()));
        let mut shown = 0_usize;
        for record in self.sol_records() {
            if record.cluster != cluster {
                continue;
            }
            let core = record.core();
            items.push(Item::Text(format!(
                "{} · {} · {}",
                local_time(record.signed_at_ms),
                core.map_or_else(String::new, |core| self.sol_label(&core.from.to_base58())),
                core.map_or_else(String::new, |core| {
                    yw_core::sol::display::transfer_title(record.cluster, &core)
                })
            )));
            items.push(Item::Muted(format!(
                "상태: {}",
                self.sol_record_status(&record)
            )));
            if let Some(core) = core {
                items.push(Item::Muted(format!("받는 주소 {}", grouped(&core.to))));
            }
            items.push(Item::Mono(record.tx_id()));
            shown = shown.saturating_add(1);
        }
        if let Some(meta) = self.meta.as_ref() {
            for entry in meta.activity_of(cluster.network_id()) {
                if shown >= crate::app_sol::SOL_MAX_ACTIVITY_ROWS {
                    break;
                }
                items.push(Item::Text(format!(
                    "{} · {} · {}",
                    local_time(entry.time_unix_ms),
                    self.sol_label(&entry.account),
                    entry.title
                )));
                items.push(Item::Muted(format!(
                    "상태: {} · 받는 주소 {}",
                    status_word(&entry.status),
                    SolAddress::parse(&entry.counterparty)
                        .map_or_else(|_| entry.counterparty.clone(), |address| grouped(&address))
                )));
                items.push(Item::Mono(entry.tx_id.clone()));
                shown = shown.saturating_add(1);
            }
        }
        if shown == 0 {
            items.push(Item::Muted("아직 보낸 거래가 없습니다.".to_owned()));
        }
    }

    /// The SOL send form.
    #[expect(clippy::too_many_lines, reason = "the send-form fields in order")]
    pub fn sol_send_screen(&self, items: &mut Vec<Item>) {
        let cluster = self.sol_cluster();
        items.push(Item::Title(format!("보내기 — {}", cluster.display_name())));
        self.sol_cluster_banner(items);
        let form = &self.sol.send;
        if let Some(info) = &form.info {
            items.push(Item::Banner(info.clone(), Tone::Warn));
        }
        if self.sol_journal_damaged() {
            items.push(Item::Banner(
                "거래 저널의 Solana 기록이 손상되어 Solana 보내기를 멈췄습니다. (E-VLT-006)"
                    .to_owned(),
                Tone::Danger,
            ));
        }
        let Some((source, from, label)) = self.sol_form_sender() else {
            items.push(Item::Muted("계정을 불러오는 중…".to_owned()));
            return;
        };
        if let Some(record) = self.sol_pending(cluster, &from) {
            items.push(Item::Banner(
                "이 계정의 이전 전송을 확인 중입니다. 확정된 뒤 보낼 수 있습니다.".to_owned(),
                Tone::Warn,
            ));
            items.push(Item::Muted(self.sol_record_status(&record)));
            items.push(Item::Mono(record.tx_id()));
        }
        items.push(Item::Text(format!("보내는 계정: {label}")));
        items.push(Item::Mono(grouped(&from)));
        let balance = self
            .sol_balance(&from)
            .map_or_else(String::new, |lamports| {
                format!(" · 잔액 {} (RPC 참고)", App::sol_text(lamports))
            });
        items.push(Item::Muted(format!("{}{balance}", source.path_text())));
        if form.moving.is_some() {
            items.push(Item::Banner(
                "비표준 경로 계정의 자금을 내 표준 계정으로 옮깁니다. 받는 주소와 '보내기 최대'는 바꿀 수 없습니다."
                    .to_owned(),
                Tone::Warn,
            ));
        }
        let mut to_edit = Ctl::edit(ids::SEND_TO_EDIT, &form.to_text, 430, false, 64);
        let mut to_row = Vec::new();
        if form.moving.is_some() {
            to_edit = to_edit.readonly();
            to_row.push(to_edit);
        } else {
            to_row.push(to_edit);
            to_row.push(Ctl::button(ids::SEND_PICK, "주소록에서 선택"));
        }
        items.push(Item::LabeledRow("받는 주소".to_owned(), to_row));
        if form.picker && form.moving.is_none() {
            self.sol_picker_rows(items);
        }
        if let Some(code) = form.recipient_error {
            items.push(Item::Banner(code.text(), Tone::Danger));
        }
        if let Some(check) = &form.check {
            items.push(Item::Mono(grouped(&check.to)));
            if let Some(exact) = &check.exact {
                let note = match exact.kind {
                    KnownKind::Book { verified } => format!(
                        "주소록: {}{}",
                        exact.label,
                        if verified { " ✓ 확인됨" } else { "" }
                    ),
                    KnownKind::Own { index } => {
                        format!("내 계정 #{}: {}", index.saturating_add(1), exact.label)
                    }
                    KnownKind::Sent => "보낸 적 있는 주소".to_owned(),
                };
                items.push(Item::Banner(note, Tone::Info));
            }
            for lookalike in &check.lookalikes {
                let name = match lookalike.kind {
                    KnownKind::Book { .. } => format!("주소록 '{}'", lookalike.label),
                    KnownKind::Own { .. } => format!("내 계정 '{}'", lookalike.label),
                    KnownKind::Sent => "보낸 내역의 주소".to_owned(),
                };
                items.push(Item::Banner(
                    format!(
                        "{name}와(과) 앞 3자 또는 뒤 3자가 같지만 다른 주소입니다. 주소 오염 공격일 수 있습니다. (승인 창 고위험 L03)"
                    ),
                    Tone::Danger,
                ));
                items.push(Item::Mono(grouped(&lookalike.address)));
            }
            if check.off_curve {
                items.push(Item::Banner(
                    "일반 지갑이 아님: 프로그램 소유 주소(PDA)나 토큰 계정일 수 있음 (승인 창 고위험 L02)"
                        .to_owned(),
                    Tone::Danger,
                ));
            }
            if check.first_time {
                items.push(Item::Banner(
                    "처음 보내는 주소입니다. 주소 전체를 확인하고, 큰 금액은 소액 시험 송금 뒤 보내세요."
                        .to_owned(),
                    Tone::Warn,
                ));
            }
        }
        let mut amount_row = vec![
            Ctl::edit(ids::SEND_AMOUNT_EDIT, &form.amount_text, 260, false, 32)
                .enabled(!form.send_max),
        ];
        if form.moving.is_none() {
            amount_row.push(Ctl::check(ids::SEND_MAX, "보내기 최대", form.send_max));
        }
        items.push(Item::LabeledRow("금액 (SOL)".to_owned(), amount_row));
        if form.send_max {
            items.push(Item::Muted(
                "보내기 최대: 잔액 − 최대 수수료를 보내고 이 계정의 SOL 잔액은 0이 됩니다(승인 창에서 확인)."
                    .to_owned(),
            ));
        }
        if let Some(code) = form.amount_error {
            items.push(Item::Banner(code.text(), Tone::Danger));
        }
        items.push(Item::Muted(format!(
            "수수료는 지갑이 계산합니다: 기본 5,000 lamports + 우선 수수료(CU 한도 {}), 상한 {} lamports.",
            yw_core::sol::fee::SOL_TRANSFER_CU_LIMIT,
            format_raw(self.settings.solana.max_fee_lamports)
        )));
        items.push(Item::Row(vec![
            Ctl::button(ids::SEND_REVIEW, "검토").enabled(self.sol_can_review()),
            Ctl::button(ids::SEND_CANCEL, "취소"),
        ]));
    }

    fn sol_picker_rows(&self, items: &mut Vec<Item>) {
        let entries = self.sol_picker_entries();
        if entries.is_empty() {
            items.push(Item::Muted(
                "일치하는 주소록·내 계정이 없습니다.".to_owned(),
            ));
        }
        for (index, (label, address)) in entries.into_iter().enumerate() {
            items.push(Item::Row(vec![Ctl::button(
                ids::SEND_PICK_BASE.saturating_add(u16::try_from(index).unwrap_or(0)),
                &label,
            )]));
            items.push(Item::Mono(grouped(&address)));
        }
    }

    /// Picker entries: address book and own accounts only (spec/07 §12.3), filtered by the text.
    #[must_use]
    pub fn sol_picker_entries(&self) -> Vec<(String, SolAddress)> {
        let filter = self.sol.send.to_text.trim().to_owned();
        self.sol_known()
            .into_iter()
            .filter_map(|entry| match entry.kind {
                KnownKind::Book { .. } => Some((format!("주소록: {}", entry.label), entry.address)),
                KnownKind::Own { .. } => Some((format!("내 계정: {}", entry.label), entry.address)),
                KnownKind::Sent => None,
            })
            .filter(|(label, address)| {
                filter.is_empty()
                    || address.to_base58().contains(&filter)
                    || label.contains(&filter)
            })
            .take(usize::from(ids::SEND_PICK_SPAN))
            .collect()
    }

    /// The SOL send result.
    pub fn sol_send_result_screen(&self, items: &mut Vec<Item>) {
        items.push(Item::Title("보내기 결과".to_owned()));
        if let Some((cluster, signature)) = self.sol.sent {
            items.push(Item::Text(
                "서명하고 저널에 기록한 뒤 전송했습니다.".to_owned(),
            ));
            items.push(Item::Mono(yw_core::codec::base58::base58_encode(
                &signature,
            )));
            let status = self
                .sol_records()
                .iter()
                .find(|record| record.signature() == signature)
                .map_or_else(
                    || "종결 (활동 참고)".to_owned(),
                    |record| self.sol_record_status(record),
                );
            items.push(Item::Muted(format!(
                "상태: {status} ({})",
                cluster.display_name()
            )));
        }
        let mut row = Vec::new();
        if self.sol_can_resend() {
            row.push(Ctl::button(ids::SEND_AGAIN, "다시 보내기"));
            items.push(Item::Muted(
                "같은 받는 주소·금액으로 보내기 화면을 다시 엽니다. 새로 검토하고 새로 승인해야 합니다(이전 승인은 쓰지 않음).".to_owned(),
            ));
        }
        row.push(Ctl::button(crate::ui::screens::ids::BACK_MAIN, "메인으로"));
        items.push(Item::Row(row));
    }

    /// S12 for Solana: full address, QR = the base58 text, path, cluster.
    pub fn sol_receive_screen(&self, items: &mut Vec<Item>) {
        items.push(Item::Title("받기 — Solana".to_owned()));
        if self.mode == AppMode::BackupPending {
            items.push(Item::Banner(
                "백업 확인 전입니다. 확인을 마치기 전에는 큰 금액을 받지 마세요.".to_owned(),
                Tone::Warn,
            ));
        }
        let Some((index, label, address)) = self.sol_selected() else {
            items.push(Item::Muted("계정을 불러오는 중…".to_owned()));
            return;
        };
        items.push(Item::Text(format!(
            "{label} · {}",
            self.sol_cluster().display_name()
        )));
        if self.sol_cluster() == SolCluster::Devnet {
            items.push(Item::Banner(
                "devnet(테스트) 주소입니다. 주소 자체는 mainnet과 같습니다.".to_owned(),
                Tone::Testnet,
            ));
        }
        items.push(Item::Mono(grouped(&address)));
        items.push(Item::Muted(format!("m/44'/501'/{index}'/0'")));
        items.push(Item::Qr(address.to_base58()));
        items.push(Item::Row(vec![
            Ctl::button(ids::COPY_ADDRESS, "주소 복사"),
            Ctl::button(crate::ui::screens::ids::BACK_MAIN, "← 메인"),
        ]));
        items.push(Item::Muted(
            "주소를 복사한 뒤 붙여넣은 곳에서 주소 전체를 확인하세요.".to_owned(),
        ));
    }

    /// S15 Solana section (spec/07 §10, §3.3).
    pub fn sol_settings_section(&self, items: &mut Vec<Item>) {
        let solana = &self.settings.solana;
        items.push(Item::Title("Solana".to_owned()));
        items.push(Item::LabeledRow(
            "클러스터".to_owned(),
            vec![
                Ctl::radio(
                    ids::SET_MAINNET,
                    "mainnet",
                    solana.cluster == crate::network::SolCluster::Mainnet,
                    true,
                ),
                Ctl::radio(
                    ids::SET_DEVNET,
                    "devnet (테스트)",
                    solana.cluster == crate::network::SolCluster::Devnet,
                    false,
                ),
            ],
        ));
        items.push(Item::Muted(
            "엔드포인트는 '네트워크' 구역의 solana:mainnet·solana:devnet URL입니다.".to_owned(),
        ));
        items.push(Item::LabeledRow(
            "수수료 상한 (lamports)".to_owned(),
            vec![Ctl::edit(
                ids::FEE_CAP_EDIT,
                &solana.max_fee_lamports.to_string(),
                200,
                false,
                12,
            )],
        ));
        items.push(Item::LabeledRow(
            "CU 가격 상한 (micro-lamports/CU)".to_owned(),
            vec![Ctl::edit(
                ids::CU_PRICE_EDIT,
                &solana.max_cu_price_micro.to_string(),
                200,
                false,
                12,
            )],
        ));
        items.push(Item::Row(vec![
            Ctl::button(ids::FEE_SAVE, "저장"),
            Ctl::button(ids::FEE_DEFAULT, "기본값으로"),
        ]));
        items.push(Item::Muted(
            "수수료 상한 10,000–10,000,000, CU 가격 상한 0–100,000,000. 우선 수수료 가격은 최근 값의 p75와 두 상한 중 작은 값입니다."
                .to_owned(),
        ));
        items.push(Item::Rule);
        items.push(Item::Row(vec![Ctl::button(
            ids::SCAN_OPEN,
            "다른 경로 스캔",
        )]));
    }

    /// The recovery scan screen (spec/07 §3.3).
    pub fn sol_scan_screen(&self, items: &mut Vec<Item>) {
        use crate::app_sol::ScanStage;
        items.push(Item::Row(vec![Ctl::button(
            crate::ui::screens::ids::BACK_MAIN,
            "← 메인",
        )]));
        items.push(Item::Title(format!(
            "다른 경로 스캔 — {}",
            self.sol_cluster().display_name()
        )));
        let scan = &self.sol.scan;
        if let Some(message) = &scan.message {
            items.push(Item::Banner(message.clone(), Tone::Danger));
        }
        match scan.stage {
            ScanStage::Notice => {
                items.push(Item::Text(
                    "다른 지갑(Ledger Live, solana-keygen 등)의 경로 m/44'/501'/i', m/44'/501', BIP39 seed[0..32]와 표준 경로 m/44'/501'/i'/0'의 계정 0–49를 조회합니다(연속 5개가 비면 중단). 읽기 전용이며 서명하지 않습니다."
                        .to_owned(),
                ));
                items.push(Item::Banner(
                    "조회하는 모든 주소가 RPC 공급자(설정한 solana 엔드포인트의 운영자)에 전달되어 서로 연결될 수 있습니다."
                        .to_owned(),
                    Tone::Warn,
                ));
                items.push(Item::Row(vec![
                    Ctl::button(ids::SCAN_START, "알겠습니다 — 스캔 시작")
                        .enabled(matches!(self.mode, AppMode::Unlocked { .. })),
                ]));
            }
            ScanStage::Deriving | ScanStage::Running => {
                items.push(Item::Muted("조회하는 중…".to_owned()));
            }
            ScanStage::Done => {
                let rows = self.sol_scan_rows();
                if rows.is_empty() {
                    items.push(Item::Muted(
                        "잔액이 있는 다른 경로 계정이나 추가할 표준 계정이 없습니다.".to_owned(),
                    ));
                }
                for (index, row) in rows.iter().enumerate() {
                    let base = ids::SCAN_ROW_BASE
                        .saturating_add(u16::try_from(index).unwrap_or(0).saturating_mul(2));
                    items.push(Item::Text(format!(
                        "{} · {} (RPC 참고)",
                        row.source.path_text(),
                        App::sol_text(row.balance)
                    )));
                    items.push(Item::Mono(grouped(&row.address)));
                    if row.source.is_standard() {
                        items.push(Item::Row(vec![Ctl::button(base, "계정 추가")]));
                    } else {
                        items.push(Item::Row(vec![
                            Ctl::button(base.saturating_add(1), "표준 계정으로 이동")
                                .enabled(matches!(self.mode, AppMode::Unlocked { .. })),
                        ]));
                    }
                }
                items.push(Item::Muted(
                    "비표준 경로 자금은 선택한 표준 계정으로 '보내기 최대'만 할 수 있습니다(승인 창 L07)."
                        .to_owned(),
                ));
            }
        }
    }

    /// The Solana part of S14.
    pub fn sol_book_section(&self, items: &mut Vec<Item>) {
        items.push(Item::Rule);
        items.push(Item::Title("Solana 주소록".to_owned()));
        let form = &self.sol.book;
        if let Some(message) = &form.message {
            items.push(Item::Banner(message.clone(), Tone::Danger));
        }
        items.push(Item::LabeledRow(
            "주소".to_owned(),
            vec![Ctl::edit(
                ids::BOOK_ADDR_EDIT,
                &form.address,
                430,
                false,
                64,
            )],
        ));
        items.push(Item::LabeledRow(
            "이름".to_owned(),
            vec![Ctl::edit(ids::BOOK_LABEL_EDIT, &form.label, 260, false, 64)],
        ));
        items.push(Item::Row(vec![Ctl::check(
            ids::BOOK_VERIFIED,
            "다른 경로(전화·대면 등)로 이 주소를 확인했습니다",
            form.verified,
        )]));
        items.push(Item::Row(vec![Ctl::button(ids::BOOK_SAVE, "추가")]));
        let entries = self
            .meta
            .as_ref()
            .map(crate::meta::Meta::sol_book)
            .unwrap_or_default();
        if entries.is_empty() {
            items.push(Item::Muted("Solana 주소록이 비어 있습니다.".to_owned()));
        }
        for (index, entry) in entries.iter().enumerate() {
            let verified = if entry.verified { " ✓ 확인됨" } else { "" };
            items.push(Item::Text(format!("{}{verified}", entry.label)));
            items.push(Item::Mono(SolAddress::parse(&entry.address).map_or_else(
                |_| entry.address.clone(),
                |address| grouped(&address),
            )));
            items.push(Item::Row(vec![Ctl::button(
                ids::BOOK_ROW_BASE.saturating_add(u16::try_from(index).unwrap_or(0)),
                "삭제",
            )]));
        }
    }

    /// Whether the main screen shows the Solana tab.
    #[must_use]
    pub fn sol_tab_active(&self) -> bool {
        self.meta
            .as_ref()
            .is_some_and(|meta| meta.prefs.tab == Tab::Sol)
    }
}
