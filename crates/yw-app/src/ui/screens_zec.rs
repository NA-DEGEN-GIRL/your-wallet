//! The S10 Zcash tab (spec/12 §11, spec/04 §2.6): enable / network, account and key source,
//! balance, receive (transparent address, QR, the Zashi note), send (t-address, TEX or the
//! transparent receiver of a UA; amount or 최대; review), activity (this wallet's journal
//! records and the address UTXOs). One page, no extra screens.

use yw_core::journal::zec::ZecTxState;
use yw_core::zec::{ZecNetwork, format_zec, format_zec_and_zats};

use crate::app::{App, AppMode};
use crate::app_zec::SourceChoice;
use crate::settings::ZecIndexer;
use crate::ui::main_window::{Ctl, Item, Tone};

/// Command ids of the Zcash tab (8,000–8,099; the map and its checks are `ui::command_ids`).
pub mod ids {
    /// Tab `Zcash`.
    pub const TAB_ZEC: u16 = 8_000;
    /// Enable on mainnet.
    pub const ENABLE_MAINNET: u16 = 8_001;
    /// Enable on testnet.
    pub const ENABLE_TESTNET: u16 = 8_002;
    /// Turn off.
    pub const DISABLE: u16 = 8_003;
    /// 새로고침.
    pub const REFRESH: u16 = 8_004;
    /// 주소 복사.
    pub const COPY_ADDRESS: u16 = 8_005;
    /// QR 보기 / 숨기기.
    pub const QR_TOGGLE: u16 = 8_006;
    /// Recipient edit.
    pub const SEND_TO_EDIT: u16 = 8_007;
    /// Amount edit.
    pub const SEND_AMOUNT_EDIT: u16 = 8_008;
    /// 최대 (check box).
    pub const SEND_MAX: u16 = 8_009;
    /// 검토.
    pub const SEND_REVIEW: u16 = 8_010;
    /// Key source: standard path.
    pub const SOURCE_STANDARD: u16 = 8_011;
    /// Key source: apply.
    pub const SOURCE_APPLY: u16 = 8_012;
    /// Key source: cancel the EVM-key confirmation.
    pub const SOURCE_CANCEL: u16 = 8_013;
    /// UTXO source: node.
    pub const INDEXER_NODE: u16 = 8_014;
    /// UTXO source: Blockbook.
    pub const INDEXER_BB: u16 = 8_015;
    /// Key source: EVM account radios (position in the EVM account list).
    pub const SOURCE_EVM_BASE: u16 = 8_020;
    /// EVM radio span.
    pub const SOURCE_EVM_SPAN: u16 = 16;
    /// `YubiKey` Zcash slot buttons (position in the slot list).
    pub const HW_BASE: u16 = 8_040;
    /// `YubiKey` button span.
    pub const HW_SPAN: u16 = 8;

    const _: () = assert!(SOURCE_EVM_BASE + SOURCE_EVM_SPAN <= HW_BASE);
    const _: () = assert!(HW_BASE + HW_SPAN <= 8_100);

    /// Every fixed id.
    pub const FIXED: [u16; 16] = [
        TAB_ZEC,
        ENABLE_MAINNET,
        ENABLE_TESTNET,
        DISABLE,
        REFRESH,
        COPY_ADDRESS,
        QR_TOGGLE,
        SEND_TO_EDIT,
        SEND_AMOUNT_EDIT,
        SEND_MAX,
        SEND_REVIEW,
        SOURCE_STANDARD,
        SOURCE_APPLY,
        SOURCE_CANCEL,
        INDEXER_NODE,
        INDEXER_BB,
    ];
}

/// T-ZEC-RECEIVE (user text).
pub const T_ZEC_RECEIVE: &str =
    "일반(transparent) 주소입니다 — Zashi 등 비공개 주소로 받으려면 그 지갑에서 받으세요.";
/// T-ZEC-EVM-SHARED: the linkage warning of the EVM-key source.
pub const T_ZEC_EVM_SHARED: &str = "EVM 계정과 같은 키를 쓰면 EVM 주소와 이 Zcash 주소가 같은 공개키라 누구나 두 주소를 한 사람의 것으로 묶을 수 있습니다. 같은 복구 단어를 다른 Zcash 지갑에 넣어도 이 주소는 나오지 않습니다(표준 경로가 아님). 정말 필요할 때만 쓰세요.";

const TEXT_MAX: usize = 1_024;

fn offset(id: u16, base: u16, span: u16) -> Option<u16> {
    id.checked_sub(base).filter(|offset| *offset < span)
}

fn grouped(address: &str) -> String {
    let mut out = String::with_capacity(address.len() + address.len() / 4);
    for (position, character) in address.chars().enumerate() {
        if position > 0 && position % 4 == 0 {
            out.push(' ');
        }
        out.push(character);
    }
    out
}

impl App {
    /// The `YubiKey` Zcash slot indices of the current network (`KeyRole::Zec`).
    fn zec_hw_slots(&self) -> Vec<u32> {
        let network = self.zec_network();
        let mut out: Vec<u32> = Vec::new();
        for slot in self.card.records.iter().flat_map(|record| &record.slots) {
            if let yw_core::yubikey::plan::KeyRole::Zec {
                network: held,
                index,
            } = slot.role
                && held == network
                && !out.contains(&index)
            {
                out.push(index);
            }
        }
        out.truncate(usize::from(ids::HW_SPAN));
        out
    }

    fn zec_evm_indices(&self) -> Vec<u32> {
        self.meta.as_ref().map_or_else(Vec::new, |meta| {
            meta.evm_accounts
                .iter()
                .filter(|account| !account.hidden)
                .map(|account| account.index)
                .take(usize::from(ids::SOURCE_EVM_SPAN))
                .collect()
        })
    }

    /// `EN_CHANGE` of a Zcash edit; `false` when `id` is not one of them.
    pub fn on_zec_edit_change(&mut self, id: u16) -> bool {
        let text = || self.controls.text(id, TEXT_MAX).unwrap_or_default();
        match id {
            ids::SEND_TO_EDIT => self.zec.to_text = text(),
            ids::SEND_AMOUNT_EDIT => self.zec.amount_text = text(),
            _ => return false,
        }
        true
    }

    /// A Zcash command; `false` when `id` is not one of them.
    pub fn on_zec_command(&mut self, id: u16) -> bool {
        match id {
            ids::TAB_ZEC => self.zec_select_tab(),
            ids::ENABLE_MAINNET => self.zec_enable(ZecNetwork::Mainnet),
            ids::ENABLE_TESTNET => self.zec_enable(ZecNetwork::Testnet),
            ids::DISABLE => self.zec_disable(),
            ids::REFRESH => {
                self.zec.error = None;
                self.zec_refresh(false);
                self.refresh();
            }
            ids::COPY_ADDRESS => {
                if let Some(account) = self.zec_account() {
                    self.copy_text(&account.address());
                }
            }
            ids::QR_TOGGLE => {
                self.zec.show_qr = !self.zec.show_qr;
                self.refresh();
            }
            ids::SEND_MAX => {
                self.zec.send_max = !self.zec.send_max;
                self.refresh();
            }
            ids::SEND_REVIEW => {
                self.zec.to_text = self
                    .controls
                    .text(ids::SEND_TO_EDIT, TEXT_MAX)
                    .unwrap_or_default();
                self.zec.amount_text = self
                    .controls
                    .text(ids::SEND_AMOUNT_EDIT, TEXT_MAX)
                    .unwrap_or_default();
                self.zec_review();
            }
            ids::SOURCE_STANDARD => {
                self.zec.source = SourceChoice::Standard;
                self.zec.confirm_shared = false;
                self.refresh();
            }
            ids::SOURCE_APPLY => self.zec_apply_source(),
            ids::SOURCE_CANCEL => {
                self.zec.confirm_shared = false;
                self.zec.source = SourceChoice::Standard;
                self.refresh();
            }
            ids::INDEXER_NODE => self.zec_set_indexer(ZecIndexer::Node),
            ids::INDEXER_BB => self.zec_set_indexer(ZecIndexer::BbRest),
            other => {
                if let Some(position) = offset(other, ids::SOURCE_EVM_BASE, ids::SOURCE_EVM_SPAN) {
                    if let Some(index) = self.zec_evm_indices().get(usize::from(position)) {
                        self.zec.source = SourceChoice::EvmShared(*index);
                        self.zec.confirm_shared = false;
                        self.refresh();
                    }
                    return true;
                }
                if let Some(position) = offset(other, ids::HW_BASE, ids::HW_SPAN) {
                    if let Some(index) = self.zec_hw_slots().get(usize::from(position)) {
                        self.zec_use_hardware(*index);
                    }
                    return true;
                }
                return false;
            }
        }
        true
    }

    fn zec_disabled_items(&self, items: &mut Vec<Item>) {
        items.push(Item::CardStart(Some(
            "Zcash (일반 주소 보내기 전용)".to_owned(),
        )));
        items.push(Item::Text(
            "Zcash 일반(transparent) 주소로 받고 보냅니다. 비공개(shielded) 전송은 지원하지 않습니다 (D35)."
                .to_owned(),
        ));
        items.push(Item::Help(
            "켜면 복구 단어에서 m/44'/133'/0'/0/0 (testnet m/44'/1'/0'/0/0) 주소 하나를 씁니다. Zcash 엔드포인트(zcash:<net>)가 필요합니다."
                .to_owned(),
        ));
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        items.push(Item::Row(vec![
            Ctl::primary(ids::ENABLE_MAINNET, "Zcash mainnet 켜기").enabled(unlocked),
            Ctl::button(ids::ENABLE_TESTNET, "Zcash testnet 켜기 (테스트)").enabled(unlocked),
        ]));
        items.push(Item::CardEnd);
    }

    /// The S10 Zcash tab body.
    #[expect(clippy::too_many_lines, reason = "the Zcash tab sections in order")]
    pub fn zec_main_screen(&self, items: &mut Vec<Item>) {
        if !self.settings.zcash.enabled {
            self.zec_disabled_items(items);
            return;
        }
        let network = self.zec_network();
        items.push(Item::Banner(
            network.banner().to_owned(),
            match network {
                ZecNetwork::Mainnet => Tone::BtcMainnet,
                ZecNetwork::Testnet => Tone::Testnet,
            },
        ));
        // TODO(chain-logos): a Zcash chain badge/logo once the chain-logo component lands.
        if self.zec_journal_damaged() {
            items.push(Item::Banner(
                "거래 저널의 Zcash 기록이 손상되어 Zcash 보내기를 멈췄습니다. (E-VLT-006)"
                    .to_owned(),
                Tone::Blocked,
            ));
        }
        if let Some(error) = &self.zec.error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        if let Some(info) = &self.zec.info {
            items.push(Item::Banner(info.clone(), Tone::Info));
        }
        let snapshot = self
            .zec
            .snapshot
            .as_ref()
            .filter(|(net, _)| *net == network)
            .map(|(_, snapshot)| snapshot);
        // Network and endpoint.
        items.push(Item::CardStart(None));
        items.push(Item::LabeledRow(
            "네트워크".to_owned(),
            vec![
                Ctl::tab(
                    ids::ENABLE_MAINNET,
                    "Zcash mainnet",
                    network == ZecNetwork::Mainnet,
                )
                .enabled(!self.zec.busy),
                Ctl::tab(
                    ids::ENABLE_TESTNET,
                    "Zcash testnet (테스트)",
                    network == ZecNetwork::Testnet,
                )
                .enabled(!self.zec.busy),
            ],
        ));
        let rpc = match (
            self.apikeys
                .rpc_url(crate::network::NetworkId::Zcash(network))
                .is_some(),
            snapshot,
        ) {
            (false, _) => {
                "엔드포인트 없음 (E-KEY-005) — 설정 > RPC에서 zcash 엔드포인트를 넣으세요"
                    .to_owned()
            }
            (true, Some(snapshot)) => {
                let upgrade = yw_core::zec::upgrade::known(snapshot.chain.consensus.next_branch)
                    .map_or("알 수 없음", |upgrade| upgrade.name);
                format!(
                    "연결됨 (genesis 확인) · 블록 {} · 업그레이드 {upgrade}",
                    snapshot.chain.tip
                )
            }
            (true, None) if self.zec.refreshing => "확인 중…".to_owned(),
            (true, None) => "확인 전".to_owned(),
        };
        items.push(Item::Help(format!(
            "RPC ({}): {rpc}",
            network.endpoint_id()
        )));
        let indexer = self.settings.zcash.indexer;
        items.push(Item::LabeledRow(
            "UTXO 원천".to_owned(),
            vec![
                Ctl::tab(
                    ids::INDEXER_NODE,
                    "노드 getaddressutxos",
                    indexer == ZecIndexer::Node,
                ),
                Ctl::tab(
                    ids::INDEXER_BB,
                    "Blockbook (/api/v2)",
                    indexer == ZecIndexer::BbRest,
                ),
            ],
        ));
        items.push(Item::Row(vec![
            Ctl::button(ids::REFRESH, "새로고침").enabled(!self.zec.refreshing),
            Ctl::link(ids::DISABLE, "Zcash 끄기").enabled(!self.zec.busy),
        ]));
        items.push(Item::CardEnd);

        // Account and balance.
        let account = self.zec_account();
        items.push(Item::CardStart(Some("계정".to_owned())));
        match account {
            None => items.push(Item::Text(
                "Zcash 계정 키를 불러오는 중… (복구 단어가 없는 지갑은 YubiKey Zcash 슬롯만 쓸 수 있습니다)"
                    .to_owned(),
            )),
            Some(account) => {
                items.push(Item::Field(
                    "키 출처".to_owned(),
                    format!(
                        "{} · {}",
                        account.source.label(),
                        account.source.path_text(network)
                    ),
                ));
                let (confirmed, pending) = snapshot.map_or((None, 0), |snapshot| {
                    let reserved: Vec<_> = self
                        .zec_records()
                        .iter()
                        .filter(|record| record.may_still_confirm())
                        .flat_map(yw_core::journal::zec::ZecRecord::inputs)
                        .collect();
                    let mut confirmed = 0_u64;
                    let mut pending = 0_u64;
                    for utxo in &snapshot.utxos {
                        if reserved.contains(&utxo.outpoint) {
                            continue;
                        }
                        if utxo.height.is_some() {
                            confirmed = confirmed.saturating_add(utxo.value);
                        } else {
                            pending = pending.saturating_add(utxo.value);
                        }
                    }
                    (Some(confirmed), pending)
                });
                items.push(Item::Display(confirmed.map_or_else(
                    || "잔액 확인 전".to_owned(),
                    |zats| format!("{} ZEC", format_zec(zats)),
                )));
                if let Some(zats) = confirmed {
                    items.push(Item::Help(format!(
                        "확인된 잔액 {} (서버 기준, 진행 중 거래의 입력 제외){}",
                        format_zec_and_zats(zats),
                        if pending > 0 {
                            format!(" · 미확인 {}", format_zec_and_zats(pending))
                        } else {
                            String::new()
                        }
                    )));
                }
            }
        }
        // Key source choice.
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        let mut sources = vec![Ctl::radio(
            ids::SOURCE_STANDARD,
            "Zcash 표준 경로 (권장, 기본값)",
            self.zec.source == SourceChoice::Standard,
            true,
        )];
        for (position, index) in self.zec_evm_indices().iter().enumerate() {
            let id = ids::SOURCE_EVM_BASE.saturating_add(u16::try_from(position).unwrap_or(0));
            sources.push(Ctl::radio(
                id,
                &format!("EVM 계정 {index}과 같은 키"),
                self.zec.source == SourceChoice::EvmShared(*index),
                false,
            ));
        }
        items.push(Item::LabeledRow("키 출처 바꾸기".to_owned(), sources));
        if matches!(self.zec.source, SourceChoice::EvmShared(_)) {
            items.push(Item::Banner(T_ZEC_EVM_SHARED.to_owned(), Tone::Warn));
        }
        let apply = if self.zec.confirm_shared {
            "정말 EVM 키 사용"
        } else {
            "이 키 출처 사용"
        };
        let mut row =
            vec![Ctl::button(ids::SOURCE_APPLY, apply).enabled(unlocked && !self.zec.busy)];
        if self.zec.confirm_shared {
            row.push(Ctl::link(ids::SOURCE_CANCEL, "취소"));
        }
        for (position, index) in self.zec_hw_slots().iter().enumerate() {
            let id = ids::HW_BASE.saturating_add(u16::try_from(position).unwrap_or(0));
            row.push(
                Ctl::button(id, &format!("YubiKey Zcash 주소 {index} 사용"))
                    .enabled(unlocked && !self.zec.busy),
            );
        }
        items.push(Item::Row(row));
        items.push(Item::CardEnd);

        // Receive.
        if let Some(account) = account {
            let address = account.address();
            items.push(Item::CardStart(Some("받기".to_owned())));
            items.push(Item::Mono(grouped(&address)));
            items.push(Item::Banner(T_ZEC_RECEIVE.to_owned(), Tone::Info));
            let receive_ok = !self.passphrase_unverified();
            items.push(Item::Row(vec![
                Ctl::button(ids::COPY_ADDRESS, "주소 복사").enabled(receive_ok),
                Ctl::button(
                    ids::QR_TOGGLE,
                    if self.zec.show_qr {
                        "QR 숨기기"
                    } else {
                        "QR 보기"
                    },
                )
                .enabled(receive_ok),
            ]));
            if self.zec.show_qr && receive_ok {
                items.push(Item::Qr(format!("zcash:{address}")));
            }
            items.push(Item::CardEnd);
        }

        // Send.
        items.push(Item::CardStart(Some("보내기".to_owned())));
        items.push(Item::Help(
            "받는 주소: t1…/t3… (testnet tm…/t2…), TEX(tex1…) 또는 일반 수신자가 있는 통합 주소(u1…). 비공개 주소(zs…)는 받지 않습니다."
                .to_owned(),
        ));
        items.push(Item::LabeledRow(
            "받는 주소".to_owned(),
            vec![Ctl::edit(
                ids::SEND_TO_EDIT,
                &self.zec.to_text,
                460,
                false,
                1_000,
            )],
        ));
        items.push(Item::LabeledRow(
            "금액 (ZEC)".to_owned(),
            vec![
                Ctl::edit(ids::SEND_AMOUNT_EDIT, &self.zec.amount_text, 200, false, 24)
                    .enabled(!self.zec.send_max),
                Ctl::check(ids::SEND_MAX, "최대 (수수료 빼고 전부)", self.zec.send_max),
            ],
        ));
        items.push(Item::Help(
            "수수료는 ZIP 317 기본값(입력·출력 수에 따라 0.0001 ZEC부터)입니다. 승인 창에서 받는 주소·금액·수수료·만료 높이를 확인하세요."
                .to_owned(),
        ));
        let can_send = unlocked
            && account.is_some()
            && !self.zec.busy
            && !self.zec.refreshing
            && !self.zec_journal_damaged();
        items.push(Item::Row(vec![
            Ctl::primary(ids::SEND_REVIEW, "검토").enabled(can_send),
        ]));
        items.push(Item::CardEnd);

        // Activity.
        items.push(Item::CardStart(Some("활동".to_owned())));
        let records = self.zec_records();
        if records.is_empty() {
            items.push(Item::Help(
                "이 지갑에서 보낸 Zcash 거래가 없습니다.".to_owned(),
            ));
        }
        for record in records.iter().rev() {
            let to = record
                .recipient()
                .map_or_else(|| "-".to_owned(), |dest| dest.encode(network));
            let state = match record.state {
                ZecTxState::Confirmed => format!("확인됨 (블록 {})", record.mined_height),
                other => other.label().to_owned(),
            };
            items.push(Item::Field(
                format!("보냄 {} ZEC", format_zec(record.amount)),
                format!(
                    "{state} · 수수료 {} zats · 받는 주소 {to} · 만료 높이 {}",
                    record.fee,
                    record.expiry_height()
                ),
            ));
            items.push(Item::Mono(record.txid_hex()));
        }
        if let Some(snapshot) = snapshot {
            items.push(Item::Subtitle("받은 출력 (UTXO, 서버 기준)".to_owned()));
            if snapshot.utxos.is_empty() {
                items.push(Item::Help(
                    "이 주소에 사용 가능한 출력이 없습니다.".to_owned(),
                ));
            }
            for utxo in snapshot.utxos.iter().take(50) {
                let height = utxo
                    .height
                    .map_or_else(|| "미확인".to_owned(), |height| format!("블록 {height}"));
                items.push(Item::Field(
                    format!("{} ZEC", format_zec(utxo.value)),
                    format!(
                        "{height} · {}:{}",
                        yw_core::zec::tx::txid_display(&utxo.outpoint.txid),
                        utxo.outpoint.index
                    ),
                ));
            }
        }
        items.push(Item::CardEnd);
    }
}
