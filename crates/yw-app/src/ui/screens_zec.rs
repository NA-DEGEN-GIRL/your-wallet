//! The S10 Zcash tab (spec/12 §11, spec/04 §2.6): enable / network, account and key source,
//! balance, receive (transparent address, QR, the Zashi note), send (t-address, TEX or the
//! transparent receiver of a UA; amount or `보내기 최대`; review, with what it ended with next
//! to `검토`), activity (this wallet's journal records with `해시 복사`, and the address UTXOs).
//! One page, no extra screens.

use yw_core::journal::zec::ZecTxState;
use yw_core::zec::{ZecNetwork, format_zec, format_zec_and_zats};

use crate::app::{App, AppMode};
use crate::app_zec::SourceChoice;
use crate::settings::ZecIndexer;
use crate::ui::badge::Badge;
use crate::ui::main_window::{Ctl, Item, Tone};
use crate::zec::rpc::ZecRpcError;

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
    /// W-ADDR-3 `주소 전체를 직접 확인했습니다`.
    pub const SEND_ADDR_ACK: u16 = 8_016;
    /// `해시 복사` of the 보내기 card's result line (the txid the node accepted).
    pub const RESULT_COPY: u16 = 8_017;
    /// The account card's `주소 복사` (2026-11-11; the 받기 card keeps [`COPY_ADDRESS`]).
    pub const CARD_COPY: u16 = 8_018;
    /// `해시 복사` of the activity rows (newest first, one id per row).
    pub const ACTIVITY_COPY_BASE: u16 = 8_100;
    /// Activity copy span (every record the journal can hold).
    pub const ACTIVITY_COPY_SPAN: u16 = 80;
    /// Key source: EVM account radios (position in the EVM account list).
    pub const SOURCE_EVM_BASE: u16 = 8_020;
    /// EVM radio span.
    pub const SOURCE_EVM_SPAN: u16 = 16;
    /// `YubiKey` Zcash slot buttons (position in the slot list).
    pub const HW_BASE: u16 = 8_040;
    /// `YubiKey` button span.
    pub const HW_SPAN: u16 = 8;
    /// `개인키 가져오기` (spec/12 §2.3).
    pub const IMPORT: u16 = 8_050;
    /// `개인키 보기` of the account's imported key.
    pub const REVEAL: u16 = 8_051;
    /// `삭제` of the account's imported key.
    pub const REMOVE: u16 = 8_052;
    /// `이 키 사용` of the imported keys of the network (position in the list).
    pub const IMPORTED_BASE: u16 = 8_060;
    /// Imported-key button span (15 keys per chain).
    pub const IMPORTED_SPAN: u16 = 16;

    const _: () = assert!(CARD_COPY < SOURCE_EVM_BASE);
    const _: () = assert!(SOURCE_EVM_BASE + SOURCE_EVM_SPAN <= HW_BASE);
    const _: () = assert!(HW_BASE + HW_SPAN <= IMPORT);
    const _: () = assert!(IMPORTED_BASE + IMPORTED_SPAN <= ACTIVITY_COPY_BASE);
    const _: () = assert!(ACTIVITY_COPY_BASE + ACTIVITY_COPY_SPAN <= 8_200);

    /// Every fixed id.
    pub const FIXED: [u16; 22] = [
        CARD_COPY,
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
        SEND_ADDR_ACK,
        RESULT_COPY,
        IMPORT,
        REVEAL,
        REMOVE,
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

/// `YYYY-MM-DD HH:MM` in local time (UTC with a suffix if the conversion fails).
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
            ids::SEND_TO_EDIT => {
                self.zec.to_text = text();
                self.zec_check_recipient();
            }
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
            ids::COPY_ADDRESS | ids::CARD_COPY => {
                if let Some(account) = self.zec_account()
                    && matches!(
                        self.zec_hw_state(),
                        crate::app_zec::ZecHwState::NotHardware
                            | crate::app_zec::ZecHwState::Present
                    )
                {
                    self.copy_address_text(&account.address());
                }
            }
            ids::QR_TOGGLE => {
                self.zec.show_qr = !self.zec.show_qr;
                self.refresh();
            }
            // A txid is public data (like Bitcoin's `해시 복사`): for checking on an explorer.
            ids::RESULT_COPY => {
                if let Some(txid) = self.zec.sent {
                    self.copy_text(&yw_core::zec::tx::txid_display(&txid));
                }
            }
            ids::SEND_MAX => {
                self.zec.send_max = !self.zec.send_max;
                self.refresh();
            }
            ids::SEND_ADDR_ACK => {
                self.zec.ack = !self.zec.ack && self.zec.checked.is_some();
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
                self.zec_check_recipient();
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
            ids::IMPORT => {
                self.open_key_import(yw_core::keyimport::ImportChain::Zec);
            }
            ids::REVEAL | ids::REMOVE => {
                if let Some(record) = self.zec_selected_imported() {
                    if id == ids::REVEAL {
                        self.imported_reveal(*record.as_bytes());
                    } else {
                        self.imported_remove(*record.as_bytes());
                    }
                }
            }
            other => return self.on_zec_indexed(other),
        }
        true
    }

    /// The Zcash row commands (activity `해시 복사`, imported keys, EVM-key radios, `YubiKey`
    /// slots); `false` when `id` is not one of them.
    fn on_zec_indexed(&mut self, id: u16) -> bool {
        if let Some(row) = offset(id, ids::ACTIVITY_COPY_BASE, ids::ACTIVITY_COPY_SPAN) {
            // Rows are drawn newest first; a txid is public data, for an explorer.
            if let Some(record) = self.zec_records().iter().rev().nth(usize::from(row)) {
                self.copy_text(&record.txid_hex());
            }
            return true;
        }
        if let Some(position) = offset(id, ids::IMPORTED_BASE, ids::IMPORTED_SPAN) {
            self.zec_use_imported(usize::from(position));
            return true;
        }
        if let Some(position) = offset(id, ids::SOURCE_EVM_BASE, ids::SOURCE_EVM_SPAN) {
            if let Some(index) = self.zec_evm_indices().get(usize::from(position)) {
                self.zec.source = SourceChoice::EvmShared(*index);
                self.zec.confirm_shared = false;
                self.refresh();
            }
            return true;
        }
        if let Some(position) = offset(id, ids::HW_BASE, ids::HW_SPAN) {
            if let Some(index) = self.zec_hw_slots().get(usize::from(position)) {
                self.zec_use_hardware(*index);
            }
            return true;
        }
        false
    }

    /// The imported keys of the network ("[가져온 키]" rows with `이 키 사용`), `개인키 가져오기`,
    /// and for an account on an imported key `개인키 보기`·`삭제` (spec/12 §2.3, spec/04 §2.18).
    fn zec_imported_items(&self, items: &mut Vec<Item>) {
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        let current = self.zec_account();
        let keys = self.zec_imported_keys();
        items.push(Item::Rule);
        for (position, (_, info)) in keys.iter().enumerate() {
            let id = ids::IMPORTED_BASE.saturating_add(u16::try_from(position).unwrap_or(0));
            let in_use = current.is_some_and(|account| {
                account.source == yw_core::zec::ZecKeySource::Imported
                    && account.pubkey == info.pubkey
            });
            items.push(Item::LabeledRow(
                format!("[가져온 키] {}", grouped(&info.address)),
                vec![
                    Ctl::button(
                        id,
                        if in_use {
                            "사용 중"
                        } else {
                            "이 키 사용"
                        },
                    )
                    .enabled(unlocked && !self.zec.busy && !in_use),
                ],
            ));
        }
        if self.zec_selected_imported().is_some() {
            items.push(Item::Help(if self.key_only() {
                crate::ui::secret::T_KEY_ONLY_BACKUP.to_owned()
            } else {
                crate::ui::secret::T_IMPORTED_KEY_BACKUP.to_owned()
            }));
            items.push(Item::Row(vec![
                Ctl::button(ids::REVEAL, "개인키 보기").enabled(unlocked),
                Ctl::danger(ids::REMOVE, "삭제").enabled(unlocked && self.can_remove_imported()),
            ]));
        }
        items.push(Item::Help(
            "다른 지갑(zcashd 등)의 Zcash 일반 주소 개인키(압축 WIF 또는 16진수)를 가져와 이 네트워크의 계정으로 쓸 수 있습니다. 가져온 키는 복구 단어로 복구되지 않습니다."
                .to_owned(),
        ));
        items.push(Item::Row(vec![
            Ctl::button(ids::IMPORT, "개인키 가져오기")
                .enabled(self.can_import(yw_core::keyimport::ImportChain::Zec)),
        ]));
    }

    fn zec_disabled_items(&self, items: &mut Vec<Item>) {
        items.push(Item::CardStart(Some("Zcash (일반 주소 전용)".to_owned())));
        items.push(Item::Text(
            "Zcash 일반(transparent) 주소로 받고 보냅니다. 비공개(shielded) 전송은 지원하지 않습니다."
                .to_owned(),
        ));
        items.push(Item::Help(
            "켜면 복구 단어에서 m/44'/133'/0'/0/0 (testnet m/44'/1'/0'/0/0) 주소 하나를 씁니다. 먼저 설정 → 네트워크(RPC)에서 그 네트워크의 Zcash RPC 주소(zcash:mainnet·zcash:testnet)를 넣으세요."
                .to_owned(),
        ));
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        let mut row = vec![
            Ctl::primary(ids::ENABLE_MAINNET, "Zcash mainnet 켜기").enabled(unlocked),
            Ctl::button(ids::ENABLE_TESTNET, "Zcash testnet 켜기 (테스트)").enabled(unlocked),
        ];
        if ZecNetwork::ALL.into_iter().all(|network| {
            self.apikeys
                .rpc_url(crate::network::NetworkId::Zcash(network))
                .is_none()
        }) {
            row.push(Ctl::link(
                crate::ui::screens::ids::ZEC_RPC_OPEN,
                "RPC 설정하기",
            ));
        }
        items.push(Item::Row(row));
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
        if self.zec_journal_damaged() {
            items.push(Item::Banner(
                "거래 저널의 Zcash 기록이 손상되어 Zcash 보내기를 멈췄습니다. (E-VLT-006)"
                    .to_owned(),
                Tone::Blocked,
            ));
        }
        let has_endpoint = self
            .apikeys
            .rpc_url(crate::network::NetworkId::Zcash(network))
            .is_some();
        // A missing URL is already the network card's status line with `RPC 설정하기`; the same
        // E-KEY-005 is not repeated as a red band above it (review 2026-11-07 F6). Nor is what
        // the 보내기 card already says next to `검토`.
        if let Some(error) = self.zec.error.as_ref().filter(|error| {
            (has_endpoint || **error != crate::errors::ErrorCode::Key005.text())
                && self.zec.send_error.as_ref() != Some(*error)
        }) {
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
                .badge(Badge::zcash(ZecNetwork::Mainnet))
                .enabled(!self.zec.busy),
                Ctl::tab(
                    ids::ENABLE_TESTNET,
                    "Zcash testnet (테스트)",
                    network == ZecNetwork::Testnet,
                )
                .badge(Badge::zcash(ZecNetwork::Testnet))
                .enabled(!self.zec.busy),
            ],
        ));
        // The network tag after the chips, as on the other tabs (2026-11-11: a small tag, no
        // longer a full-width band).
        items.push(Item::Pill(
            network.banner().to_owned(),
            match network {
                ZecNetwork::Mainnet => Tone::BtcMainnet,
                ZecNetwork::Testnet => Tone::Testnet,
            },
        ));
        let rpc = match (has_endpoint, snapshot) {
            (false, _) => {
                "RPC 주소 없음 (E-KEY-005) — 설정 → 네트워크(RPC)에서 Zcash RPC 주소를 넣으세요"
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
        // `새로고침` (or `RPC 설정하기`) is the account card's, as on the other tabs (2026-11-11).
        items.push(Item::Row(vec![
            Ctl::link(ids::DISABLE, "Zcash 끄기").enabled(!self.zec.busy),
        ]));
        items.push(Item::CardEnd);

        // Account and balance: the other tabs' layout (2026-11-11) — name, key source and
        // path, balance, status, the address with `주소 복사`, `새로고침`.
        let account = self.zec_account();
        let hw_state = self.zec_hw_state();
        let address_ok = matches!(
            hw_state,
            crate::app_zec::ZecHwState::NotHardware | crate::app_zec::ZecHwState::Present
        );
        items.push(Item::CardStart(None));
        items.push(Item::Badged(
            Badge::zcash(network),
            Box::new(Item::Subtitle(format!(
                "Zcash 계정 · {}",
                network.display_name()
            ))),
        ));
        match account {
            None => items.push(Item::Text(
                "Zcash 계정 키를 불러오는 중… (복구 단어가 없는 지갑은 YubiKey Zcash 슬롯만 쓸 수 있습니다)"
                    .to_owned(),
            )),
            Some(account) => {
                items.push(Item::Help(format!(
                    "키 출처: {} · {}",
                    self.zec_source_label(account.source),
                    account.source.path_text(network)
                )));
                let (confirmed, pending) = snapshot.map_or((None, 0), |snapshot| {
                    let reserved: Vec<_> = self
                        .zec_records()
                        .iter()
                        .filter(|record| record.reserves_inputs())
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
                // The other tabs' words when there is no balance yet (2026-11-11).
                items.push(Item::Display(confirmed.map_or_else(
                    || "잔액 —".to_owned(),
                    |zats| format!("{} ZEC", format_zec(zats)),
                )));
                items.push(Item::Help(match confirmed {
                    Some(zats) => format!(
                        "확인된 잔액 {} (서버 기준, 진행 중 거래의 입력 제외){}",
                        format_zec_and_zats(zats),
                        if pending > 0 {
                            format!(" · 미확인 {}", format_zec_and_zats(pending))
                        } else {
                            String::new()
                        }
                    ),
                    None if !has_endpoint => crate::ui::screens::no_endpoint_text(
                        &self.network_name(crate::network::NetworkId::Zcash(network)),
                    ),
                    None if self.zec.error.is_some() && !self.zec.refreshing => {
                        crate::ui::screens::T_BALANCE_FAILED.to_owned()
                    }
                    None => crate::ui::screens::T_BALANCE_LOADING.to_owned(),
                }));
                // Not while a hardware account's key is missing or unchecked (like 받기).
                if address_ok {
                    let address = account.address();
                    items.push(crate::ui::screens::own_address_row(
                        &address,
                        crate::ui::theme::AddressKind::Zcash,
                        ids::CARD_COPY,
                        !self.passphrase_unverified(),
                        self.explorer_address_link(
                            crate::network::NetworkId::Zcash(network),
                            &address,
                            crate::ui::screens_explorer::ids::CARD_ZEC,
                        ),
                    ));
                }
            }
        }
        items.push(Item::Row(vec![if has_endpoint {
            Ctl::link(ids::REFRESH, "새로고침").enabled(!self.zec.refreshing)
        } else {
            // Nothing to refresh without an address: this network's row (EVM·Solana alike).
            Ctl::button(crate::ui::screens::ids::ZEC_RPC_OPEN, "RPC 설정하기")
        }]));
        items.push(Item::CardEnd);
        // Key source choice.
        items.push(Item::CardStart(Some("키 출처".to_owned())));
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
            let label = if yw_core::yubikey::plan::is_unknown_index(*index) {
                format!(
                    "YubiKey Zcash 카드 키 {} 사용 (경로 모름)",
                    index
                        .saturating_sub(yw_core::yubikey::plan::UNKNOWN_PATH_FIRST)
                        .saturating_add(1)
                )
            } else {
                format!("YubiKey Zcash 주소 {index} 사용")
            };
            row.push(Ctl::button(id, &label).enabled(unlocked && !self.zec.busy));
        }
        items.push(Item::Row(row));
        // The standard path of each added mnemonic (spec/02 §8.6).
        let added: Vec<Ctl> = self
            .mn
            .infos
            .iter()
            .enumerate()
            .filter(|(_, info)| !info.primary)
            .map(|(row, info)| {
                let id = crate::ui::screens_mnemonics::ids::ZEC_PICK_BASE
                    .saturating_add(u16::try_from(row).unwrap_or(0));
                let in_use = account.is_some_and(|account| {
                    account.source
                        == yw_core::zec::ZecKeySource::Mnemonic {
                            mnemonic: info.id,
                            account: 0,
                            index: 0,
                        }
                });
                let label = if in_use {
                    format!("{} 표준 경로 (사용 중)", self.mnemonic_label(info.id))
                } else {
                    format!("{} 표준 경로 사용", self.mnemonic_label(info.id))
                };
                Ctl::button(id, &label).enabled(unlocked && !self.zec.busy && !in_use)
            })
            .collect();
        if !added.is_empty() {
            items.push(Item::LabeledRow("추가한 복구 단어".to_owned(), added));
        }
        self.zec_imported_items(items);
        items.push(Item::CardEnd);

        // Receive (hidden while a hardware account's key is missing or not yet checked).
        if hw_state == crate::app_zec::ZecHwState::Missing {
            items.push(Item::Banner(
                crate::app_zec::T_ZEC_HW_MISSING.to_owned(),
                Tone::Danger,
            ));
        }
        if let Some(account) = account.filter(|_| address_ok) {
            let address = account.address();
            items.push(Item::CardStart(Some("받기".to_owned())));
            items.push(Item::Mono(grouped(&address)));
            items.push(Item::Banner(T_ZEC_RECEIVE.to_owned(), Tone::Info));
            self.mn_receive_banner(
                self.mn_backup_gate(
                    account.source.mnemonic(),
                    matches!(
                        account.source,
                        yw_core::zec::ZecKeySource::Derived { .. }
                            | yw_core::zec::ZecKeySource::EvmShared { .. }
                    ),
                ),
                items,
            );
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
        // U7: an account whose phrase has not passed its backup quiz cannot sign; said before
        // the form, with `검토` off, instead of after the approval (E-VLT-009).
        let backup_gate = self.zec_backup_gate();
        self.mn_signing_banner(backup_gate, items);
        self.card_pin_banner(self.zec_card_gate(), items);
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
        if let Some(note) = &self.zec.look_alike {
            items.push(Item::Banner(note.clone(), Tone::HighRisk));
            items.push(Item::Row(vec![Ctl::check(
                ids::SEND_ADDR_ACK,
                "주소 전체를 직접 확인했습니다",
                self.zec.ack,
            )]));
        }
        items.push(Item::LabeledRow(
            "금액 (ZEC)".to_owned(),
            vec![
                Ctl::edit(ids::SEND_AMOUNT_EDIT, &self.zec.amount_text, 200, false, 24)
                    .enabled(!self.zec.send_max),
                Ctl::check(ids::SEND_MAX, "보내기 최대", self.zec.send_max),
            ],
        ));
        if self.zec.send_max {
            items.push(Item::Help(format!(
                "보내기 최대: 확인된 출력(최대 {}개)의 합에서 수수료를 뺀 금액을 보냅니다(승인 창에서 확인).",
                yw_core::zec::ZEC_MAX_INPUTS
            )));
        }
        items.push(Item::Help(
            "수수료는 ZIP 317 기본값(입력·출력 수에 따라 0.0001 ZEC부터)입니다. 승인 창에서 받는 주소·금액·수수료·만료 높이를 확인하세요."
                .to_owned(),
        ));
        let can_send = unlocked
            && account.is_some()
            && !self.zec.busy
            && !self.zec.refreshing
            && !self.zec_journal_damaged()
            && !self.mn_send_blocked(backup_gate)
            // spec/10 §9.3: the YubiKey is still on its factory PINs (the band says so).
            && self.zec_card_gate().is_none()
            && self
                .journal_hold(crate::app_sidecar::SendChain::Zec)
                .is_none()
            && (self.zec.look_alike.is_none() || self.zec.ack);
        // What `검토`, the approval, signing and sending ended with, next to the button (the
        // tab's own band is several cards above it).
        if let Some(error) = &self.zec.send_error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        if let Some(info) = &self.zec.send_info {
            items.push(Item::Banner(info.clone(), Tone::Info));
        }
        if let Some(txid) = &self.zec.sent {
            items.push(Item::Banner(
                format!(
                    "보냈습니다. txid {} — 아래 활동에서 확인 상태를 봅니다.",
                    yw_core::zec::tx::txid_display(txid)
                ),
                Tone::Success,
            ));
        }
        self.journal_send_items(crate::app_sidecar::SendChain::Zec, items);
        let mut row = vec![Ctl::primary(ids::SEND_REVIEW, "검토").enabled(can_send)];
        if let Some(txid) = &self.zec.sent {
            row.push(Ctl::button(ids::RESULT_COPY, "해시 복사"));
            // 2026-11-11: the accepted txid on the network's explorer.
            row.extend(self.explorer_tx_buttons(
                crate::network::NetworkId::Zcash(network),
                &yw_core::zec::tx::txid_display(txid),
                Some((
                    crate::ui::screens_explorer::ids::RESULT_ZEC_OPEN,
                    crate::ui::screens_explorer::ids::RESULT_ZEC_COPY,
                )),
            ));
        }
        items.push(Item::Row(row));
        items.push(Item::CardEnd);

        // Activity.
        items.push(Item::CardStart(Some("활동".to_owned())));
        let records = self.zec_records();
        if records.is_empty() {
            items.push(Item::Help(format!(
                "이 지갑에서 보낸 Zcash 거래가 없습니다. {}",
                crate::ui::screens::T_ACTIVITY_RECEIVED
            )));
        }
        // The rows of the other chains' order (2026-11-10): time and amount, status (the expiry
        // height only while it may still confirm), the recipient with its display-only name on
        // its own `Mono` line, the fee in ZEC, then the txid.
        let own = self
            .zec_account()
            .map(|account| (account.address(), self.zec_source_label(account.source)));
        for (row, record) in records.iter().rev().enumerate() {
            let state = match record.state {
                ZecTxState::Confirmed => format!("확인됨 (블록 {})", record.mined_height),
                other => other.label().to_owned(),
            };
            items.push(Item::Text(format!(
                "{} · 보냄 {} ZEC",
                local_time(record.signed_at_ms),
                format_zec(record.amount)
            )));
            items.push(Item::Help(if record.state.is_terminal() {
                format!("상태: {state}")
            } else {
                format!("상태: {state} · 만료 높이 {}", record.expiry_height())
            }));
            match record.recipient().map(|dest| dest.encode(network)) {
                Some(to) => {
                    let name = own
                        .as_ref()
                        .filter(|(address, _)| *address == to)
                        .map(|(_, label)| format!(" → 내 계정: {label}"))
                        .unwrap_or_default();
                    items.push(Item::Help(format!("받는 주소{name}")));
                    items.push(Item::Mono(grouped(&to)));
                }
                None => items.push(Item::Help("받는 주소 -".to_owned())),
            }
            items.push(Item::Help(format!("수수료 {} ZEC", format_zec(record.fee))));
            let txid = record.txid_hex();
            items.push(Item::Mono(txid.clone()));
            let mut buttons: Vec<Ctl> = u16::try_from(row)
                .ok()
                .filter(|row| *row < ids::ACTIVITY_COPY_SPAN)
                .map(|row| Ctl::button(ids::ACTIVITY_COPY_BASE.saturating_add(row), "해시 복사"))
                .into_iter()
                .collect();
            // 2026-11-11: `탐색기에서 열기`·`탐색기 링크 복사` (ids of `ui::screens_explorer`).
            buttons.extend(self.explorer_tx_buttons(
                crate::network::NetworkId::Zcash(network),
                &txid,
                crate::ui::screens_explorer::ids::activity_ids(
                    crate::ui::screens_explorer::ids::ZEC_ACTIVITY_BASE,
                    crate::ui::screens_explorer::ids::ZEC_ACTIVITY_SPAN,
                    row,
                ),
            ));
            if !buttons.is_empty() {
                items.push(Item::Row(buttons));
            }
        }
        if let Some(snapshot) = snapshot {
            items.push(Item::Subtitle("받은 출력 (UTXO, 서버 기준)".to_owned()));
            if snapshot.utxo_error == Some(ZecRpcError::TooMany) {
                items.push(Item::Help(ZecRpcError::TooMany.text()));
            } else if let Some(error) = snapshot.utxo_error {
                items.push(Item::Help(format!(
                    "출력 목록을 불러오지 못했습니다: {}",
                    error.text()
                )));
            } else if snapshot.utxos.is_empty() {
                items.push(Item::Help(
                    "이 주소에 사용 가능한 출력이 없습니다.".to_owned(),
                ));
            }
            if snapshot.ignored_utxos > 0 {
                items.push(Item::Help(format!(
                    "아주 작은 출력(먼지, {} zats 이하)이나 한도({}개)를 넘는 작은 출력 {}개는 잔액과 보내기에서 제외했습니다.",
                    yw_core::zec::ZEC_MIN_UTXO,
                    yw_core::zec::ZEC_MAX_UTXOS,
                    snapshot.ignored_utxos
                )));
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
        self.received_items(crate::received::RecvChain::Zec, items);
        items.push(Item::CardEnd);
    }
}
