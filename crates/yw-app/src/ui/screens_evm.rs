//! EVM screen contents (M4, spec/04 §2.6–§2.8, §2.10, §2.11, §2.16, §2.17): the S10 network,
//! balance, token and activity sections, S11 send, S12 receive, S14 address book, S16 token add,
//! the S15 `EVM 체인` section with fee caps, S17 chain add/edit and their confirmation texts.

use core::fmt::Write as _;

use yw_core::evm::address::{Address, parse_address};
use yw_core::evm::amount::{U256, format_amount, format_units};
use yw_core::evm::chain::{HYPEREVM_MAINNET, SEPOLIA, builtin_chain};
use yw_core::evm::display::format_address;
use yw_core::journal::evm::{EvmRecord, ReceiptStatus, TxState, groups};

use crate::app::{App, AppMode};
use crate::app_evm::{SendAsset, hash_text};
use crate::errors::ErrorCode;
use crate::flow::evm::MismatchKind;
use crate::flow::evm::track::BroadcastOutcome;
use crate::logging::format_utc;
use crate::meta::ActivityEntry;
use crate::network::NetworkId;
use crate::ui::main_window::{Ctl, Item, Tone};

/// T-CUSTOM-CHAIN (spec/04 §2.16): the user-chain badge of S10, S15 and the A01 header.
#[must_use]
pub fn custom_chain_badge(chain_id: u64) -> String {
    format!("사용자 추가 체인 (chainId {chain_id})")
}

/// `YYYY-MM-DD HH:MM` in local time (spec/04 §2.6); UTC with a suffix if the conversion fails.
fn format_local(unix_ms: u64) -> String {
    let wall = yw_win::time::local_wall_ms(unix_ms);
    let text = format_utc(wall.unwrap_or(unix_ms));
    let short = text.get(..16).unwrap_or(&text).replace('T', " ");
    if wall.is_some() {
        short
    } else {
        format!("{short} UTC")
    }
}

/// Command ids of the EVM screens (900 and up; spec/04 screens).
pub mod ids {
    /// 보내기.
    pub const SEND_OPEN: u16 = 900;
    /// 받기.
    pub const RECEIVE_OPEN: u16 = 901;
    /// 새로고침.
    pub const REFRESH: u16 = 902;
    /// 주소록.
    pub const BOOK_OPEN: u16 = 903;
    /// 토큰 추가.
    pub const TOKEN_OPEN: u16 = 904;
    /// 설정에서 다시 고정.
    pub const REPIN_SETTINGS: u16 = 905;
    /// Recipient edit.
    pub const SEND_TO_EDIT: u16 = 910;
    /// Amount edit.
    pub const SEND_AMOUNT_EDIT: u16 = 911;
    /// 최대.
    pub const SEND_MAX: u16 = 912;
    /// 주소록에서 선택.
    pub const SEND_PICK: u16 = 913;
    /// W-ADDR-3 check.
    pub const SEND_ACK: u16 = 914;
    /// 검토.
    pub const SEND_REVIEW: u16 = 915;
    /// 취소 / 돌아가기.
    pub const SEND_CANCEL: u16 = 916;
    /// Asset radios.
    pub const SEND_ASSET_BASE: u16 = 920;
    /// Asset radio span.
    pub const SEND_ASSET_SPAN: u16 = 40;
    /// Picker rows.
    pub const SEND_PICK_BASE: u16 = 960;
    /// Picker span.
    pub const SEND_PICK_SPAN: u16 = 40;
    /// 주소 복사.
    pub const COPY_ADDRESS: u16 = 1_000;
    /// Book address edit.
    pub const BOOK_ADDR_EDIT: u16 = 1_010;
    /// Book label edit.
    pub const BOOK_LABEL_EDIT: u16 = 1_011;
    /// Book verified check.
    pub const BOOK_VERIFIED: u16 = 1_012;
    /// Book save.
    pub const BOOK_SAVE: u16 = 1_013;
    /// Book cancel edit.
    pub const BOOK_CANCEL: u16 = 1_014;
    /// Book rows (2 ids per row: 편집, 삭제).
    pub const BOOK_ROW_BASE: u16 = 1_020;
    /// Book rows span.
    pub const BOOK_ROW_SPAN: u16 = 1_000;
    /// Token address edit.
    pub const TOKEN_ADDR_EDIT: u16 = 2_100;
    /// 조회.
    pub const TOKEN_LOOKUP: u16 = 2_101;
    /// Token label edit.
    pub const TOKEN_LABEL_EDIT: u16 = 2_102;
    /// Token save.
    pub const TOKEN_SAVE: u16 = 2_103;
    /// Settings EVM-chains section.
    pub const SECTION_CHAINS: u16 = 2_200;
    /// 추가.
    pub const CHAIN_ADD: u16 = 2_201;
    /// Chain rows (4 ids per row: 편집, 삭제, 다시 고정).
    pub const CHAIN_ROW_BASE: u16 = 2_210;
    /// Chain rows span.
    pub const CHAIN_ROW_SPAN: u16 = 140;
    /// S17 chainId.
    pub const CHAIN_ID_EDIT: u16 = 2_350;
    /// S17 name.
    pub const CHAIN_NAME_EDIT: u16 = 2_351;
    /// S17 symbol.
    pub const CHAIN_SYMBOL_EDIT: u16 = 2_352;
    /// S17 decimals.
    pub const CHAIN_DECIMALS_EDIT: u16 = 2_353;
    /// S17 RPC (`ES_PASSWORD`).
    pub const CHAIN_RPC_EDIT: u16 = 2_354;
    /// S17 explorer.
    pub const CHAIN_EXPLORER_EDIT: u16 = 2_355;
    /// S17 simulation auto.
    pub const CHAIN_SIM_AUTO: u16 = 2_356;
    /// S17 simulation unsupported.
    pub const CHAIN_SIM_UNSUPPORTED: u16 = 2_357;
    /// S17 save.
    pub const CHAIN_SAVE: u16 = 2_358;
    /// S17 cancel.
    pub const CHAIN_CANCEL: u16 = 2_359;
    /// Fee caps chain radios.
    pub const CAPS_CHAIN_BASE: u16 = 2_400;
    /// Fee caps chain span.
    pub const CAPS_CHAIN_SPAN: u16 = 40;
    /// maxFee cap edit.
    pub const CAPS_FEE_EDIT: u16 = 2_450;
    /// tip cap edit.
    pub const CAPS_TIP_EDIT: u16 = 2_451;
    /// total cap edit.
    pub const CAPS_TOTAL_EDIT: u16 = 2_452;
    /// 저장.
    pub const CAPS_SAVE: u16 = 2_453;
    /// 기본값으로.
    pub const CAPS_DEFAULT: u16 = 2_454;
    /// Activity rows (8 ids per row).
    pub const ACTIVITY_BASE: u16 = 2_500;
    /// Activity span.
    pub const ACTIVITY_SPAN: u16 = 4_000;
    /// T-CHAIN-REPIN-ACK check.
    pub const REPIN_CHECK: u16 = 6_600;
}

/// Status words of activity rows.
fn activity_status(word: &str) -> &'static str {
    match word {
        "succeeded" => "성공",
        "failed" => "실패",
        "dropped" => "폐기됨",
        "replaced" => "대체됨",
        "expired" => "만료",
        "rejected" => "거부됨",
        "conflicted" => "충돌",
        _ => "중단됨",
    }
}

/// One activity row of the S10 list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivityRowView {
    /// Time, account label, title.
    pub head: String,
    /// Status.
    pub status: String,
    /// Hash text.
    pub hash: String,
    /// Group key when it is an open journal group (speed-up/cancel/resend/discard).
    pub open: Option<yw_core::journal::evm::GroupKey>,
    /// Manual resend/discard offered.
    pub manual: bool,
}

impl App {
    fn account_label(&self, address: &str) -> String {
        self.account_rows()
            .into_iter()
            .find(|(_, _, shown, _)| shown.eq_ignore_ascii_case(address))
            .map_or_else(|| address.to_owned(), |(_, label, _, _)| label)
    }

    fn record_status(&self, record: &EvmRecord) -> String {
        let note = self.evm.notes.get(&record.tx_hash).copied();
        match record.state {
            TxState::Signed => match note {
                Some(BroadcastOutcome::HashMismatch) => {
                    "RPC가 다른 거래 해시를 반환했습니다 (재전송·폐기)".to_owned()
                }
                Some(BroadcastOutcome::Rejected { known: false }) => {
                    "전송 실패 — 재전송하거나 폐기하세요".to_owned()
                }
                Some(BroadcastOutcome::Unconfirmed { .. }) | None => "전송 확인 중".to_owned(),
                _ => "서명됨".to_owned(),
            },
            TxState::Broadcast => "전송됨".to_owned(),
            TxState::Included => {
                if record.receipt_status == ReceiptStatus::Failure {
                    "포함됨 (실행 실패)".to_owned()
                } else {
                    format!("포함됨 (블록 {})", record.included_block_number)
                }
            }
            TxState::Finalized => {
                if record.receipt_status == ReceiptStatus::Failure {
                    "확정 (실행 실패)".to_owned()
                } else {
                    "확정".to_owned()
                }
            }
            TxState::Dropped => {
                if record.has_flag(yw_core::journal::evm::FLAG_USER_DISCARDED) {
                    "폐기됨".to_owned()
                } else {
                    "다른 거래가 이 nonce를 사용".to_owned()
                }
            }
            TxState::Replaced => "대체됨".to_owned(),
        }
    }

    /// Activity rows of the active chain: journal groups first, then meta activity.
    #[must_use]
    pub fn activity_rows(&self) -> Vec<ActivityRowView> {
        let chain_id = self.settings.evm_chain_id;
        let mut rows = Vec::new();
        let records: Vec<EvmRecord> = self
            .evm
            .records()
            .iter()
            .filter(|record| record.chain_id == chain_id)
            .cloned()
            .collect();
        let mut seen: Vec<String> = Vec::new();
        let mut grouped = groups(&records);
        grouped.sort_by_key(|(_, members)| {
            std::cmp::Reverse(members.iter().map(|record| record.created_unix_ms).max())
        });
        for (key, members) in grouped {
            let open = members.iter().any(|record| !record.is_terminal());
            let shown = members
                .iter()
                .find(|record| matches!(record.state, TxState::Included | TxState::Finalized))
                .or_else(|| members.iter().max_by_key(|record| record.created_unix_ms))
                .copied();
            let Some(shown) = shown else { continue };
            let hash = hash_text(&shown.tx_hash);
            for member in &members {
                seen.push(hash_text(&member.tx_hash));
            }
            let manual = members.iter().any(|record| {
                record.state == TxState::Signed
                    && matches!(
                        self.evm.notes.get(&record.tx_hash),
                        Some(
                            BroadcastOutcome::Rejected { known: false }
                                | BroadcastOutcome::HashMismatch
                        )
                    )
            });
            rows.push(ActivityRowView {
                head: format!(
                    "{} · {} · {} · nonce {}",
                    format_local(shown.created_unix_ms),
                    self.account_label(&shown.account.to_lower_hex()),
                    shown.label,
                    key.nonce
                ),
                status: self.record_status(shown),
                hash,
                open: open.then_some(key),
                manual,
            });
        }
        if let Some(meta) = self.meta.as_ref() {
            let network = NetworkId::Eip155(chain_id).to_string();
            for entry in meta.activity_of(&network) {
                if seen.contains(&entry.tx_id) {
                    continue;
                }
                rows.push(self.meta_activity_row(&entry, chain_id));
            }
        }
        rows.truncate(crate::app_evm::MAX_ACTIVITY_ROWS);
        rows
    }

    fn meta_activity_row(&self, entry: &ActivityEntry, chain_id: u64) -> ActivityRowView {
        let amount = U256::from_decimal_str(&entry.amount).unwrap_or(U256::ZERO);
        let value = if entry.asset == "native" {
            self.native_text(chain_id, &amount)
        } else {
            let token = parse_address(&entry.asset).ok();
            token
                .and_then(|token| {
                    self.chain_tokens(chain_id)
                        .into_iter()
                        .find(|(address, ..)| *address == token)
                })
                .map_or_else(
                    || format!("{} (원시 단위)", amount.to_decimal_string()),
                    |(_, symbol, decimals, _)| format_amount(&amount, decimals, &symbol),
                )
        };
        ActivityRowView {
            head: format!(
                "{} · {} · {} · {value}",
                format_local(entry.time_unix_ms),
                self.account_label(&entry.account),
                entry.title
            ),
            status: activity_status(&entry.status).to_owned(),
            hash: entry.tx_id.clone(),
            open: None,
            manual: false,
        }
    }

    /// The S10 status line (spec/04 §2.6).
    #[must_use]
    pub fn evm_status_line(&self) -> String {
        let chain_id = self.settings.evm_chain_id;
        let network = NetworkId::Eip155(chain_id);
        let rpc = if !self.apikeys.has(crate::apikeys::KeyName::Rpc(network)) {
            "엔드포인트 없음 (E-KEY-005)".to_owned()
        } else if let Some(kind) = self.evm.blocked(chain_id) {
            format!("차단 {}", kind.code().code())
        } else if let Some(code) = self
            .evm
            .balances
            .get(&chain_id)
            .and_then(|state| state.error)
        {
            format!("오류 {}", code.code())
        } else if self.evm.chain_checks.contains_key(&chain_id) {
            "연결됨".to_owned()
        } else {
            "확인 전".to_owned()
        };
        format!(
            "RPC: {rpc}   ·   {}",
            crate::app_browser::status_text(self.browser.as_ref())
        )
    }

    /// Network radios with "(차단됨)".
    #[must_use]
    pub fn network_label(&self, chain_id: u64) -> String {
        let mut name = self.network_name(NetworkId::Eip155(chain_id));
        if self
            .settings
            .evm_chains
            .iter()
            .any(|def| def.chain_id == chain_id)
        {
            name.push_str(" · ");
            name.push_str(&custom_chain_badge(chain_id));
        }
        if self.evm.blocked(chain_id).is_some() {
            name.push_str(" (차단됨)");
        }
        name
    }

    /// The blocked-chain banner and the journal banner of S10.
    pub fn evm_banners(&self, items: &mut Vec<Item>) {
        let chain_id = self.settings.evm_chain_id;
        if let Some(kind) = self.evm.blocked(chain_id) {
            items.push(Item::Banner(kind.code().text(), Tone::Danger));
            if matches!(kind, MismatchKind::PinnedGenesis { .. }) {
                items.push(Item::Row(vec![Ctl::button(
                    ids::REPIN_SETTINGS,
                    "설정에서 다시 고정",
                )]));
            }
        }
        if self.evm.journal_damaged() {
            items.push(Item::Banner(
                "거래 저널이 손상되어 보내기를 멈췄습니다. (E-VLT-006)".to_owned(),
                Tone::Danger,
            ));
        }
    }

    /// Balance text of an account (muted handled by the caller).
    #[must_use]
    pub fn balance_text(&self, address: &str) -> Option<String> {
        let chain_id = self.settings.evm_chain_id;
        let address = parse_address(address).ok()?;
        let balance = self.native_balance(chain_id, &address)?;
        let state = self.evm.balances.get(&chain_id)?;
        let block = state.snapshot.as_ref()?.block;
        let mut text = format!(
            "잔액 {} (블록 {block})",
            self.native_text(chain_id, &balance)
        );
        if let Some(code) = state.error {
            let _ = write!(text, " — 갱신 실패 {}", code.code());
        }
        Some(text)
    }

    /// Tokens and activity sections of S10.
    pub fn evm_main_sections(&self, items: &mut Vec<Item>) {
        let chain_id = self.settings.evm_chain_id;
        items.push(Item::Rule);
        items.push(Item::Text("토큰 (선택 계정)".to_owned()));
        for (address, symbol, decimals, registered) in self.chain_tokens(chain_id) {
            let balance = self.token_balance(chain_id, &address).map_or_else(
                || "잔액 알 수 없음".to_owned(),
                |value| format_amount(&value, decimals, &symbol),
            );
            let label = if registered {
                symbol.clone()
            } else {
                format!("{symbol} (사용자 추가)")
            };
            items.push(Item::Text(format!("{label}   {balance}")));
            items.push(Item::Mono(format_address(&address)));
        }
        items.push(Item::Row(vec![Ctl::button(ids::TOKEN_OPEN, "토큰 추가")]));
        items.push(Item::Rule);
        items.push(Item::Text("활동 (이 지갑이 보낸 거래)".to_owned()));
        let rows = self.activity_rows();
        if rows.is_empty() {
            items.push(Item::Muted("아직 보낸 거래가 없습니다.".to_owned()));
        }
        for (index, row) in rows.into_iter().enumerate() {
            let base = ids::ACTIVITY_BASE
                .saturating_add(u16::try_from(index).unwrap_or(0).saturating_mul(8));
            items.push(Item::Text(row.head));
            items.push(Item::Muted(format!("상태: {}", row.status)));
            items.push(Item::Mono(row.hash));
            let mut buttons = vec![Ctl::button(base, "해시 복사")];
            if row.open.is_some() {
                buttons.push(Ctl::button(base.saturating_add(1), "가속"));
                buttons.push(Ctl::button(base.saturating_add(2), "취소"));
                if row.manual {
                    buttons.push(Ctl::button(base.saturating_add(3), "재전송"));
                }
                buttons.push(Ctl::button(base.saturating_add(4), "폐기"));
            }
            if self.explorer(chain_id).is_some() {
                buttons.push(Ctl::button(base.saturating_add(5), "탐색기 링크 복사"));
            }
            items.push(Item::Row(buttons));
            items.push(Item::Gap(4));
        }
    }

    /// A user chain's explorer base URL.
    #[must_use]
    pub fn explorer(&self, chain_id: u64) -> Option<String> {
        self.settings
            .evm_chains
            .iter()
            .find(|def| def.chain_id == chain_id)
            .and_then(|def| def.explorer.clone())
    }

    /// S11.
    #[expect(clippy::too_many_lines, reason = "the S11 fields in order")]
    pub fn send_screen(&self, items: &mut Vec<Item>) {
        let chain_id = self.settings.evm_chain_id;
        items.push(Item::Title(format!(
            "보내기 — {}",
            self.network_name(NetworkId::Eip155(chain_id))
        )));
        if chain_id == SEPOLIA {
            items.push(Item::Banner(
                "테스트넷 — 실제 자산이 아닙니다".to_owned(),
                Tone::Testnet,
            ));
        }
        let form = &self.evm.send;
        if let Some(info) = &form.info {
            items.push(Item::Banner(info.clone(), Tone::Warn));
        }
        if let Some(record) = self.send_in_flight() {
            items.push(Item::Banner(
                "이 계정의 이전 거래가 아직 확정되지 않았습니다. 확정된 뒤 보낼 수 있습니다."
                    .to_owned(),
                Tone::Warn,
            ));
            items.push(Item::Muted(format!(
                "nonce {} · {}",
                record.nonce,
                self.record_status(&record)
            )));
            items.push(Item::Mono(hash_text(&record.tx_hash)));
        }
        if let Some((account, _, label)) = self.selected_account() {
            items.push(Item::LabeledRow(
                "보내는 계정".to_owned(),
                vec![Ctl::button(
                    crate::ui::screens::ids::BACK_MAIN,
                    "계정 바꾸기 (메인)",
                )],
            ));
            let balance = self
                .native_balance(chain_id, &account)
                .map_or_else(String::new, |value| {
                    format!(" · {}", self.native_text(chain_id, &value))
                });
            items.push(Item::Text(format!("{label}{balance}")));
            items.push(Item::Mono(format_address(&account)));
        }
        let mut assets = Vec::new();
        let native_symbol = self
            .active_chain()
            .map_or_else(|| "ETH".to_owned(), |chain| chain.native_symbol);
        assets.push(Ctl::radio(
            ids::SEND_ASSET_BASE,
            &native_symbol,
            form.asset == SendAsset::Native,
            true,
        ));
        for (index, (address, symbol, _, registered)) in
            self.chain_tokens(chain_id).into_iter().enumerate()
        {
            let text = if registered {
                symbol
            } else {
                format!("{symbol} (사용자 추가)")
            };
            assets.push(Ctl::radio(
                ids::SEND_ASSET_BASE
                    .saturating_add(u16::try_from(index.saturating_add(1)).unwrap_or(0)),
                &text,
                form.asset == SendAsset::Token(address),
                false,
            ));
        }
        items.push(Item::LabeledRow("자산".to_owned(), assets));
        if let SendAsset::Token(token) = form.asset {
            items.push(Item::Muted(format!(
                "토큰 컨트랙트 {}",
                format_address(&token)
            )));
        }
        items.push(Item::LabeledRow(
            "받는 주소".to_owned(),
            vec![
                Ctl::edit(ids::SEND_TO_EDIT, &form.to_text, 430, false, 64),
                Ctl::button(ids::SEND_PICK, "주소록에서 선택"),
            ],
        ));
        if form.picker {
            self.picker_rows(items);
        }
        if let Some(code) = form.recipient_error {
            items.push(Item::Banner(code.text(), Tone::Danger));
        }
        if let Some((address, notes)) = &form.recipient {
            items.push(Item::Mono(format_address(address)));
            for note in notes {
                items.push(Item::Banner(
                    note.text(),
                    if note.is_warning() {
                        Tone::Warn
                    } else {
                        Tone::Info
                    },
                ));
            }
            if form.contract == Some(true) && form.asset == SendAsset::Native {
                items.push(Item::Banner(
                    crate::flow::evm::form::AddressNote::Contract.text(),
                    Tone::Warn,
                ));
            }
            if notes
                .iter()
                .any(crate::flow::evm::form::AddressNote::needs_ack)
            {
                items.push(Item::Row(vec![Ctl::check(
                    ids::SEND_ACK,
                    "주소 전체를 직접 확인했습니다",
                    form.ack,
                )]));
            }
        }
        items.push(Item::LabeledRow(
            "금액".to_owned(),
            vec![
                Ctl::edit(ids::SEND_AMOUNT_EDIT, &form.amount_text, 260, false, 128),
                Ctl::button(ids::SEND_MAX, "최대"),
            ],
        ));
        if let Some(code) = form.amount_error {
            items.push(Item::Banner(code.text(), Tone::Danger));
        }
        if let (Some(quote), Some(chain)) = (&form.quote, self.active_chain()) {
            items.push(Item::Muted(quote.line(&chain)));
            if let Some(violation) = &quote.cap_violation {
                items.push(Item::Banner(violation.clone(), Tone::Danger));
            }
            if quote.estimate_failed {
                items.push(Item::Banner(
                    "가스 추정 실패 — 거래가 실패할 수 있습니다 (승인 창에서 확인)".to_owned(),
                    Tone::Warn,
                ));
            }
        }
        if let Some(code) = form.quote_error {
            items.push(Item::Banner(code.text(), Tone::Danger));
        }
        items.push(Item::Row(vec![
            Ctl::button(ids::SEND_REVIEW, "검토").enabled(self.can_review()),
            Ctl::button(ids::SEND_CANCEL, "취소"),
        ]));
        items.push(Item::Muted(
            "수수료는 지갑이 계산합니다. 검토를 누르면 승인 창에서 시뮬레이션 결과와 함께 확인합니다."
                .to_owned(),
        ));
    }

    fn picker_rows(&self, items: &mut Vec<Item>) {
        let filter = self.evm.send.to_text.trim().to_ascii_lowercase();
        let mut shown = 0_u16;
        for entry in self.known_addresses() {
            let hex = entry.address.to_lower_hex();
            if !filter.is_empty()
                && !hex.contains(filter.trim_start_matches("0x"))
                && !entry.name.to_ascii_lowercase().contains(&filter)
            {
                continue;
            }
            if shown >= ids::SEND_PICK_SPAN {
                break;
            }
            let prefix = if entry.mine {
                "내 계정"
            } else {
                "주소록"
            };
            items.push(Item::Row(vec![Ctl::button(
                ids::SEND_PICK_BASE.saturating_add(shown),
                &format!("{prefix}: {}", entry.name),
            )]));
            items.push(Item::Mono(format_address(&entry.address)));
            shown = shown.saturating_add(1);
        }
        if shown == 0 {
            items.push(Item::Muted("일치하는 주소록 항목이 없습니다.".to_owned()));
        }
    }

    /// The picker entries in display order (for the command handler).
    #[must_use]
    pub fn picker_entries(&self) -> Vec<Address> {
        let filter = self.evm.send.to_text.trim().to_ascii_lowercase();
        self.known_addresses()
            .into_iter()
            .filter(|entry| {
                filter.is_empty()
                    || entry
                        .address
                        .to_lower_hex()
                        .contains(filter.trim_start_matches("0x"))
                    || entry.name.to_ascii_lowercase().contains(&filter)
            })
            .map(|entry| entry.address)
            .take(usize::from(ids::SEND_PICK_SPAN))
            .collect()
    }

    /// S11 result.
    pub fn send_result_screen(&self, items: &mut Vec<Item>) {
        items.push(Item::Title("보내기 결과".to_owned()));
        if let Some(sent) = self.evm.sent {
            items.push(Item::Text("전송했습니다.".to_owned()));
            items.push(Item::Mono(hash_text(&sent.tx_hash)));
            let status = self
                .evm
                .records()
                .iter()
                .find(|record| record.tx_hash == sent.tx_hash)
                .map_or_else(
                    || "전송 확인 중".to_owned(),
                    |record| self.record_status(record),
                );
            items.push(Item::Muted(format!(
                "상태: {status} ({})",
                self.network_name(NetworkId::Eip155(sent.chain_id))
            )));
        }
        items.push(Item::Row(vec![Ctl::button(
            crate::ui::screens::ids::BACK_MAIN,
            "메인으로",
        )]));
    }

    /// S12.
    pub fn receive_screen(&self, items: &mut Vec<Item>) {
        let chain_id = self.settings.evm_chain_id;
        items.push(Item::Title("받기".to_owned()));
        if self.mode == AppMode::BackupPending {
            items.push(Item::Banner(
                "백업 확인 전입니다. 확인을 마치기 전에는 큰 금액을 받지 마세요.".to_owned(),
                Tone::Warn,
            ));
        }
        let Some((address, source, label)) = self.selected_account() else {
            items.push(Item::Muted("계정을 불러오는 중…".to_owned()));
            return;
        };
        items.push(Item::Text(format!(
            "{label} · {}",
            self.network_name(NetworkId::Eip155(chain_id))
        )));
        if chain_id == SEPOLIA {
            items.push(Item::Banner(
                "테스트넷 주소입니다.".to_owned(),
                Tone::Testnet,
            ));
        }
        items.push(Item::Mono(format_address(&address)));
        items.push(Item::Muted(match source {
            yw_core::vault::EvmKeySource::Derived(index) => {
                format!("m/44'/60'/0'/0/{}", index.get())
            }
            yw_core::vault::EvmKeySource::Raw(_) => "가져온 개인키".to_owned(),
        }));
        items.push(Item::Qr(crate::ui::qr::evm_payload(&address, chain_id)));
        items.push(Item::Row(vec![
            Ctl::button(ids::COPY_ADDRESS, "주소 복사"),
            Ctl::button(crate::ui::screens::ids::BACK_MAIN, "← 메인"),
        ]));
        items.push(Item::Muted(
            "주소를 복사한 뒤 붙여넣은 곳에서 주소 전체를 확인하세요.".to_owned(),
        ));
    }

    /// S14.
    pub fn book_screen(&self, items: &mut Vec<Item>) {
        items.push(Item::Row(vec![Ctl::button(
            crate::ui::screens::ids::BACK_MAIN,
            "← 메인",
        )]));
        items.push(Item::Title("주소록".to_owned()));
        let form = &self.evm.book;
        if let Some(message) = &form.message {
            items.push(Item::Banner(message.clone(), Tone::Danger));
        }
        let editing = form.editing.is_some();
        let mut address = Ctl::edit(ids::BOOK_ADDR_EDIT, &form.address, 430, false, 64);
        if editing {
            address = address.readonly();
        }
        items.push(Item::LabeledRow("주소".to_owned(), vec![address]));
        items.push(Item::LabeledRow(
            "이름".to_owned(),
            vec![Ctl::edit(ids::BOOK_LABEL_EDIT, &form.label, 260, false, 64)],
        ));
        items.push(Item::Row(vec![Ctl::check(
            ids::BOOK_VERIFIED,
            "다른 경로(전화·대면 등)로 이 주소를 확인했습니다",
            form.verified,
        )]));
        let mut row = vec![Ctl::button(
            ids::BOOK_SAVE,
            if editing { "저장" } else { "추가" },
        )];
        if editing {
            row.push(Ctl::button(ids::BOOK_CANCEL, "취소"));
        }
        items.push(Item::Row(row));
        items.push(Item::Rule);
        let entries = self
            .meta
            .as_ref()
            .map(crate::meta::Meta::book)
            .unwrap_or_default();
        if entries.is_empty() {
            items.push(Item::Muted("주소록이 비어 있습니다.".to_owned()));
        }
        for (index, entry) in entries.iter().enumerate() {
            let base = ids::BOOK_ROW_BASE
                .saturating_add(u16::try_from(index).unwrap_or(0).saturating_mul(2));
            let verified = if entry.verified { " ✓ 확인됨" } else { "" };
            items.push(Item::Text(format!("{}{verified}", entry.label)));
            let shown = parse_address(&entry.address).map_or_else(
                |_| entry.address.clone(),
                |address| format_address(&address),
            );
            items.push(Item::Mono(shown));
            items.push(Item::Row(vec![
                Ctl::button(base, "편집"),
                Ctl::button(base.saturating_add(1), "삭제"),
            ]));
        }
    }

    /// S16.
    pub fn token_screen(&self, items: &mut Vec<Item>) {
        let chain_id = self.settings.evm_chain_id;
        items.push(Item::Row(vec![Ctl::button(
            crate::ui::screens::ids::BACK_MAIN,
            "← 메인",
        )]));
        items.push(Item::Title(format!(
            "토큰 추가 — {}",
            self.network_name(NetworkId::Eip155(chain_id))
        )));
        let form = &self.evm.token;
        if let Some(message) = &form.message {
            items.push(Item::Banner(message.clone(), Tone::Info));
        }
        items.push(Item::LabeledRow(
            "컨트랙트 주소".to_owned(),
            vec![
                Ctl::edit(ids::TOKEN_ADDR_EDIT, &form.address, 430, false, 64),
                Ctl::button(ids::TOKEN_LOOKUP, "조회"),
            ],
        ));
        if let Some((token, meta)) = &form.found {
            let decimals = meta
                .decimals
                .map_or_else(|| "읽을 수 없음".to_owned(), |value| value.to_string());
            let symbol = meta
                .symbol
                .as_deref()
                .filter(|symbol| crate::text::is_symbol(symbol))
                .unwrap_or("(표시할 수 없는 기호)");
            items.push(Item::Mono(format_address(token)));
            items.push(Item::Text(format!(
                "decimals: {decimals}, 체인에서 읽은 기호: {symbol}"
            )));
            items.push(Item::LabeledRow(
                "라벨".to_owned(),
                vec![Ctl::edit(
                    ids::TOKEN_LABEL_EDIT,
                    &form.label,
                    260,
                    false,
                    64,
                )],
            ));
            items.push(Item::Row(vec![Ctl::button(ids::TOKEN_SAVE, "저장")]));
        }
    }

    /// The S15 `EVM 체인` section with fee caps.
    pub fn chains_section(&self, items: &mut Vec<Item>) {
        items.push(Item::Title("EVM 체인".to_owned()));
        for (index, chain_id) in self.settings.registered_evm().into_iter().enumerate() {
            let user = self
                .settings
                .evm_chains
                .iter()
                .find(|def| def.chain_id == chain_id);
            let info = crate::flow::evm::chain_info(&self.settings, chain_id);
            let (symbol, decimals, simulation) =
                info.as_ref().map_or((String::new(), 18, "auto"), |chain| {
                    (
                        chain.native_symbol.clone(),
                        chain.native_decimals,
                        chain.simulation.as_str(),
                    )
                });
            let state = match self.evm.chain_checks.get(&chain_id) {
                Some(crate::flow::evm::ChainCheck::Verified { .. }) => "연결됨".to_owned(),
                Some(crate::flow::evm::ChainCheck::Mismatch(kind)) => {
                    format!("차단 {}", kind.code().code())
                }
                _ => "확인 전".to_owned(),
            };
            let genesis = self.pinned_genesis(chain_id).map_or_else(
                || "첫 연결 때 고정".to_owned(),
                |hash| crate::text::hash32_text(&hash),
            );
            items.push(Item::Text(format!(
                "{} (chainId {chain_id}) · {symbol}, 소수 {decimals} · 시뮬레이션 {simulation} · {state}",
                self.network_name(NetworkId::Eip155(chain_id))
            )));
            items.push(Item::Muted(format!(
                "엔드포인트: {}",
                self.endpoint_text(chain_id)
            )));
            if let Some(def) = user {
                items.push(Item::Muted(custom_chain_badge(chain_id)));
                let mut ids_text = Vec::new();
                if let Some(subdomain) = &def.quicknode_subdomain {
                    ids_text.push(format!("QuickNode 서브도메인 {subdomain}"));
                }
                if let Some(label) = &def.alchemy_label {
                    ids_text.push(format!("알케미 라벨 {label}"));
                }
                if let Some(explorer) = &def.explorer {
                    ids_text.push(format!("탐색기 {explorer}"));
                }
                if !ids_text.is_empty() {
                    items.push(Item::Muted(ids_text.join(" · ")));
                }
            }
            items.push(Item::Mono(format!("genesis {genesis}")));
            let base = ids::CHAIN_ROW_BASE
                .saturating_add(u16::try_from(index).unwrap_or(0).saturating_mul(4));
            let mut row = Vec::new();
            if user.is_some() {
                row.push(Ctl::button(base, "편집"));
                row.push(
                    Ctl::button(base.saturating_add(1), "삭제")
                        .enabled(matches!(self.mode, AppMode::Unlocked { .. })),
                );
            }
            if matches!(
                self.evm.blocked(chain_id),
                Some(MismatchKind::PinnedGenesis { .. })
            ) && (user.is_some() || chain_id == HYPEREVM_MAINNET)
            {
                row.push(Ctl::button(base.saturating_add(2), "다시 고정"));
            }
            if !row.is_empty() {
                items.push(Item::Row(row));
            }
            items.push(Item::Gap(6));
        }
        if let Some(repin) = &self.evm.repin
            && let Some(message) = &repin.message
        {
            items.push(Item::Banner(message.clone(), Tone::Info));
        }
        items.push(Item::Row(vec![Ctl::button(ids::CHAIN_ADD, "추가")]));
        items.push(Item::Rule);
        self.caps_section(items);
    }

    fn caps_section(&self, items: &mut Vec<Item>) {
        items.push(Item::Title("EVM 수수료 상한".to_owned()));
        let selected = self.evm.caps.as_ref().map(|caps| caps.chain_id);
        let radios: Vec<Ctl> = self
            .settings
            .registered_evm()
            .into_iter()
            .enumerate()
            .map(|(index, chain_id)| {
                Ctl::radio(
                    ids::CAPS_CHAIN_BASE.saturating_add(u16::try_from(index).unwrap_or(0)),
                    &self.network_name(NetworkId::Eip155(chain_id)),
                    selected == Some(chain_id),
                    index == 0,
                )
            })
            .collect();
        items.push(Item::LabeledRow("체인".to_owned(), radios));
        let Some(caps) = &self.evm.caps else {
            items.push(Item::Muted("상한을 바꿀 체인을 고르세요.".to_owned()));
            return;
        };
        if let Some(message) = &caps.message {
            items.push(Item::Banner(message.clone(), Tone::Info));
        }
        let symbol = crate::flow::evm::chain_info(&self.settings, caps.chain_id)
            .map_or_else(String::new, |chain| chain.native_symbol);
        items.push(Item::LabeledRow(
            "maxFee 상한 (gwei)".to_owned(),
            vec![Ctl::edit(ids::CAPS_FEE_EDIT, &caps.fee, 160, false, 32)],
        ));
        items.push(Item::LabeledRow(
            "tip 상한 (gwei)".to_owned(),
            vec![Ctl::edit(ids::CAPS_TIP_EDIT, &caps.tip, 160, false, 32)],
        ));
        items.push(Item::LabeledRow(
            format!("총 최대 수수료 ({symbol})"),
            vec![Ctl::edit(ids::CAPS_TOTAL_EDIT, &caps.total, 160, false, 40)],
        ));
        items.push(Item::Row(vec![
            Ctl::button(ids::CAPS_SAVE, "저장"),
            Ctl::button(ids::CAPS_DEFAULT, "기본값으로"),
        ]));
        items.push(Item::Muted(
            "범위: maxFee 1–10,000 gwei, tip 0.01–10,000 gwei(maxFee 상한 이하), 총 0.0001–10. 다음 준비부터 적용됩니다."
                .to_owned(),
        ));
    }

    /// S17.
    pub fn chain_edit_screen(&self, items: &mut Vec<Item>) {
        let Some(form) = &self.evm.chain_form else {
            return;
        };
        items.push(Item::Title(if form.editing.is_some() {
            "EVM 체인 편집".to_owned()
        } else {
            "EVM 체인 추가".to_owned()
        }));
        if let Some(message) = &form.message {
            items.push(Item::Banner(message.clone(), Tone::Info));
        }
        let mut chain_id = Ctl::edit(ids::CHAIN_ID_EDIT, &form.chain_id, 260, false, 20);
        if form.editing.is_some() {
            chain_id = chain_id.readonly();
        }
        items.push(Item::LabeledRow("chainId".to_owned(), vec![chain_id]));
        items.push(Item::LabeledRow(
            "이름".to_owned(),
            vec![Ctl::edit(ids::CHAIN_NAME_EDIT, &form.name, 260, false, 64)],
        ));
        items.push(Item::LabeledRow(
            "네이티브 심볼".to_owned(),
            vec![Ctl::edit(
                ids::CHAIN_SYMBOL_EDIT,
                &form.symbol,
                160,
                false,
                11,
            )],
        ));
        items.push(Item::LabeledRow(
            "소수 자릿수".to_owned(),
            vec![Ctl::edit(
                ids::CHAIN_DECIMALS_EDIT,
                &form.decimals,
                80,
                false,
                2,
            )],
        ));
        let template = self.settings.rpc_template;
        let credential = self.apikeys.credential(template).is_some();
        let hint = match template {
            crate::settings::RpcTemplate::QuickNode => format!(
                "https:// URL 또는 QuickNode 서브도메인(예 base-sepolia). 자격 정보: {}",
                if credential { "설정됨" } else { "없음" }
            ),
            crate::settings::RpcTemplate::Alchemy => format!(
                "https:// URL 또는 알케미 라벨(예 base-sepolia). 자격 정보: {}",
                if credential { "설정됨" } else { "없음" }
            ),
            crate::settings::RpcTemplate::Manual => "https:// URL (직접 입력 템플릿)".to_owned(),
        };
        items.push(Item::LabeledRow(
            "RPC".to_owned(),
            vec![Ctl::edit(ids::CHAIN_RPC_EDIT, "", 430, true, 2_048)],
        ));
        items.push(Item::Muted(if form.editing.is_some() {
            format!("{hint} · 비워 두면 기존 URL을 유지합니다.")
        } else {
            hint
        }));
        items.push(Item::LabeledRow(
            "탐색기 URL(선택)".to_owned(),
            vec![Ctl::edit(
                ids::CHAIN_EXPLORER_EDIT,
                &form.explorer,
                430,
                false,
                256,
            )],
        ));
        items.push(Item::LabeledRow(
            "시뮬레이션".to_owned(),
            vec![
                Ctl::radio(
                    ids::CHAIN_SIM_AUTO,
                    "auto (항상 시도)",
                    !form.unsupported,
                    true,
                ),
                Ctl::radio(
                    ids::CHAIN_SIM_UNSUPPORTED,
                    "unsupported (호출하지 않음)",
                    form.unsupported,
                    false,
                ),
            ],
        ));
        items.push(Item::Row(vec![
            Ctl::button(ids::CHAIN_SAVE, "저장").enabled(form.pending.is_none()),
            Ctl::button(ids::CHAIN_CANCEL, "취소"),
        ]));
    }

    /// T-CHAIN-PIN text.
    #[must_use]
    pub fn chain_pin_text(&self) -> String {
        let Some((valid, Some(genesis))) = self
            .evm
            .chain_form
            .as_ref()
            .and_then(|form| form.pending.clone())
        else {
            return String::new();
        };
        let rpc = match &valid.rpc {
            crate::flow::evm::user_chain::RpcSpec::Template {
                template, entry, ..
            } => match template {
                crate::settings::RpcTemplate::QuickNode => format!("QuickNode 서브도메인 {entry}"),
                _ => format!("알케미 라벨 {entry}"),
            },
            crate::flow::evm::user_chain::RpcSpec::Url(url) => crate::apikeys::mask_url(url),
            crate::flow::evm::user_chain::RpcSpec::Keep => String::new(),
        };
        format!(
            "이 체인의 제네시스 해시를 지금 받은 값으로 고정합니다. 이후 연결할 때마다 chainId와 이 값을 비교하고, 다르면 이 체인을 쓰지 않습니다. 해시가 공식 자료(체인 문서·탐색기)의 값과 같은지 확인하세요.\nchainId {}\n이름 {}\nRPC {rpc}\n제네시스 {}",
            valid.chain_id,
            valid.name,
            crate::text::hash32_text(&genesis)
        )
    }

    /// T-CHAIN-REPIN text.
    #[must_use]
    pub fn chain_repin_text(&self) -> String {
        let Some(repin) = &self.evm.repin else {
            return String::new();
        };
        let old = self
            .pinned_genesis(repin.chain_id)
            .map_or_else(String::new, |hash| crate::text::hash32_text(&hash));
        let new = repin
            .new
            .map_or_else(String::new, |hash| crate::text::hash32_text(&hash));
        format!(
            "고정된 제네시스 해시와 RPC가 알려준 값이 다릅니다. RPC가 다른 체인을 가리키거나 체인이 새로 시작되었을 수 있습니다. 새 값을 공식 자료로 확인한 경우에만 다시 고정하세요.\n고정된 값 {old}\n새 값     {new}"
        )
    }

    /// The default label of a built-in chain (for tests and the network list).
    #[must_use]
    pub fn builtin_name(chain_id: u64) -> Option<String> {
        builtin_chain(chain_id).map(|chain| chain.name)
    }

    /// Error text for an amount.
    #[must_use]
    pub fn amount_text(value: &U256, decimals: u8) -> String {
        format_units(value, decimals)
    }

    /// The fixed E-KEY-005 text (S10 without endpoint).
    #[must_use]
    pub fn no_endpoint_text() -> String {
        ErrorCode::Key005.text()
    }
}
