//! EVM screen contents (M4, spec/04 §2.6–§2.8, §2.10, §2.11, §2.16, §2.17): the S10 network,
//! balance, token and activity sections, S11 send, S12 receive, S14 address book, S16 token add,
//! the S15 `EVM 체인` section with fee caps, S17 chain add/edit and their confirmation texts.

use yw_core::evm::address::{Address, parse_address};
use yw_core::evm::amount::{U256, format_amount, format_units};
use yw_core::evm::chain::{HYPEREVM_MAINNET, SEPOLIA, builtin_chain};
use yw_core::evm::display::format_address;
use yw_core::journal::evm::{EvmRecord, ReceiptStatus, TxState, groups};
use yw_core::lang::Lang;

use crate::app::{App, AppMode};
use crate::app_book::{BookTarget, PromptPlace};
use crate::app_evm::{SendAsset, hash_text};
use crate::app_tokens::EvmTokenRow;
use crate::errors::ErrorCode;
use crate::flow::evm::MismatchKind;
use crate::flow::evm::form::tx_recipients;
use crate::flow::evm::track::BroadcastOutcome;
use crate::logging::format_utc;
use crate::meta::{ActivityEntry, BookChain};
use crate::network::NetworkId;
use crate::token_view::RowPlace;
use crate::ui::badge::Badge;
use crate::ui::main_window::{Ctl, Item, Tone};
use crate::ui::qr::{EvmQrKind, RECEIVE_SHARED_ADDRESS_NOTE};

pub mod text;

/// T-CUSTOM-CHAIN (spec/04 §2.16): the user-chain badge of S10, S15 and the A01 header.
#[must_use]
pub fn custom_chain_badge(lang: yw_core::lang::Lang, chain_id: u64) -> String {
    crate::ui::approval_text::BADGE_CUSTOM_CHAIN.fill(lang, [&chain_id.to_string()])
}

/// The S15 `EVM 체인` add note and button (spec/04 §2.11): any other L1/L2 is a user chain.
fn chain_add_row(lang: Lang, items: &mut Vec<Item>) {
    items.push(Item::Help(text::CHAIN_ADD_HELP.get(lang).to_owned()));
    items.push(Item::Row(vec![Ctl::button(
        ids::CHAIN_ADD,
        text::CHAIN_ADD.get(lang),
    )]));
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
    /// S10 network drop-down: opens / closes the list (2026-11-11; the entries keep the chip
    /// ids `screens::ids::NETWORK_BASE`…).
    pub const NETWORK_PICKER: u16 = 906;
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
    /// Send form `숨긴 토큰 n개 보기` (asset radios of hidden tokens).
    pub const SEND_HIDDEN_TOGGLE: u16 = 917;
    /// Asset radios: native, then the chain's registry tokens and the user's tokens (≤ 100 per
    /// network, spec/02 §5.3). The old 920..960 span (40) let the 40th token reuse the first
    /// picker id; see `ui::command_ids`.
    pub const SEND_ASSET_BASE: u16 = 3_000;
    /// Asset radio span.
    pub const SEND_ASSET_SPAN: u16 = 200;
    /// Picker rows.
    pub const SEND_PICK_BASE: u16 = 960;
    /// Picker span.
    pub const SEND_PICK_SPAN: u16 = 40;
    /// 주소 복사.
    pub const COPY_ADDRESS: u16 = 1_000;
    /// Receive QR: EIP-681 (`ui::qr::EvmQrKind::Eip681`).
    pub const QR_EIP681: u16 = 1_001;
    /// Receive QR: the bare address (`ui::qr::EvmQrKind::PlainAddress`).
    pub const QR_PLAIN: u16 = 1_002;
    /// Token card `주소 복사` of the contract (one per row, indexed like [`TOKEN_ROW_BASE`];
    /// 2026-11-11).
    pub const TOKEN_COPY_BASE: u16 = 1_010;
    /// Token contract copy span (120 rows).
    pub const TOKEN_COPY_SPAN: u16 = 120;
    /// Token address edit.
    pub const TOKEN_ADDR_EDIT: u16 = 2_100;
    /// 조회.
    pub const TOKEN_LOOKUP: u16 = 2_101;
    /// Token label edit.
    pub const TOKEN_LABEL_EDIT: u16 = 2_102;
    /// Token save.
    pub const TOKEN_SAVE: u16 = 2_103;
    /// Token card `잔액 0인 토큰 숨기기`.
    pub const TOKEN_HIDE_ZERO: u16 = 2_104;
    /// Token card `숨긴 토큰 n개 보기` / `접기`.
    pub const TOKEN_HIDDEN_TOGGLE: u16 = 2_105;
    /// Settings EVM-chains section.
    pub const SECTION_CHAINS: u16 = 2_200;
    /// 추가.
    pub const CHAIN_ADD: u16 = 2_201;
    /// Chain rows (3 ids per row: 편집, 삭제, 다시 고정).
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
    /// Activity rows ([`ACTIVITY_STRIDE`] ids per row, at most `MAX_ACTIVITY_ROWS` = 50 rows).
    pub const ACTIVITY_BASE: u16 = 2_500;
    /// Ids per activity row (해시 복사, 수수료 올리기, 취소, 재전송, 폐기, 탐색기 링크 복사, 이 주소
    /// 저장, 탐색기에서 열기).
    pub const ACTIVITY_STRIDE: u16 = 8;
    /// Activity span (50 rows × 8).
    pub const ACTIVITY_SPAN: u16 = 400;
    /// Token card rows ([`TOKEN_ROW_STRIDE`] ids per row: 숨기기/다시 보이기, 삭제), indexed by
    /// the token's position in `App::chain_tokens` (registry tokens + ≤ 100 user tokens).
    pub const TOKEN_ROW_BASE: u16 = 3_200;
    /// Ids per token row.
    pub const TOKEN_ROW_STRIDE: u16 = 2;
    /// Token rows span (120 rows × 2).
    pub const TOKEN_ROW_SPAN: u16 = 240;
    /// Token card `{기호} 보내기` links (one per row, indexed like [`TOKEN_ROW_BASE`]).
    pub const TOKEN_SEND_BASE: u16 = 3_440;
    /// Token send links span (120 rows).
    pub const TOKEN_SEND_SPAN: u16 = 120;
    /// Activity `이전 활동 n건 더 보기 ▸` / `접기 ▾`.
    pub const ACTIVITY_MORE: u16 = 3_560;
    /// Activity rows drawn before `이전 활동 n건 더 보기`.
    pub const ACTIVITY_FIRST: usize = 10;
    /// T-CHAIN-REPIN-ACK check.
    pub const REPIN_CHECK: u16 = 6_600;

    /// What a token-row id does.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TokenAction {
        /// `숨기기` / `다시 보이기` of the row.
        ToggleHidden(usize),
        /// `삭제` (user tokens only).
        Delete(usize),
    }

    /// The button id of a token action (`None` beyond the span).
    #[must_use]
    pub fn token_row_id(action: TokenAction) -> Option<u16> {
        let (row, extra) = match action {
            TokenAction::ToggleHidden(row) => (row, 0),
            TokenAction::Delete(row) => (row, 1),
        };
        let offset = u16::try_from(row)
            .ok()?
            .checked_mul(TOKEN_ROW_STRIDE)?
            .checked_add(extra)?;
        (offset < TOKEN_ROW_SPAN).then(|| TOKEN_ROW_BASE.saturating_add(offset))
    }

    /// The token action of `id`, if it is a token-row id.
    #[must_use]
    pub fn token_action(id: u16) -> Option<TokenAction> {
        let offset = id
            .checked_sub(TOKEN_ROW_BASE)
            .filter(|offset| *offset < TOKEN_ROW_SPAN)?;
        let row = usize::from(offset / TOKEN_ROW_STRIDE);
        Some(if offset % TOKEN_ROW_STRIDE == 0 {
            TokenAction::ToggleHidden(row)
        } else {
            TokenAction::Delete(row)
        })
    }

    /// Every fixed id of this module (`ui::command_ids` checks them against all ranges).
    pub const FIXED: &[u16] = &[
        SEND_OPEN,
        RECEIVE_OPEN,
        REFRESH,
        BOOK_OPEN,
        TOKEN_OPEN,
        REPIN_SETTINGS,
        NETWORK_PICKER,
        SEND_TO_EDIT,
        SEND_AMOUNT_EDIT,
        SEND_MAX,
        SEND_PICK,
        SEND_ACK,
        SEND_REVIEW,
        SEND_CANCEL,
        SEND_HIDDEN_TOGGLE,
        COPY_ADDRESS,
        QR_EIP681,
        QR_PLAIN,
        TOKEN_ADDR_EDIT,
        TOKEN_LOOKUP,
        TOKEN_LABEL_EDIT,
        TOKEN_SAVE,
        TOKEN_HIDE_ZERO,
        TOKEN_HIDDEN_TOGGLE,
        SECTION_CHAINS,
        CHAIN_ADD,
        CHAIN_ID_EDIT,
        CHAIN_NAME_EDIT,
        CHAIN_SYMBOL_EDIT,
        CHAIN_DECIMALS_EDIT,
        CHAIN_RPC_EDIT,
        CHAIN_EXPLORER_EDIT,
        CHAIN_SIM_AUTO,
        CHAIN_SIM_UNSUPPORTED,
        CHAIN_SAVE,
        CHAIN_CANCEL,
        CAPS_FEE_EDIT,
        CAPS_TIP_EDIT,
        CAPS_TOTAL_EDIT,
        CAPS_SAVE,
        CAPS_DEFAULT,
        REPIN_CHECK,
        ACTIVITY_MORE,
    ];
}

/// Status words of activity rows.
fn activity_status(lang: Lang, word: &str) -> &'static str {
    match word {
        "succeeded" => text::STATUS_SUCCEEDED,
        "failed" => text::STATUS_FAILED,
        "dropped" => text::STATUS_DROPPED,
        "replaced" => text::STATUS_REPLACED,
        "expired" => text::STATUS_EXPIRED,
        "rejected" => text::STATUS_REJECTED,
        "conflicted" => text::STATUS_CONFLICTED,
        _ => text::STATUS_STOPPED,
    }
    .get(lang)
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
    /// The recipient (decoded token recipient for ERC-20 transfers) for `이 주소 저장`.
    pub counterparty: Option<Address>,
}

impl App {
    /// The heading line of an activity row's recipient (2026-11-08, like Solana and Zcash):
    /// "받는 주소" with, display only, the address-book or own-account name. The address follows
    /// on its own copy line (2026-11-11: sent rows come only from the wallet's own signed
    /// journal, so their recipient may be copied; the received history's senders never are).
    fn recipient_items(&self, address: &Address, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let lower = address.to_lower_hex();
        let name = self
            .meta
            .as_ref()
            .and_then(|meta| {
                meta.contacts(BookChain::Evm)
                    .into_iter()
                    .find(|contact| contact.address == lower)
            })
            .map(|contact| text::TO_BOOK.fill(lang, [&contact.label]))
            .or_else(|| {
                self.account_rows()
                    .into_iter()
                    .find(|(_, _, shown, _)| shown.eq_ignore_ascii_case(&lower))
                    .map(|(pref, label, _, _)| {
                        text::TO_MINE.fill(lang, [&self.evm_pref_title(pref, &label)])
                    })
            })
            .unwrap_or_default();
        items.push(Item::Help(text::RECIPIENT.fill(lang, [&name])));
    }

    /// An account row's name with its recovery phrase while the wallet has several.
    fn evm_pref_title(&self, pref: crate::meta::EvmAccountPref, label: &str) -> String {
        match pref {
            crate::meta::EvmAccountPref::Index(_) => self.mnemonic_tagged(label, None),
            crate::meta::EvmAccountPref::Mnemonic(id, _) => self.mnemonic_tagged(label, Some(id)),
            crate::meta::EvmAccountPref::Record(_) | crate::meta::EvmAccountPref::Hardware(_) => {
                label.to_owned()
            }
        }
    }

    fn account_label(&self, address: &str) -> String {
        self.account_rows()
            .into_iter()
            .find(|(_, _, shown, _)| shown.eq_ignore_ascii_case(address))
            .map_or_else(
                || address.to_owned(),
                |(pref, label, _, _)| self.evm_pref_title(pref, &label),
            )
    }

    fn record_status(&self, record: &EvmRecord) -> String {
        let lang = self.settings.language;
        let note = self.evm.notes.get(&record.tx_hash).copied();
        match record.state {
            TxState::Signed => match note {
                Some(BroadcastOutcome::HashMismatch) => text::REC_HASH_MISMATCH,
                Some(BroadcastOutcome::Rejected { known: false }) => text::REC_SEND_FAILED,
                Some(BroadcastOutcome::Unconfirmed { .. }) | None => text::REC_CONFIRMING,
                _ => text::REC_SIGNED,
            }
            .get(lang)
            .to_owned(),
            TxState::Broadcast => text::REC_BROADCAST.get(lang).to_owned(),
            // One confirmation is final; `Included` only remains in records of older builds
            // until the next tracking round finalizes them.
            TxState::Included | TxState::Finalized => {
                if record.receipt_status == ReceiptStatus::Failure {
                    text::REC_FINAL_FAILED
                } else {
                    text::REC_FINAL
                }
                .fill(lang, [&record.included_block_number.to_string()])
            }
            TxState::Dropped => {
                if record.has_flag(yw_core::journal::evm::FLAG_USER_DISCARDED) {
                    text::STATUS_DROPPED.get(lang).to_owned()
                } else {
                    text::REC_NONCE_USED.get(lang).to_owned()
                }
            }
            TxState::Replaced => text::STATUS_REPLACED.get(lang).to_owned(),
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
            // The nonce only matters while the group is open (speed-up, cancel).
            let nonce = if open {
                format!(" · nonce {}", key.nonce)
            } else {
                String::new()
            };
            rows.push(ActivityRowView {
                head: format!(
                    "{} · {} · {}{nonce}",
                    format_local(shown.created_unix_ms),
                    self.account_label(&shown.account.to_lower_hex()),
                    shown.label,
                ),
                status: self.record_status(shown),
                hash,
                open: open.then_some(key),
                manual,
                counterparty: shown.tx().and_then(|tx| tx_recipients(&tx).last().copied()),
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
        let lang = self.settings.language;
        let amount = U256::from_decimal_str(&entry.amount).unwrap_or(U256::ZERO);
        let mut value = if entry.asset == "native" {
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
                    || text::RAW_UNITS.fill(lang, [&amount.to_decimal_string()]),
                    |(_, symbol, decimals, _)| format_amount(&amount, decimals, &symbol),
                )
        };
        // History stays visible for hidden tokens, tagged so the row is not a surprise.
        if parse_address(&entry.asset).is_ok_and(|token| self.evm_token_hidden(chain_id, &token)) {
            value.push_str(text::HIDDEN_TOKEN_TAG.get(lang));
        }
        ActivityRowView {
            head: format!(
                "{} · {} · {} · {value}",
                format_local(entry.time_unix_ms),
                self.account_label(&entry.account),
                entry.title
            ),
            status: activity_status(lang, &entry.status).to_owned(),
            hash: entry.tx_id.clone(),
            open: None,
            manual: false,
            counterparty: parse_address(&entry.counterparty).ok(),
        }
    }

    /// The S10 status line (spec/04 §2.6).
    #[must_use]
    pub fn evm_status_line(&self) -> String {
        let chain_id = self.settings.evm_chain_id;
        let network = NetworkId::Eip155(chain_id);
        let lang = self.settings.language;
        let browser = crate::app_browser::status_text(lang, self.browser.as_ref());
        let rpc = if !self.apikeys.has(crate::apikeys::KeyName::Rpc(network)) {
            text::RPC_NO_ADDRESS.get(lang)
        } else if let Some(kind) = self.evm.blocked(chain_id) {
            return text::RPC_BLOCKED.fill(lang, [kind.code().code(), &browser]);
        } else if self
            .evm
            .balances
            .get(&chain_id)
            .is_some_and(|state| state.error.is_some())
        {
            // A failed read is the band right above (`evm_balance_failure`, name and code):
            // not said again here (2026-11-12; "오류 E-RPC-003 · 인증 거부" before).
            return browser;
        } else if self.evm.chain_checks.contains_key(&chain_id) {
            text::CONNECTED.get(lang)
        } else {
            text::UNCHECKED.get(lang)
        };
        format!("RPC: {rpc}   ·   {browser}")
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
            name.push_str(&custom_chain_badge(self.settings.language, chain_id));
        }
        if self.evm.blocked(chain_id).is_some() {
            name.push_str(text::BLOCKED_TAG.get(self.settings.language));
        }
        name
    }

    /// The S10 network drop-down's text of a chain (2026-11-11): [`App::network_label`] with
    /// `(메인넷)` after a built-in mainnet whose name does not say so (`Arbitrum One (메인넷)`;
    /// `Sepolia 테스트넷` and `Ethereum 메인넷` already do; user chains carry no such flag).
    #[must_use]
    pub fn network_choice_label(&self, chain_id: u64) -> String {
        let lang = self.settings.language;
        let name = self.network_name(NetworkId::Eip155(chain_id));
        let label = self.network_label(chain_id);
        if yw_core::evm::chain::is_builtin_mainnet(chain_id)
            && !name.contains(text::MAINNET_WORD.get(lang))
        {
            label.replacen(&name, &text::MAINNET_SUFFIX.fill(lang, [&name]), 1)
        } else {
            label
        }
    }

    /// The badge of an EVM chain (user chains: from their name).
    #[must_use]
    pub fn evm_badge(&self, chain_id: u64) -> Badge {
        Badge::evm(chain_id, &self.network_name(NetworkId::Eip155(chain_id)))
    }

    /// The blocked-chain banner and the journal banner of S10.
    pub fn evm_banners(&self, items: &mut Vec<Item>) {
        let chain_id = self.settings.evm_chain_id;
        let lang = self.settings.language;
        if let Some(kind) = self.evm.blocked(chain_id) {
            items.push(Item::Banner(kind.code().text_in(lang), Tone::Blocked));
            if matches!(kind, MismatchKind::PinnedGenesis { .. }) {
                items.push(Item::Row(vec![Ctl::primary(
                    ids::REPIN_SETTINGS,
                    text::REPIN_IN_SETTINGS.get(lang),
                )]));
            }
        }
        if self.evm.journal_damaged() {
            items.push(Item::Banner(
                crate::app_evm::text::JOURNAL_CORRUPT.get(lang).to_owned(),
                Tone::Blocked,
            ));
        }
    }

    /// The network card's band of a failed balance read (2026-11-10, spec/04 §2.6; one line
    /// since 2026-11-12): the failure's short name and code (no URL or host, §1.9), `RPC 테스트`
    /// (its answer — the code's whole §7 text — in the same card as the three-state band of
    /// settings) and `RPC 설정`. Not for a network without an address (U17) or a blocked
    /// chain: those keep their own lines.
    pub fn evm_balance_failure(&self, items: &mut Vec<Item>) {
        let chain_id = self.settings.evm_chain_id;
        let network = NetworkId::Eip155(chain_id);
        let Some(state) = self.evm.balances.get(&chain_id) else {
            return;
        };
        let Some(code) = state.error else {
            return;
        };
        if self.evm.blocked(chain_id).is_some()
            || !self.apikeys.has(crate::apikeys::KeyName::Rpc(network))
        {
            return;
        }
        items.push(Item::Banner(
            crate::ui::screens::balance_failure_text(self.settings.language, code),
            Tone::Danger,
        ));
        self.rpc_failure_buttons(
            network,
            crate::ui::screens::ids::EVM_RPC_TEST,
            crate::ui::screens::ids::EVM_RPC_ROW,
            items,
        );
    }

    /// The two buttons under a network card's failure band, and the answer of its test.
    pub(crate) fn rpc_failure_buttons(
        &self,
        network: NetworkId,
        test: u16,
        open: u16,
        items: &mut Vec<Item>,
    ) {
        let testing =
            self.rpc_tests.running == Some(network) || self.rpc_tests.waiting.contains(&network);
        let lang = self.settings.language;
        items.push(Item::Row(vec![
            Ctl::button(test, text::RPC_TEST.get(lang))
                .compact()
                .enabled(!testing),
            Ctl::button(open, text::RPC_SETTINGS.get(lang)).compact(),
        ]));
        if let Some((_, message, state)) = self.rpc_messages.iter().find(|(id, ..)| *id == network)
        {
            items.push(Item::Banner(message.clone(), state.tone()));
        }
    }

    /// The account name, with its recovery phrase when the wallet has several
    /// (`계정 1  [복구 단어 2]`, 2026-11-10: two `계정 1` could not be told apart on the
    /// selected-account card, S11, S12 and in the activity).
    #[must_use]
    pub fn evm_account_title(&self, source: yw_core::vault::EvmKeySource, label: &str) -> String {
        match source {
            yw_core::vault::EvmKeySource::Derived(_) => self.mnemonic_tagged(label, None),
            yw_core::vault::EvmKeySource::Mnemonic(id, _) => {
                self.mnemonic_tagged(label, Some(*id.as_bytes()))
            }
            yw_core::vault::EvmKeySource::Raw(_) | yw_core::vault::EvmKeySource::Hardware(_) => {
                label.to_owned()
            }
        }
    }

    /// The path line of an EVM account: `{복구 단어} · m/44'/60'/0'/0/{i}` (the first phrase's
    /// accounts too while the wallet has several), `가져온 개인키` or `YubiKey · …`.
    #[must_use]
    pub fn evm_path_text(&self, source: yw_core::vault::EvmKeySource) -> String {
        match source {
            yw_core::vault::EvmKeySource::Derived(index) => match self
                .several_mnemonics()
                .then(|| self.primary_mnemonic_label())
                .flatten()
            {
                Some(name) => format!("{name} · m/44'/60'/0'/0/{}", index.get()),
                None => format!("m/44'/60'/0'/0/{}", index.get()),
            },
            yw_core::vault::EvmKeySource::Mnemonic(id, index) => format!(
                "{} · m/44'/60'/0'/0/{}",
                self.mnemonic_label(id),
                index.get()
            ),
            yw_core::vault::EvmKeySource::Raw(_) => {
                text::IMPORTED_KEY.get(self.settings.language).to_owned()
            }
            yw_core::vault::EvmKeySource::Hardware(index) => format!(
                "YubiKey · {}",
                yw_core::yubikey::plan::KeyRole::Evm { index, btc: None }
                    .path_text_in(self.settings.language)
            ),
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
        let lang = self.settings.language;
        let mut line = text::BALANCE_AT_BLOCK.fill(
            lang,
            [&self.native_text(chain_id, &balance), &block.to_string()],
        );
        if let Some(code) = state.error {
            line.push_str(&text::REFRESH_FAILED.fill(lang, [code.code()]));
        }
        Some(line)
    }

    /// Tokens and activity sections of S10.
    #[expect(
        clippy::too_many_lines,
        reason = "the activity rows with their lines and buttons"
    )]
    pub fn evm_main_sections(&self, items: &mut Vec<Item>) {
        let chain_id = self.settings.evm_chain_id;
        let lang = self.settings.language;
        self.evm_token_card(items, chain_id);
        self.hc_card(items);
        items.push(Item::CardStart(None));
        items.push(Item::Badged(
            self.evm_badge(chain_id),
            Box::new(Item::Subtitle(text::SENT_TITLE.get(lang).to_owned())),
        ));
        let rows = self.activity_rows();
        if rows.is_empty() {
            // One line (2026-11-12): the title says these are sent ones, and the switch for
            // received ones is right below.
            items.push(Item::Help(text::SENT_NONE.get(lang).to_owned()));
        }
        // The latest rows first; the rest behind a link (this run only). A row still in flight
        // (speed-up, cancel, a broadcast that needs a resend) is never folded away; its buttons
        // keep their row number.
        let foldable = rows
            .iter()
            .skip(ids::ACTIVITY_FIRST)
            .filter(|row| row.open.is_none())
            .count();
        let shown: Vec<(usize, ActivityRowView)> = rows
            .into_iter()
            .enumerate()
            .filter(|(index, row)| {
                self.activity_all || *index < ids::ACTIVITY_FIRST || row.open.is_some()
            })
            .collect();
        let count = shown.len();
        let mut prompt_drawn = false;
        for (position, (index, row)) in shown.into_iter().enumerate() {
            let base = ids::ACTIVITY_BASE.saturating_add(
                u16::try_from(index)
                    .unwrap_or(0)
                    .saturating_mul(ids::ACTIVITY_STRIDE),
            );
            // The status at the end of the first line (2026-11-12: a line of its own before).
            items.push(Item::Text(format!("{} · {}", row.head, row.status)));
            // 2026-11-11: the recipient whole (ends emphasized) and the hash on lines of their
            // own; a click copies either (the wallet's own signed journal — the received
            // history's senders never are), the explorer and address-book actions are icons
            // at the right end of their line.
            let counterparty = row.counterparty.map(Address::to_lower_hex);
            if let Some(address) = &row.counterparty {
                let save = counterparty
                    .as_ref()
                    .filter(|lower| self.offer_save(BookChain::Evm, lower))
                    .map(|_| {
                        crate::ui::screens_links::save_icon(
                            self.settings.language,
                            base.saturating_add(6),
                        )
                    });
                self.recipient_items(address, items);
                crate::ui::screens_links::push_address_line(
                    items,
                    self.settings.language,
                    crate::ui::screens_links::ids::row_id(
                        crate::ui::screens_links::ids::EVM_TO_BASE,
                        crate::ui::screens_links::ids::EVM_TO_SPAN,
                        index,
                    ),
                    &address.to_checksum(),
                    crate::ui::theme::AddressKind::Evm,
                    save.into_iter().collect(),
                );
            }
            // The chain's transaction page (2026-11-11: the templates of the S15 card "블록
            // 탐색기" — built-in, the user chain's `explorer`, or the user's override).
            crate::ui::screens_links::push_hash_line(
                items,
                self.settings.language,
                Some(base),
                &row.hash,
                self.explorer_tx_icons(
                    NetworkId::Eip155(chain_id),
                    &row.hash,
                    Some((base.saturating_add(7), base.saturating_add(5))),
                ),
            );
            let mut buttons = Vec::new();
            if row.open.is_some() {
                // Replace-by-fee has one name on every chain (Bitcoin's `수수료 올리기`).
                buttons.push(Ctl::button(
                    base.saturating_add(1),
                    text::SPEED_UP.get(lang),
                ));
                buttons.push(Ctl::button(
                    base.saturating_add(2),
                    text::CANCEL_TX.get(lang),
                ));
                if row.manual {
                    buttons.push(Ctl::button(base.saturating_add(3), text::RESEND.get(lang)));
                }
                buttons.push(Ctl::danger(base.saturating_add(4), text::DISCARD.get(lang)));
            }
            if !buttons.is_empty() {
                items.push(Item::Row(buttons));
            }
            if let Some(address) = &counterparty
                && !prompt_drawn
            {
                prompt_drawn =
                    self.prompt_items(PromptPlace::Activity, BookChain::Evm, address, items);
            }
            if position.saturating_add(1) < count {
                items.push(Item::Rule);
            }
        }
        if foldable > 0 {
            items.push(Item::Row(vec![Ctl::link(
                ids::ACTIVITY_MORE,
                &if self.activity_all {
                    text::ACTIVITY_FOLD.get(lang).to_owned()
                } else {
                    text::ACTIVITY_MORE.fill(lang, [&foldable.to_string()])
                },
            )]));
        }
        self.received_items(crate::received::RecvChain::Evm, items);
        items.push(Item::CardEnd);
    }

    /// The S10 EVM "토큰" card (spec/04 §2.6): shown rows with `숨기기` (and `삭제` for user
    /// tokens), then one footer row (2026-11-12) — `토큰 추가`, `잔액 0 숨기기` with the count
    /// it hides, and `숨긴 토큰 n개 ▸` listing the hidden rows dimmed with `다시 보이기`.
    fn evm_token_card(&self, items: &mut Vec<Item>, chain_id: u64) {
        let lang = self.settings.language;
        items.push(Item::CardStart(Some(
            text::TOKENS_TITLE.get(lang).to_owned(),
        )));
        let rows = self.evm_token_rows(chain_id);
        let shown: Vec<&EvmTokenRow> = rows
            .iter()
            .filter(|row| row.place == RowPlace::Shown)
            .collect();
        let hidden: Vec<&EvmTokenRow> = rows
            .iter()
            .filter(|row| row.place == RowPlace::Hidden)
            .collect();
        let zero = rows
            .iter()
            .filter(|row| row.place == RowPlace::ZeroHidden)
            .count();
        if rows.is_empty() {
            items.push(Item::Help(text::TOKENS_NONE.get(lang).to_owned()));
        } else if shown.is_empty() {
            items.push(Item::Help(text::TOKENS_NONE_SHOWN.get(lang).to_owned()));
        }
        let can_send = matches!(self.mode, AppMode::Unlocked { .. })
            && self
                .apikeys
                .has(crate::apikeys::KeyName::Rpc(NetworkId::Eip155(chain_id)));
        for (position, row) in shown.into_iter().enumerate() {
            if position > 0 {
                items.push(Item::Rule);
            }
            Self::evm_token_row(lang, items, row, false, can_send);
        }
        // The footer in one row (2026-11-12; four stacked lines before): the action first,
        // the count of tucked-away zero rows in the check box's label, the hidden rows' link.
        let mut footer = vec![Ctl::button(ids::TOKEN_OPEN, text::TOKEN_ADD.get(lang)).compact()];
        if !rows.is_empty() {
            items.push(Item::Rule);
            footer.push(Ctl::check(
                ids::TOKEN_HIDE_ZERO,
                &if zero > 0 {
                    text::HIDE_ZERO_COUNT.fill(lang, [&zero.to_string()])
                } else {
                    text::HIDE_ZERO.get(lang).to_owned()
                },
                self.evm_hide_zero(),
            ));
        }
        let open = self.evm.show_hidden_tokens && !hidden.is_empty();
        if !hidden.is_empty() {
            let count = hidden.len();
            footer.push(Ctl::link(
                ids::TOKEN_HIDDEN_TOGGLE,
                &if open {
                    text::HIDDEN_FOLD_COUNT
                } else {
                    text::HIDDEN_SHOW_COUNT
                }
                .fill(lang, [&count.to_string()]),
            ));
        }
        items.push(Item::Row(footer));
        if open {
            items.push(Item::Help(text::TOKEN_HIDDEN_NOTE.get(lang).to_owned()));
            for (position, row) in hidden.into_iter().enumerate() {
                if position > 0 {
                    items.push(Item::Rule);
                }
                Self::evm_token_row(lang, items, row, true, false);
            }
        }
        items.push(Item::CardEnd);
    }

    /// One token row (2026-11-11, a list a person can scan): the symbol bold with the token's
    /// name small and muted after it, the balance (amount and symbol only) right-aligned; under
    /// it the whole contract without spaces (its ends emphasized like the account card's
    /// address; a click copies it, checksum case) and, at the right end of that line, small
    /// actions — `보내기` (a visible row with a balance, like the Solana token card) and
    /// `숨기기`/`다시 보이기`; user tokens also `삭제`. Hidden rows are muted, their note ending
    /// in `숨김`.
    fn evm_token_row(
        lang: Lang,
        items: &mut Vec<Item>,
        row: &EvmTokenRow,
        hidden: bool,
        can_send: bool,
    ) {
        use ids::{TokenAction, token_row_id};
        let balance = row.balance.map_or_else(
            || text::BALANCE_UNKNOWN.get(lang).to_owned(),
            |value| format_units(&value, row.decimals),
        );
        let note = match (row.name.is_empty(), hidden) {
            (true, false) => String::new(),
            (true, true) => text::HIDDEN.get(lang).to_owned(),
            (false, false) => row.name.clone(),
            (false, true) => text::NAME_HIDDEN.fill(lang, [&row.name]),
        };
        items.push(Item::ListRow {
            title: row.ticker.clone(),
            note,
            value: balance,
            dim: hidden,
        });
        let offset = u16::try_from(row.index).ok();
        let mut buttons = Vec::new();
        if !hidden && let Some(offset) = offset.filter(|offset| *offset < ids::TOKEN_SEND_SPAN) {
            buttons.push(
                Ctl::link(
                    ids::TOKEN_SEND_BASE.saturating_add(offset),
                    text::SEND.get(lang),
                )
                .compact()
                .enabled(can_send && row.balance.is_some_and(|value| !value.is_zero())),
            );
        }
        if let Some(id) = token_row_id(TokenAction::ToggleHidden(row.index)) {
            buttons.push(
                Ctl::link(
                    id,
                    if hidden {
                        text::UNHIDE.get(lang)
                    } else {
                        text::HIDE.get(lang)
                    },
                )
                .compact(),
            );
        }
        if !row.registered
            && let Some(id) = token_row_id(TokenAction::Delete(row.index))
        {
            buttons.push(Ctl::danger(id, text::DELETE.get(lang)).compact());
        }
        crate::ui::screens_links::push_address_line(
            items,
            lang,
            offset
                .filter(|offset| *offset < ids::TOKEN_COPY_SPAN)
                .map(|offset| ids::TOKEN_COPY_BASE.saturating_add(offset)),
            &row.address.to_checksum(),
            crate::ui::theme::AddressKind::Evm,
            buttons,
        );
    }

    /// The explorer base URL: the user chain's, else the built-in chain's (spec/03 §1.1).
    #[must_use]
    pub fn explorer(&self, chain_id: u64) -> Option<String> {
        self.settings
            .evm_chains
            .iter()
            .find(|def| def.chain_id == chain_id)
            .and_then(|def| def.explorer.clone())
            .or_else(|| builtin_chain(chain_id).and_then(|chain| chain.explorer))
    }

    /// The S11 token radios `(visible, hidden)`: every token of the chain (zero balances
    /// included), the ones the user hid apart. Radio ids follow the `App::chain_tokens` index.
    #[must_use]
    pub fn send_asset_rows(&self, chain_id: u64) -> (Vec<Ctl>, Vec<Ctl>) {
        let lang = self.settings.language;
        let asset = self.evm.send.asset;
        let mut visible = Vec::new();
        let mut hidden = Vec::new();
        for row in self.evm_token_rows(chain_id) {
            let Some(id) = u16::try_from(row.index.saturating_add(1))
                .ok()
                .filter(|offset| *offset < ids::SEND_ASSET_SPAN)
                .map(|offset| ids::SEND_ASSET_BASE.saturating_add(offset))
            else {
                continue;
            };
            let name = if row.registered {
                row.symbol.clone()
            } else {
                text::USER_TOKEN.fill(lang, [&row.symbol])
            };
            // The holding next to the name (2026-11-08): the form shows what can be sent.
            let text = row.balance.map_or_else(
                || text::NAME_BALANCE_UNKNOWN.fill(lang, [&name]),
                |value| format!("{name} · {}", format_units(&value, row.decimals)),
            );
            let radio = Ctl::radio(id, &text, asset == SendAsset::Token(row.address), false);
            if row.place == RowPlace::Hidden {
                hidden.push(radio);
            } else {
                visible.push(radio);
            }
        }
        (visible, hidden)
    }

    /// S11.
    #[expect(clippy::too_many_lines, reason = "the S11 fields in order")]
    pub fn send_screen(&self, items: &mut Vec<Item>) {
        let chain_id = self.settings.evm_chain_id;
        let lang = self.settings.language;
        items.push(crate::ui::screens::back_main(lang));
        items.push(Item::Badged(
            self.evm_badge(chain_id),
            Box::new(Item::Title(
                text::SEND_TITLE.fill(lang, [&self.network_name(NetworkId::Eip155(chain_id))]),
            )),
        ));
        if chain_id == SEPOLIA {
            items.push(Item::Banner(
                text::TESTNET_BAND.get(lang).to_owned(),
                Tone::Testnet,
            ));
        } else if yw_core::evm::chain::is_builtin_mainnet(chain_id) {
            // The main tab's mainnet band on S11 too (2026-11-08; Bitcoin shows it everywhere).
            items.push(Item::Banner(
                crate::ui::screens::T_MAINNET.get(lang).to_owned(),
                Tone::BtcMainnet,
            ));
        }
        let form = &self.evm.send;
        if let Some(record) = self.send_in_flight() {
            items.push(Item::Banner(
                text::IN_FLIGHT.get(lang).to_owned(),
                Tone::Warn,
            ));
            items.push(Item::Help(format!(
                "nonce {} · {}",
                record.nonce,
                self.record_status(&record)
            )));
            items.push(Item::Mono(hash_text(&record.tx_hash)));
        }
        if let Some((account, source, label)) = self.selected_account() {
            items.push(Item::CardStart(Some(
                text::FROM_ACCOUNT.get(lang).to_owned(),
            )));
            let balance = self
                .native_balance(chain_id, &account)
                .map_or_else(String::new, |value| {
                    text::BALANCE_SUFFIX.fill(lang, [&self.native_text(chain_id, &value)])
                });
            items.push(Item::Text(format!(
                "{}{balance}",
                self.evm_account_title(source, &label)
            )));
            items.push(Item::Mono(format_address(&account)));
            // U7: `검토` stays off while the phrase waits for its backup quiz, and while the
            // YubiKey is still on its factory PINs (spec/10 §9.3).
            self.mn_signing_banner(self.evm_backup_gate(source), items);
            self.card_pin_banner(self.evm_card_gate(source), items);
            items.push(Item::Row(vec![Ctl::link(
                crate::ui::screens::ids::SWITCH_ACCOUNT,
                text::SWITCH_ACCOUNT.get(lang),
            )]));
            items.push(Item::CardEnd);
        }
        items.push(Item::CardStart(Some(
            text::RECIPIENT_CARD.get(lang).to_owned(),
        )));
        self.favorite_chip_items(BookTarget::Evm, items);
        items.push(Item::LabeledRow(
            text::RECIPIENT_FIELD.get(lang).to_owned(),
            vec![
                Ctl::edit(ids::SEND_TO_EDIT, &form.to_text, 430, false, 64),
                Ctl::button(ids::SEND_PICK, text::PICK_FROM_BOOK.get(lang)),
            ],
        ));
        // The format hint only until the address is valid (2026-11-12); the reminder to check
        // all of it then sits under the grouped address.
        if form.recipient.is_none() {
            items.push(Item::Help(text::ADDRESS_FORMAT.get(lang).to_owned()));
        }
        if form.picker {
            self.picker_rows(items);
        }
        if let Some(code) = form.recipient_error {
            items.push(Item::Banner(code.text_in(lang), Tone::Danger));
        }
        if let Some(text) = &form.system_error {
            items.push(Item::Banner(text.clone(), Tone::Blocked));
        }
        if let Some((address, notes)) = &form.recipient {
            items.push(Item::Mono(format_address(address)));
            items.push(Item::Help(text::CHECK_WHOLE.get(lang).to_owned()));
            for note in notes {
                items.push(Item::Banner(
                    note.text_in(lang),
                    if note.needs_ack() {
                        Tone::HighRisk
                    } else if note.is_warning() {
                        Tone::Warn
                    } else {
                        Tone::Info
                    },
                ));
            }
            if form.contract == Some(true) && form.asset == SendAsset::Native {
                items.push(Item::Banner(
                    crate::flow::evm::form::AddressNote::Contract.text_in(lang),
                    Tone::Warn,
                ));
            }
            if notes
                .iter()
                .any(crate::flow::evm::form::AddressNote::needs_ack)
            {
                items.push(Item::Row(vec![Ctl::check(
                    ids::SEND_ACK,
                    text::ACK_WHOLE.get(lang),
                    form.ack,
                )]));
                if notes.iter().any(|note| {
                    matches!(
                        note,
                        crate::flow::evm::form::AddressNote::Book {
                            verified: false,
                            ..
                        }
                    )
                }) {
                    items.push(Item::Help(
                        crate::app_book::text::BOOK_VERIFY_HINT.get(lang).to_owned(),
                    ));
                }
            }
            self.recipient_save_items(BookTarget::Evm, items);
        }
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(text::ASSET_CARD.get(lang).to_owned())));
        let mut assets = Vec::new();
        let (native_symbol, native_decimals) = self.active_chain().map_or_else(
            || ("ETH".to_owned(), 18),
            |chain| (chain.native_symbol, chain.native_decimals),
        );
        // The native asset shows its holding like the tokens (2026-11-10).
        let native_held = self
            .selected_account()
            .and_then(|(account, ..)| self.native_balance(chain_id, &account));
        assets.push(Ctl::radio(
            ids::SEND_ASSET_BASE,
            &native_held.map_or_else(
                || text::NAME_BALANCE_UNKNOWN.fill(lang, [&native_symbol]),
                |value| {
                    format!(
                        "{native_symbol} · {}",
                        format_units(&value, native_decimals)
                    )
                },
            ),
            form.asset == SendAsset::Native,
            true,
        ));
        let (visible, hidden) = self.send_asset_rows(chain_id);
        assets.extend(visible);
        items.push(Item::LabeledRow(text::ASSET.get(lang).to_owned(), assets));
        if !hidden.is_empty() {
            // The selected asset is never tucked away.
            let selected = hidden.iter().any(|ctl| ctl.checked == Some(true));
            let open = self.evm.send_show_hidden || selected;
            items.push(Item::Row(vec![
                Ctl::link(
                    ids::SEND_HIDDEN_TOGGLE,
                    &if open {
                        text::HIDDEN_FOLD.get(lang).to_owned()
                    } else {
                        text::HIDDEN_SHOW_COUNT.fill(lang, [&hidden.len().to_string()])
                    },
                )
                .enabled(!selected),
            ]));
            if open {
                items.push(Item::LabeledRow(
                    text::HIDDEN_TOKENS.get(lang).to_owned(),
                    hidden,
                ));
            }
        }
        if let SendAsset::Token(token) = form.asset {
            if let Some(row) = self
                .evm_token_rows(chain_id)
                .into_iter()
                .find(|row| row.address == token)
            {
                let block = self
                    .evm
                    .balances
                    .get(&chain_id)
                    .and_then(|state| state.snapshot.as_ref())
                    .map(|snapshot| text::AT_BLOCK.fill(lang, [&snapshot.block.to_string()]))
                    .unwrap_or_default();
                items.push(Item::Text(row.balance.map_or_else(
                    || text::HELD_UNREAD.fill(lang, [&row.symbol]),
                    |value| {
                        text::HELD.fill(
                            lang,
                            [&format_amount(&value, row.decimals, &row.symbol), &block],
                        )
                    },
                )));
            }
            items.push(Item::Help(
                text::TOKEN_CONTRACT.fill(lang, [&token.to_checksum()]),
            ));
        }
        // The unit next to the field and a `최대` note for the chosen asset (2026-11-10).
        let (_, asset_symbol) = self.send_asset_meta();
        items.push(Item::LabeledRow(
            text::AMOUNT_FIELD.fill(lang, [&asset_symbol]),
            vec![
                Ctl::edit(ids::SEND_AMOUNT_EDIT, &form.amount_text, 260, false, 128),
                Ctl::button(ids::SEND_MAX, text::MAX.get(lang)),
            ],
        ));
        // Only until the amount is valid (2026-11-12).
        if form.amount.is_none() {
            items.push(Item::Help(match form.asset {
                SendAsset::Native => text::AMOUNT_HINT_NATIVE.get(lang).to_owned(),
                SendAsset::Token(_) => text::AMOUNT_HINT_TOKEN.fill(lang, [&native_symbol]),
            }));
        }
        if let Some(code) = form.amount_error {
            items.push(Item::Banner(code.text_in(lang), Tone::Danger));
            // E-INP-012 of a token send whose amount the token balance covers: the native fee is
            // what is missing (2026-11-10; the text and code stay §7's).
            if let SendAsset::Token(token) = form.asset
                && code == ErrorCode::Inp012
                && let (Some(amount), Some(held)) =
                    (form.amount, self.token_balance(chain_id, &token))
                && amount <= held
            {
                items.push(Item::Help(text::NO_FEE_ASSET.fill(lang, [&native_symbol])));
            }
        }
        if let (Some(quote), Some(chain)) = (&form.quote, self.active_chain()) {
            let line = quote.line_in(lang, &chain);
            let (summary, detail) = line
                .split_once(" (")
                .map_or((line.as_str(), None), |(head, tail)| {
                    (head, Some(tail.trim_end_matches(')')))
                });
            match form.asset {
                SendAsset::Native => items.push(Item::Text(summary.to_owned())),
                // A token send pays its fee in the native asset: what it costs and what the
                // account holds of it, side by side.
                SendAsset::Token(_) => items.push(Item::Text(text::FEE_HELD.fill(
                    lang,
                    [
                        summary,
                        &native_held.map_or_else(
                            || text::BALANCE_UNKNOWN_SHORT.get(lang).to_owned(),
                            |value| format_amount(&value, native_decimals, &native_symbol),
                        ),
                    ],
                ))),
            }
            if self.show_advanced
                && let Some(detail) = detail
            {
                items.push(Item::Help(text::FEE_DETAIL.fill(lang, [detail])));
            }
            items.push(Item::Row(vec![Ctl::link(
                crate::ui::screens::ids::ADVANCED_TOGGLE,
                if self.show_advanced {
                    text::FEE_DETAIL_HIDE.get(lang)
                } else {
                    text::FEE_DETAIL_SHOW.get(lang)
                },
            )]));
            if let Some(violation) = &quote.cap_violation {
                items.push(Item::Banner(violation.clone(), Tone::Blocked));
            }
            if quote.estimate_failed {
                items.push(Item::Banner(
                    text::ESTIMATE_FAILED.get(lang).to_owned(),
                    Tone::Warn,
                ));
            }
        }
        if let Some(code) = form.quote_error {
            items.push(Item::Banner(code.text_in(lang), Tone::Danger));
        }
        // What `검토`, the approval or the signature ended with, next to the button.
        if let Some(info) = &form.info {
            items.push(Item::Banner(info.clone(), Tone::Warn));
        }
        items.push(Item::CardEnd);
        self.journal_send_items(crate::app_sidecar::SendChain::Evm, items);
        let blocker = self.review_blocker();
        items.push(Item::Row(vec![
            Ctl::primary(ids::SEND_REVIEW, text::REVIEW.get(lang)).enabled(blocker.is_none()),
            Ctl::button(ids::SEND_CANCEL, text::CANCEL.get(lang)),
        ]));
        // What `검토` waits for, or that it sends nothing yet (2026-11-12).
        items.push(Item::Help(
            crate::app_sol::ReviewBlocker::line(lang, blocker).to_owned(),
        ));
    }

    fn picker_rows(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let mut shown = 0_u16;
        for entry in self.picker_known() {
            let hex = entry.address.to_lower_hex();
            let favorite = !entry.mine
                && self
                    .meta
                    .as_ref()
                    .is_some_and(|meta| meta.is_favorite(BookChain::Evm, &hex));
            let prefix = if entry.mine {
                text::PICK_MINE
            } else if favorite {
                text::PICK_FAVORITE
            } else {
                text::PICK_BOOK
            };
            items.push(Item::Row(vec![Ctl::button(
                ids::SEND_PICK_BASE.saturating_add(shown),
                &prefix.fill(lang, [&entry.name]),
            )]));
            items.push(Item::Mono(format_address(&entry.address)));
            shown = shown.saturating_add(1);
        }
        if shown == 0 {
            items.push(Item::Help(text::PICK_NONE.get(lang).to_owned()));
        }
    }

    /// The picker rows in display order: book entries and own accounts matching the filter of
    /// the rows on screen (`SendForm::picker_filter`), at most [`ids::SEND_PICK_SPAN`].
    fn picker_known(&self) -> Vec<crate::flow::evm::form::KnownAddress> {
        let filter = self.evm.send.picker_filter.trim().to_ascii_lowercase();
        self.known_addresses()
            .into_iter()
            .filter(|entry| !entry.history)
            .filter(|entry| {
                filter.is_empty()
                    || entry
                        .address
                        .to_lower_hex()
                        .contains(filter.trim_start_matches("0x"))
                    || entry.name.to_ascii_lowercase().contains(&filter)
            })
            .take(usize::from(ids::SEND_PICK_SPAN))
            .collect()
    }

    /// The picker entries in display order (for the command handler): the same rows as drawn,
    /// so a click picks the row it was drawn for even when the recipient text changed since.
    #[must_use]
    pub fn picker_entries(&self) -> Vec<Address> {
        self.picker_known()
            .into_iter()
            .map(|entry| entry.address)
            .collect()
    }

    /// S11 result.
    pub fn send_result_screen(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Title(text::RESULT_TITLE.get(lang).to_owned()));
        if let Some(sent) = self.evm.sent {
            items.push(Item::Banner(
                text::RESULT_SENT.get(lang).to_owned(),
                Tone::Success,
            ));
            items.push(Item::CardStart(None));
            let status = self
                .evm
                .records()
                .iter()
                .find(|record| record.tx_hash == sent.tx_hash)
                .map_or_else(
                    || text::REC_CONFIRMING.get(lang).to_owned(),
                    |record| self.record_status(record),
                );
            items.push(Item::Badged(
                self.evm_badge(sent.chain_id),
                Box::new(Item::Field(
                    text::STATE.get(lang).to_owned(),
                    format!(
                        "{status} ({})",
                        self.network_name(NetworkId::Eip155(sent.chain_id))
                    ),
                )),
            ));
            items.push(Item::Field(
                text::TX_HASH.get(lang).to_owned(),
                String::new(),
            ));
            let hash = hash_text(&sent.tx_hash);
            items.push(Item::Mono(hash.clone()));
            // 2026-11-11: the transaction on the chain's explorer (no row without a page).
            let buttons = self.explorer_tx_buttons(
                NetworkId::Eip155(sent.chain_id),
                &hash,
                Some((
                    crate::ui::screens_explorer::ids::RESULT_EVM_OPEN,
                    crate::ui::screens_explorer::ids::RESULT_EVM_COPY,
                )),
            );
            if !buttons.is_empty() {
                items.push(Item::Row(buttons));
            }
            items.push(Item::CardEnd);
            self.result_save_items(BookTarget::Evm, items);
        }
        items.push(Item::Row(vec![Ctl::primary(
            crate::ui::screens::ids::BACK_MAIN,
            text::BACK_MAIN.get(lang),
        )]));
    }

    /// S12.
    pub fn receive_screen(&self, items: &mut Vec<Item>) {
        let chain_id = self.settings.evm_chain_id;
        let lang = self.settings.language;
        items.push(crate::ui::screens::back_main(lang));
        items.push(Item::Badged(
            self.evm_badge(chain_id),
            Box::new(Item::Title(
                text::RECEIVE_TITLE.fill(lang, [&self.network_name(NetworkId::Eip155(chain_id))]),
            )),
        ));
        if self.mode == AppMode::BackupPending {
            items.push(Item::Banner(
                text::BACKUP_PENDING.get(lang).to_owned(),
                Tone::Warn,
            ));
        }
        let Some((address, source, label)) = self.selected_account() else {
            self.accounts_loading(items);
            return;
        };
        items.push(Item::CardStart(None));
        // The account only: the screen title above names the network (2026-11-12).
        items.push(Item::Subtitle(self.evm_account_title(source, &label)));
        if chain_id == SEPOLIA {
            items.push(Item::Banner(
                text::TESTNET_ADDRESS.get(lang).to_owned(),
                Tone::Testnet,
            ));
        } else if yw_core::evm::chain::is_builtin_mainnet(chain_id) {
            items.push(Item::Banner(
                crate::ui::screens::T_MAINNET.get(lang).to_owned(),
                Tone::BtcMainnet,
            ));
        }
        self.mn_receive_banner(self.evm_backup_gate(source), items);
        items.push(Item::Help(
            text::RECEIVE_ONLY.fill(lang, [&self.network_name(NetworkId::Eip155(chain_id))]),
        ));
        // The address on its copy line, then the QR (2026-11-12: one line of help above and
        // no button row, so the QR comes that much earlier; the other notes follow the QR).
        items.push(crate::ui::screens::receive_address_row(
            self.settings.language,
            &format_address(&address),
            ids::COPY_ADDRESS,
            Vec::new(),
        ));
        let kind = self.evm.receive_qr;
        items.push(Item::Row(vec![
            Ctl::radio(
                ids::QR_EIP681,
                EvmQrKind::Eip681.label(self.settings.language),
                kind == EvmQrKind::Eip681,
                true,
            ),
            Ctl::radio(
                ids::QR_PLAIN,
                EvmQrKind::PlainAddress.label(self.settings.language),
                kind == EvmQrKind::PlainAddress,
                false,
            ),
        ]));
        if kind == EvmQrKind::PlainAddress {
            items.push(Item::Help(
                text::PLAIN_QR.fill(lang, [&self.network_name(NetworkId::Eip155(chain_id))]),
            ));
        }
        items.push(Item::Qr(crate::ui::qr::evm_receive_payload(
            &address, chain_id, kind,
        )));
        items.push(Item::Help(
            RECEIVE_SHARED_ADDRESS_NOTE
                .get(self.settings.language)
                .to_owned(),
        ));
        items.push(Item::Help(self.evm_path_text(source)));
        items.push(Item::CardEnd);
    }

    /// S16.
    pub fn token_screen(&self, items: &mut Vec<Item>) {
        let chain_id = self.settings.evm_chain_id;
        let lang = self.settings.language;
        items.push(crate::ui::screens::back_main(lang));
        items.push(Item::Title(
            text::TOKEN_TITLE.fill(lang, [&self.network_name(NetworkId::Eip155(chain_id))]),
        ));
        let form = &self.evm.token;
        if let Some(message) = &form.message {
            items.push(Item::Banner(message.clone(), Tone::Info));
        }
        items.push(Item::CardStart(None));
        items.push(Item::LabeledRow(
            text::CONTRACT_ADDRESS.get(lang).to_owned(),
            vec![
                Ctl::edit(ids::TOKEN_ADDR_EDIT, &form.address, 430, false, 64),
                Ctl::button(ids::TOKEN_LOOKUP, text::LOOKUP.get(lang)),
            ],
        ));
        items.push(Item::Help(text::TOKEN_HELP.get(lang).to_owned()));
        if let Some((token, meta)) = &form.found {
            let decimals = meta.decimals.map_or_else(
                || text::UNREADABLE.get(lang).to_owned(),
                |value| value.to_string(),
            );
            let symbol = meta
                .symbol
                .as_deref()
                .filter(|symbol| crate::text::is_symbol(symbol))
                .unwrap_or(text::SYMBOL_UNSHOWABLE.get(lang));
            items.push(Item::Rule);
            items.push(Item::Mono(format_address(token)));
            items.push(Item::Text(text::TOKEN_META.fill(lang, [&decimals, symbol])));
            items.push(Item::LabeledRow(
                text::LABEL.get(lang).to_owned(),
                vec![Ctl::edit(
                    ids::TOKEN_LABEL_EDIT,
                    &form.label,
                    260,
                    false,
                    64,
                )],
            ));
            items.push(Item::Help(text::LABEL_HELP.get(lang).to_owned()));
            items.push(Item::Row(vec![Ctl::primary(
                ids::TOKEN_SAVE,
                text::SAVE.get(lang),
            )]));
        }
        items.push(Item::CardEnd);
    }

    /// The S15 `EVM 체인` section with fee caps.
    #[expect(
        clippy::too_many_lines,
        reason = "one card per chain row with its badge, identifiers and caps"
    )]
    pub fn chains_section(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::CardStart(Some(
            text::CHAINS_TITLE.get(lang).to_owned(),
        )));
        items.push(Item::Help(text::CHAINS_HELP.get(lang).to_owned()));
        let mut chains = self.settings.registered_evm();
        chains.truncate(usize::from(ids::CHAIN_ROW_SPAN / 3));
        let count = chains.len();
        for (index, chain_id) in chains.into_iter().enumerate() {
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
                Some(crate::flow::evm::ChainCheck::Verified { .. }) => {
                    text::CONNECTED.get(lang).to_owned()
                }
                Some(crate::flow::evm::ChainCheck::Mismatch(kind)) => {
                    text::BLOCKED_CODE.fill(lang, [kind.code().code()])
                }
                _ => text::UNCHECKED.get(lang).to_owned(),
            };
            items.push(Item::Badged(
                self.evm_badge(chain_id),
                Box::new(Item::Subtitle(format!(
                    "{} (chainId {chain_id})",
                    self.network_name(NetworkId::Eip155(chain_id))
                ))),
            ));
            items.push(Item::Help(text::CHAIN_LINE.fill(
                lang,
                [
                    &symbol,
                    &decimals.to_string(),
                    simulation,
                    &state,
                    &self.endpoint_text(chain_id),
                ],
            )));
            if let Some(def) = user {
                items.push(Item::Help(custom_chain_badge(
                    self.settings.language,
                    chain_id,
                )));
                let mut ids_text = Vec::new();
                if let Some(subdomain) = &def.quicknode_subdomain {
                    ids_text.push(text::QUICKNODE_ENTRY.fill(lang, [subdomain]));
                }
                if let Some(label) = &def.alchemy_label {
                    ids_text.push(text::ALCHEMY_ENTRY.fill(lang, [label]));
                }
                if let Some(explorer) = &def.explorer {
                    ids_text.push(text::EXPLORER_ENTRY.fill(lang, [explorer]));
                }
                if !ids_text.is_empty() {
                    items.push(Item::Help(ids_text.join(" · ")));
                }
            }
            if self.show_advanced {
                let genesis = self.pinned_genesis(chain_id).map_or_else(
                    || text::PIN_ON_FIRST.get(lang).to_owned(),
                    |hash| crate::text::hash32_text(&hash),
                );
                items.push(Item::Mono(format!("genesis {genesis}")));
            }
            let base = ids::CHAIN_ROW_BASE
                .saturating_add(u16::try_from(index).unwrap_or(0).saturating_mul(3));
            let mut row = Vec::new();
            if user.is_some() {
                row.push(Ctl::button(base, text::EDIT.get(lang)));
                row.push(
                    Ctl::danger(base.saturating_add(1), text::DELETE.get(lang))
                        .enabled(matches!(self.mode, AppMode::Unlocked { .. })),
                );
            }
            if matches!(
                self.evm.blocked(chain_id),
                Some(MismatchKind::PinnedGenesis { .. })
            ) && (user.is_some() || chain_id == HYPEREVM_MAINNET)
            {
                row.push(Ctl::primary(base.saturating_add(2), text::REPIN.get(lang)));
            }
            if !row.is_empty() {
                items.push(Item::Row(row));
            }
            if index.saturating_add(1) < count {
                items.push(Item::Rule);
            }
        }
        if let Some(repin) = &self.evm.repin
            && let Some(message) = &repin.message
        {
            items.push(Item::Banner(message.clone(), Tone::Info));
        }
        chain_add_row(lang, items);
        items.push(Item::CardEnd);
        self.hc_settings_section(items);
        if self.show_advanced {
            self.caps_section(items);
        }
        self.advanced_toggle(items);
    }

    fn caps_section(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::CardStart(Some(text::CAPS_TITLE.get(lang).to_owned())));
        items.push(Item::Help(text::CAPS_HELP.get(lang).to_owned()));
        let selected = self.evm.caps.as_ref().map(|caps| caps.chain_id);
        let radios: Vec<Ctl> = self
            .settings
            .registered_evm()
            .into_iter()
            .take(usize::from(ids::CAPS_CHAIN_SPAN))
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
        items.push(Item::LabeledRow(text::CHAIN.get(lang).to_owned(), radios));
        let Some(caps) = &self.evm.caps else {
            items.push(Item::Help(text::CAPS_PICK.get(lang).to_owned()));
            items.push(Item::CardEnd);
            return;
        };
        if let Some(message) = &caps.message {
            items.push(Item::Banner(message.clone(), Tone::Info));
        }
        let symbol = crate::flow::evm::chain_info(&self.settings, caps.chain_id)
            .map_or_else(String::new, |chain| chain.native_symbol);
        items.push(Item::LabeledRow(
            text::CAPS_FEE.get(lang).to_owned(),
            vec![Ctl::edit(ids::CAPS_FEE_EDIT, &caps.fee, 160, false, 32)],
        ));
        items.push(Item::LabeledRow(
            text::CAPS_TIP.get(lang).to_owned(),
            vec![Ctl::edit(ids::CAPS_TIP_EDIT, &caps.tip, 160, false, 32)],
        ));
        items.push(Item::LabeledRow(
            text::CAPS_TOTAL.fill(lang, [&symbol]),
            vec![Ctl::edit(ids::CAPS_TOTAL_EDIT, &caps.total, 160, false, 40)],
        ));
        items.push(Item::Row(vec![
            Ctl::primary(ids::CAPS_SAVE, text::SAVE.get(lang)),
            Ctl::button(ids::CAPS_DEFAULT, text::DEFAULTS.get(lang)),
        ]));
        items.push(Item::Help(text::CAPS_RANGE.get(lang).to_owned()));
        items.push(Item::CardEnd);
    }

    /// S17.
    #[expect(clippy::too_many_lines, reason = "the S17 fields in order")]
    pub fn chain_edit_screen(&self, items: &mut Vec<Item>) {
        let Some(form) = &self.evm.chain_form else {
            return;
        };
        let lang = self.settings.language;
        items.push(Item::Title(
            if form.editing.is_some() {
                text::CHAIN_EDIT_TITLE
            } else {
                text::CHAIN_ADD
            }
            .get(lang)
            .to_owned(),
        ));
        if let Some(message) = &form.message {
            items.push(Item::Banner(message.clone(), Tone::Info));
        }
        items.push(Item::CardStart(None));
        let mut chain_id = Ctl::edit(ids::CHAIN_ID_EDIT, &form.chain_id, 260, false, 20);
        if form.editing.is_some() {
            chain_id = chain_id.readonly();
        }
        items.push(Item::LabeledRow("chainId".to_owned(), vec![chain_id]));
        items.push(Item::Help(text::CHAIN_ID_HELP.get(lang).to_owned()));
        items.push(Item::LabeledRow(
            text::NAME.get(lang).to_owned(),
            vec![Ctl::edit(ids::CHAIN_NAME_EDIT, &form.name, 260, false, 64)],
        ));
        items.push(Item::LabeledRow(
            crate::flow::evm::user_chain::text::ITEM_SYMBOL
                .get(lang)
                .to_owned(),
            vec![Ctl::edit(
                ids::CHAIN_SYMBOL_EDIT,
                &form.symbol,
                160,
                false,
                11,
            )],
        ));
        items.push(Item::LabeledRow(
            crate::flow::evm::user_chain::text::ITEM_DECIMALS
                .get(lang)
                .to_owned(),
            vec![Ctl::edit(
                ids::CHAIN_DECIMALS_EDIT,
                &form.decimals,
                80,
                false,
                2,
            )],
        ));
        items.push(Item::Help(text::NATIVE_HELP.get(lang).to_owned()));
        let template = self.settings.rpc_template;
        let credential = self.apikeys.credential(template).is_some();
        let credential = if credential {
            text::CREDENTIAL_SET
        } else {
            text::CREDENTIAL_NONE
        }
        .get(lang);
        let hint = match template {
            crate::settings::RpcTemplate::QuickNode => {
                text::RPC_HINT_QUICKNODE.fill(lang, [credential])
            }
            crate::settings::RpcTemplate::Alchemy => {
                text::RPC_HINT_ALCHEMY.fill(lang, [credential])
            }
            crate::settings::RpcTemplate::Manual => text::RPC_HINT_MANUAL.get(lang).to_owned(),
        };
        items.push(Item::LabeledRow(
            text::RPC_ADDRESS.get(lang).to_owned(),
            vec![Ctl::edit(ids::CHAIN_RPC_EDIT, "", 430, true, 2_048)],
        ));
        items.push(Item::Help(if form.editing.is_some() {
            text::RPC_KEEP.fill(lang, [&hint])
        } else {
            hint
        }));
        items.push(Item::LabeledRow(
            text::EXPLORER_OPTIONAL.get(lang).to_owned(),
            vec![Ctl::edit(
                ids::CHAIN_EXPLORER_EDIT,
                &form.explorer,
                430,
                false,
                256,
            )],
        ));
        items.push(Item::LabeledRow(
            text::SIMULATION.get(lang).to_owned(),
            vec![
                Ctl::radio(
                    ids::CHAIN_SIM_AUTO,
                    text::SIM_AUTO.get(lang),
                    !form.unsupported,
                    true,
                ),
                Ctl::radio(
                    ids::CHAIN_SIM_UNSUPPORTED,
                    text::SIM_UNSUPPORTED.get(lang),
                    form.unsupported,
                    false,
                ),
            ],
        ));
        items.push(Item::Help(text::SIM_HELP.get(lang).to_owned()));
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::primary(ids::CHAIN_SAVE, text::SAVE.get(lang)).enabled(form.pending.is_none()),
            Ctl::button(ids::CHAIN_CANCEL, text::CANCEL.get(lang)),
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
        let lang = self.settings.language;
        let rpc = match &valid.rpc {
            crate::flow::evm::user_chain::RpcSpec::Template {
                template, entry, ..
            } => match template {
                crate::settings::RpcTemplate::QuickNode => {
                    text::QUICKNODE_ENTRY.fill(lang, [entry])
                }
                _ => text::ALCHEMY_ENTRY.fill(lang, [entry]),
            },
            crate::flow::evm::user_chain::RpcSpec::Url(url) => crate::apikeys::mask_url(url),
            crate::flow::evm::user_chain::RpcSpec::Keep => String::new(),
        };
        text::CHAIN_PIN.fill(
            lang,
            [
                &valid.chain_id.to_string(),
                &valid.name,
                &rpc,
                &crate::text::hash32_text(&genesis),
            ],
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
        text::CHAIN_REPIN.fill(self.settings.language, [&old, &new])
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
    pub fn no_endpoint_text(lang: Lang) -> String {
        ErrorCode::Key005.text_in(lang)
    }
}
