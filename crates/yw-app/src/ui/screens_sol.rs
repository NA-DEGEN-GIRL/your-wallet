//! Solana screen contents (M7; spec/04 §2.6–§2.8, §2.10, §2.11, spec/07 §3.3, §12.3): the S10
//! Solana tab (with the allowlisted-token card of v1.1), the SOL/SPL send form with its asset
//! picker and its result, receive, the S15 Solana section, the recovery scan and the Solana part
//! of the address book. Addresses are always shown in full, in 4-character groups (spec/07
//! §12.3); activity addresses have no copy or select buttons (a transaction id, public data,
//! has `해시 복사` like Bitcoin's and EVM's).

use core::fmt::Write as _;

use yw_core::sol::address::grouped;
use yw_core::sol::recipient::KnownKind;
use yw_core::sol::rent::{format_amount, format_raw};
use yw_core::sol::template::spl_entries;
use yw_core::sol::token::TokenHolding;
use yw_core::sol::{SolAddress, SolAsset, SolCluster, SplAllowEntry};

use crate::app::{App, AppMode};
use crate::app_book::{BookTarget, PromptPlace};
use crate::app_sol::SolAccountId;
use crate::meta::{BookChain, Tab};
use crate::ui::badge::Badge;
use crate::ui::main_window::{Ctl, Item, Tone};

/// Command ids of the Solana screens (7000–7909 and the account radios at 12,000; the whole
/// map and its checks are in `ui::command_ids`).
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
    /// Send-form asset radios (SOL, then the cluster's allowlisted tokens; v1.1).
    pub const SEND_ASSET_BASE: u16 = 7_015;
    /// Asset radio span.
    pub const SEND_ASSET_SPAN: u16 = 4;
    /// Token card "이 토큰 보내기" (allowlist index of the cluster; v1.1).
    pub const TOKEN_SEND_BASE: u16 = 7_027;
    /// Token send span.
    pub const TOKEN_SEND_SPAN: u16 = 3;
    /// Token card `숨기기` / `다시 보이기` (allowlist index of the cluster).
    pub const TOKEN_HIDE_BASE: u16 = 7_070;
    /// Token hide span.
    pub const TOKEN_HIDE_SPAN: u16 = 4;
    /// Token card `숨긴 토큰 n개 보기` / `접기`.
    pub const TOKEN_HIDDEN_TOGGLE: u16 = 7_075;
    /// Token card `주소 복사` of the mint (one per allowlist row; 2026-11-11).
    pub const TOKEN_COPY_BASE: u16 = 7_080;
    /// Mint copy span.
    pub const TOKEN_COPY_SPAN: u16 = 4;
    /// `해시 복사` of the send result (the signature, i.e. the transaction id).
    pub const RESULT_COPY: u16 = 7_076;
    /// `해시 복사` of the S10 activity rows (display order, one id per row).
    pub const ACTIVITY_COPY_BASE: u16 = 7_400;
    /// Activity copy span (the journal's records, or the drawn activity rows).
    pub const ACTIVITY_COPY_SPAN: u16 = 64;
    /// Account radios (one id per row; rows ≤ 100, spec/02 §5.3). The span covers the whole
    /// account-index range 0..=999. It used to start at 7,200, inside the scan rows below, so
    /// the 41st scan row's `계정 추가` selected account 0 instead.
    pub const ACCOUNT_BASE: u16 = 12_000;
    /// Account radio span.
    pub const ACCOUNT_SPAN: u16 = 1_000;
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
    /// "지금 다시 전송": the same signed bytes of a pending transfer, now (spec/07 §14.3).
    pub const SEND_NOW: u16 = 7_019;
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
    /// Scan results: `다시 스캔` (back to the notice).
    pub const SCAN_AGAIN: u16 = 7_111;
    /// Send result of a scan move: `스캔 결과로`.
    pub const SCAN_BACK: u16 = 7_112;
    /// Scan rows ([`SCAN_ROW_STRIDE`] ids per row: 계정 추가, 표준 계정으로 이동). Rows ≤ 107
    /// (spec/07 §3.3: 50 standard + 50 BIP44 + root + seed + 5 Sollet sources).
    pub const SCAN_ROW_BASE: u16 = 7_120;
    /// Ids per scan row.
    pub const SCAN_ROW_STRIDE: u16 = 2;
    /// Scan rows span (128 rows × 2; ends at 7,376).
    pub const SCAN_ROW_SPAN: u16 = 256;

    /// Every fixed id of this module (`ui::command_ids` checks them against all ranges).
    pub const FIXED: &[u16] = &[
        TAB_EVM,
        TAB_SOL,
        CLUSTER_MAINNET,
        CLUSTER_DEVNET,
        REFRESH,
        SEND_OPEN,
        RECEIVE_OPEN,
        RENAME,
        HIDE,
        ADD_ACCOUNT,
        SCAN_OPEN,
        RENAME_EDIT,
        RENAME_SAVE,
        RENAME_CANCEL,
        COPY_ADDRESS,
        SEND_TO_EDIT,
        SEND_AMOUNT_EDIT,
        SEND_MAX,
        SEND_REVIEW,
        SEND_CANCEL,
        SEND_PICK,
        SEND_AGAIN,
        SEND_NOW,
        TOKEN_HIDDEN_TOGGLE,
        RESULT_COPY,
        SECTION_SOL,
        FEE_CAP_EDIT,
        CU_PRICE_EDIT,
        FEE_SAVE,
        FEE_DEFAULT,
        SET_MAINNET,
        SET_DEVNET,
        SCAN_START,
        SCAN_AGAIN,
        SCAN_BACK,
    ];

    /// What a scan-row id does (row index into `sol_scan_rows`).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ScanAction {
        /// `계정 추가` (standard path).
        Add(usize),
        /// `표준 계정으로 이동` (non-standard path).
        Move(usize),
    }

    /// The button id of a scan action (`None` beyond the span).
    #[must_use]
    pub fn scan_row_id(action: ScanAction) -> Option<u16> {
        let (row, extra) = match action {
            ScanAction::Add(row) => (row, 0),
            ScanAction::Move(row) => (row, 1),
        };
        let offset = u16::try_from(row)
            .ok()?
            .checked_mul(SCAN_ROW_STRIDE)?
            .checked_add(extra)?;
        (offset < SCAN_ROW_SPAN).then(|| SCAN_ROW_BASE.saturating_add(offset))
    }

    /// The scan action of `id`, if it is a scan-row id.
    #[must_use]
    pub fn scan_action(id: u16) -> Option<ScanAction> {
        let offset = id
            .checked_sub(SCAN_ROW_BASE)
            .filter(|offset| *offset < SCAN_ROW_SPAN)?;
        let row = usize::from(offset / SCAN_ROW_STRIDE);
        Some(if offset % SCAN_ROW_STRIDE == 0 {
            ScanAction::Add(row)
        } else {
            ScanAction::Move(row)
        })
    }
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

/// `(value, note)` of a token holding: the balance with the pinned decimals and symbol, and what
/// it means (RPC reference; missing account; frozen; unreadable).
fn token_holding_text(entry: &SplAllowEntry, holding: Option<TokenHolding>) -> (String, String) {
    let amount = |raw: u64| format_amount(raw, entry.decimals);
    let raw = |raw: u64| {
        format!(
            "{} 원시 단위 · decimals {} · RPC finalized 기준(참고)",
            format_raw(raw),
            entry.decimals
        )
    };
    match holding {
        None => (
            "잔액 알 수 없음".to_owned(),
            "아직 읽지 못했습니다. RPC 연결을 확인하고 새로고침하세요.".to_owned(),
        ),
        Some(TokenHolding::Missing) => (
            amount(0),
            format!(
                "이 계정에는 아직 {} 토큰 계정(ATA)이 없습니다. 받으면 보내는 쪽이 만듭니다.",
                entry.symbol
            ),
        ),
        Some(TokenHolding::Active(value)) => (amount(value), raw(value)),
        Some(TokenHolding::Frozen(value)) => (
            amount(value),
            format!(
                "{} — 토큰 발행자가 이 토큰 계정을 동결해 보내거나 받을 수 없습니다.",
                raw(value)
            ),
        ),
        Some(TokenHolding::Invalid) => (
            "확인할 수 없음".to_owned(),
            "RPC가 돌려준 계정이 이 토큰의 토큰 계정 형식과 달라 잔액을 표시하지 않습니다."
                .to_owned(),
        ),
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
        items.push(Item::Row(vec![
            Ctl::tab(ids::TAB_EVM, "  EVM (이더리움 등)  ", tab == Tab::Evm)
                .badge(Badge::family(BookChain::Evm)),
            Ctl::tab(ids::TAB_SOL, "  Solana  ", tab == Tab::Sol)
                .badge(Badge::family(BookChain::Sol)),
            Ctl::tab(
                crate::ui::screens_btc::ids::TAB_BTC,
                "  Bitcoin  ",
                tab == Tab::Btc,
            )
            .badge(Badge::family(BookChain::Btc)),
            Ctl::tab(
                crate::ui::screens_zec::ids::TAB_ZEC,
                "  Zcash  ",
                tab == Tab::Zec,
            )
            .badge(Badge::zcash(self.settings.zcash.network)),
        ]));
    }

    /// The cluster band: a full band on S11 (`pill == false`), a small tag after the S10
    /// cluster chips (2026-11-11, like the EVM network card).
    fn sol_cluster_banner(&self, items: &mut Vec<Item>, pill: bool) {
        let (text, tone) = if self.sol_cluster() == SolCluster::Devnet {
            // The tag sits after the `Solana devnet (테스트)` chip: the EVM tag's words.
            (
                if pill {
                    "테스트넷 — 실제 자산이 아닙니다"
                } else {
                    "Solana devnet (테스트) — 실제 자산이 아닙니다"
                }
                .to_owned(),
                Tone::Testnet,
            )
        } else {
            // Like the EVM mainnets (2026-11-08): S10, S11 and S12 say real assets move.
            (crate::ui::screens::T_MAINNET.to_owned(), Tone::BtcMainnet)
        };
        items.push(if pill {
            Item::Pill(text, tone)
        } else {
            Item::Banner(text, tone)
        });
    }

    /// The S10 Solana tab.
    #[expect(clippy::too_many_lines, reason = "the S10 Solana sections in order")]
    pub fn sol_main_screen(&self, items: &mut Vec<Item>) {
        let cluster = self.sol_cluster();
        items.push(Item::CardStart(None));
        items.push(Item::LabeledRow(
            "네트워크".to_owned(),
            vec![
                Ctl::tab(
                    ids::CLUSTER_MAINNET,
                    "Solana mainnet",
                    cluster == SolCluster::Mainnet,
                )
                .badge(Badge::solana(SolCluster::Mainnet)),
                Ctl::tab(
                    ids::CLUSTER_DEVNET,
                    "Solana devnet (테스트)",
                    cluster == SolCluster::Devnet,
                )
                .badge(Badge::solana(SolCluster::Devnet)),
            ],
        ));
        self.sol_cluster_banner(items, true);
        if self.sol_journal_damaged() {
            items.push(Item::Banner(
                "거래 저널의 Solana 기록이 손상되어 Solana 보내기를 멈췄습니다. (E-VLT-006)"
                    .to_owned(),
                Tone::Blocked,
            ));
        }
        let network = crate::network::NetworkId::Solana(self.settings.solana.cluster);
        let no_endpoint = self.sol_endpoint(cluster).is_err();
        let failure = (!no_endpoint)
            .then(|| self.sol.balance_error.get(&cluster).copied())
            .flatten();
        // The failed read, said once with what to do (2026-11-10, like the EVM network card).
        if let Some(code) = failure {
            items.push(Item::Banner(
                crate::ui::screens::balance_failure_text(code),
                Tone::Danger,
            ));
            self.rpc_failure_buttons(
                network,
                crate::ui::screens::ids::SOL_RPC_TEST,
                crate::ui::screens::ids::SOL_RPC_ROW,
                items,
            );
        }
        // The status line, unless the band above has just said the failure (2026-11-12).
        if failure.is_none() {
            let rpc = if no_endpoint {
                "RPC 주소 없음 (E-KEY-005)"
            } else if self.sol.balances.keys().any(|(known, _)| *known == cluster) {
                "연결됨 (genesis 확인)"
            } else {
                "확인 전"
            };
            items.push(Item::Help(format!("RPC ({network}): {rpc}")));
        }
        items.push(Item::CardEnd);
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        let selected = self.sol_selected();
        if selected.is_none() && self.key_only() && self.meta.is_some() {
            self.no_accounts_card(yw_core::keyimport::ImportChain::Sol, items);
            return;
        }
        if let Some((id, label, address)) = &selected {
            items.push(Item::CardStart(None));
            items.push(Item::Subtitle(self.sol_title(*id, label)));
            items.push(Item::Help(id.path_text()));
            self.mn_signing_banner(
                self.mn_backup_gate(
                    id.mnemonic().map(yw_core::vault::RecordId::from_bytes),
                    matches!(id, crate::app_sol::SolAccountId::Derived(_)),
                ),
                items,
            );
            self.card_pin_banner(
                id.source().and_then(|source| self.sol_card_gate(source)),
                items,
            );
            // Three states under the big balance (2026-11-10, like EVM): loading, read (with
            // the time), or failed — explained once by the network card above.
            match (self.sol_balance(address), failure) {
                (Some(lamports), Some(_)) => {
                    // The earlier value, dimmed, and since when (2026-11-12, like EVM).
                    items.push(Item::DisplayMuted(App::sol_text(lamports)));
                    items.push(Item::Help(crate::ui::screens::balance_stale_text(
                        None,
                        self.sol.balance_at.get(&cluster).copied(),
                    )));
                }
                (Some(lamports), None) => {
                    items.push(Item::Display(App::sol_text(lamports)));
                    let read = crate::ui::screens::balance_read_text(
                        None,
                        self.sol.balance_at.get(&cluster).copied(),
                    );
                    items.push(Item::Help(if read.is_empty() {
                        format!(
                            "{} lamports · RPC finalized 기준(참고)",
                            format_raw(lamports)
                        )
                    } else {
                        format!(
                            "{} lamports · RPC finalized 기준(참고) · {read}",
                            format_raw(lamports)
                        )
                    }));
                }
                (None, _) if no_endpoint => {
                    items.push(Item::Display("잔액 —".to_owned()));
                    items.push(Item::Help(crate::ui::screens::no_endpoint_text(
                        &self.network_name(network),
                    )));
                }
                (None, Some(_)) => {
                    items.push(Item::Display("잔액 —".to_owned()));
                    items.push(Item::Help(crate::ui::screens::T_BALANCE_FAILED.to_owned()));
                }
                (None, None) => {
                    items.push(Item::Display("잔액 —".to_owned()));
                    items.push(Item::Help(crate::ui::screens::T_BALANCE_LOADING.to_owned()));
                }
            }
            if let Some(holdings) = self.sol_token_holdings(address) {
                let tokens: Vec<String> = holdings
                    .iter()
                    .filter(|(entry, _)| !self.sol_token_hidden(entry))
                    .map(|(entry, holding)| {
                        holding.balance().map_or_else(
                            || format!("{} 확인할 수 없음", entry.symbol),
                            |raw| {
                                format!("{} {}", format_amount(raw, entry.decimals), entry.symbol)
                            },
                        )
                    })
                    .collect();
                if !tokens.is_empty() {
                    items.push(Item::Help(format!("토큰: {}", tokens.join(" · "))));
                }
            }
            // The own address whole with its ends emphasized and `주소 복사` (2026-11-11).
            let text = address.to_base58();
            items.push(crate::ui::screens::own_address_row(
                &text,
                crate::ui::theme::AddressKind::Solana,
                ids::COPY_ADDRESS,
                true,
                self.explorer_address_icon(
                    crate::network::NetworkId::Solana(self.settings.solana.cluster),
                    &text,
                    crate::ui::screens_explorer::ids::CARD_SOL,
                ),
            ));
            let mut row = vec![
                Ctl::primary(ids::SEND_OPEN, "보내기").enabled(unlocked),
                Ctl::primary(ids::RECEIVE_OPEN, "받기"),
            ];
            if no_endpoint {
                // The same next step as every tab (2026-11-08): no refresh without an address;
                // it opens this cluster's row with its field (2026-11-10).
                row.push(Ctl::button(
                    crate::ui::screens::ids::SOL_RPC_OPEN,
                    "RPC 설정하기",
                ));
            } else {
                row.push(Ctl::link(ids::REFRESH, "새로고침"));
            }
            items.push(Item::Row(row));
            items.push(Item::CardEnd);
        }
        items.push(Item::CardStart(Some("내 Solana 계정".to_owned())));
        let rows = self.sol_account_rows();
        // The same help as `내 계정` (2026-11-12; the path is the hero card's second line).
        if let Some(help) = self.accounts_help(
            rows.iter().any(|(id, ..)| id.is_hardware()),
            rows.iter().any(|(id, ..)| id.is_imported()),
        ) {
            items.push(Item::Help(help));
        }
        if rows.is_empty() {
            items.push(Item::Muted(if self.sol.creating {
                "Solana 계정을 만드는 중…".to_owned()
            } else {
                "Solana 계정이 없습니다.".to_owned()
            }));
        }
        let selected = selected.map(|(id, ..)| id);
        let removable = self.can_remove_imported();
        // A drop-down like the EVM network's (2026-11-11): the selected account on its button,
        // the accounts under it while open (each keeps the id its radio had); the selected
        // account's actions follow (2026-11-12: its path, balance and address are the hero
        // card's and are not said again here).
        let mut entries = Vec::new();
        let mut chosen = None;
        for (row, (id, label, _)) in rows
            .into_iter()
            .take(usize::from(ids::ACCOUNT_SPAN))
            .enumerate()
        {
            let is_selected = selected == Some(id);
            let shown_label = if id.is_imported() {
                format!("{label} · 가져온 키")
            } else if id.is_hardware() {
                format!("{label} · YubiKey")
            } else {
                // With several mnemonics every derived row names its source.
                self.mnemonic_tag(id.mnemonic())
                    .map_or_else(|| label.clone(), |tag| format!("{label} · {tag}"))
            };
            entries.push(crate::ui::screens_links::PickerEntry {
                id: ids::ACCOUNT_BASE.saturating_add(u16::try_from(row).unwrap_or(0)),
                label: shown_label,
                selected: is_selected,
                enabled: true,
            });
            if is_selected {
                chosen = Some((id, label));
            }
        }
        if !entries.is_empty() {
            self.push_account_picker(items, crate::ui::screens_links::ids::PICKER_SOL, &entries);
        }
        if let Some((id, label)) = chosen {
            if self.sol.rename == Some(id) {
                items.push(Item::Row(vec![
                    Ctl::edit(ids::RENAME_EDIT, &label, 260, false, 64),
                    Ctl::primary(ids::RENAME_SAVE, "저장"),
                    Ctl::button(ids::RENAME_CANCEL, "취소"),
                ]));
            } else {
                let mut row_ctls = vec![Ctl::button(ids::RENAME, "이름 바꾸기").compact()];
                match id {
                    // No `숨기기` for a recovery phrase's first account (2026-11-12, as EVM).
                    SolAccountId::Derived(index) | SolAccountId::Mnemonic(_, index) => {
                        if index != 0 {
                            row_ctls.push(Ctl::button(ids::HIDE, "숨기기").compact());
                        }
                    }
                    // A YubiKey account: no "개인키 보기" (the key is on the card only).
                    SolAccountId::Hardware(_) => {
                        row_ctls.push(Ctl::button(ids::HIDE, "숨기기").compact());
                    }
                    SolAccountId::Imported(_) => {
                        row_ctls.push(
                            Ctl::button(crate::ui::screens_keys::ids::SOL_REVEAL, "개인키 보기")
                                .compact()
                                .enabled(unlocked),
                        );
                        row_ctls.push(
                            Ctl::danger(crate::ui::screens_keys::ids::SOL_REMOVE, "삭제")
                                .compact()
                                .enabled(unlocked && removable),
                        );
                    }
                }
                items.push(Item::Row(row_ctls));
            }
        }
        self.hidden_items(crate::app_hidden::Family::Sol, items);
        items.push(Item::Rule);
        let import = Ctl::button(crate::ui::screens_keys::ids::SOL_IMPORT, "개인키 가져오기")
            .compact()
            .enabled(self.can_import(yw_core::keyimport::ImportChain::Sol));
        if self.key_only() {
            items.push(Item::Row(vec![import]));
        } else {
            items.push(Item::Row(vec![
                Ctl::button(ids::ADD_ACCOUNT, "계정 추가")
                    .compact()
                    .enabled(
                        !self.sol.creating
                            && (self.several_mnemonics()
                                || self
                                    .meta
                                    .as_ref()
                                    .and_then(crate::meta::Meta::next_sol_index)
                                    .is_some()),
                    ),
                Ctl::button(ids::SCAN_OPEN, "다른 경로 스캔").compact(),
                import,
            ]));
            self.sol_pick_row(items);
            items.push(Item::Help(
                "안 보이는 계정은 '다른 경로 스캔'으로 찾습니다.".to_owned(),
            ));
        }
        items.push(Item::CardEnd);
        if let Some((_, _, address)) = self.sol_selected() {
            self.sol_token_card(items, &address, unlocked && !no_endpoint);
        }
        items.push(Item::CardStart(None));
        items.push(Item::Badged(
            Badge::solana(cluster),
            Box::new(Item::Subtitle("보낸 거래".to_owned())),
        ));
        let mut shown = 0_usize;
        let mut prompt_drawn = false;
        let counterparties = self.sol_activity_counterparties();
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
            items.push(Item::Help(format!(
                "상태: {}",
                self.sol_record_status(&record)
            )));
            if let Some(core) = core {
                self.sol_recipient_items(shown, &core.to, &counterparties, items);
            }
            let tx_id = record.tx_id();
            self.sol_activity_actions(shown, &tx_id, &counterparties, &mut prompt_drawn, items);
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
                items.push(Item::Help(format!("상태: {}", status_word(&entry.status))));
                match SolAddress::parse(&entry.counterparty) {
                    Ok(address) => {
                        self.sol_recipient_items(shown, &address, &counterparties, items);
                    }
                    Err(_) => items.push(Item::Help(format!("받는 주소 {}", entry.counterparty))),
                }
                self.sol_activity_actions(
                    shown,
                    &entry.tx_id,
                    &counterparties,
                    &mut prompt_drawn,
                    items,
                );
                shown = shown.saturating_add(1);
            }
        }
        if shown == 0 {
            items.push(Item::Help("아직 보낸 거래가 없습니다.".to_owned()));
        }
        self.received_items(crate::received::RecvChain::Sol, items);
        items.push(Item::CardEnd);
    }

    /// The recipient lines of activity row `row` (2026-11-10, like EVM's U11): "받는 주소" with,
    /// display only, the address-book or own-account name, then the whole address (ends
    /// emphasized) on its own copy line with `☆ 이 주소 저장` at its right end when offered
    /// (2026-11-11: sent rows come only from the wallet's own signed journal, so their recipient
    /// may be copied; the received history's senders never are, spec/07 §12.3).
    fn sol_recipient_items(
        &self,
        row: usize,
        address: &SolAddress,
        counterparties: &[String],
        items: &mut Vec<Item>,
    ) {
        let text = address.to_base58();
        let name = self
            .meta
            .as_ref()
            .and_then(|meta| meta.contact(BookChain::Sol, &text))
            .map(|contact| format!(" → 주소록: {}", contact.label))
            .or_else(|| {
                self.sol_account_rows()
                    .into_iter()
                    .find(|(_, _, known)| known == address)
                    .map(|(id, label, _)| format!(" → 내 계정: {}", self.sol_title(id, &label)))
            })
            .unwrap_or_default();
        items.push(Item::Help(format!("받는 주소{name}")));
        // The save icon only for the row's own counterparty (the list `이 주소 저장` reads).
        let save = counterparties
            .get(row)
            .filter(|known| **known == text && self.offer_save(BookChain::Sol, known))
            .and(crate::ui::screens_links::ids::row_id(
                crate::ui::screens_book::ids::SOL_ACTIVITY_BASE,
                crate::ui::screens_book::ids::SOL_ACTIVITY_SPAN,
                row,
            ))
            .map(crate::ui::screens_links::save_icon);
        crate::ui::screens_links::push_address_line(
            items,
            crate::ui::screens_links::ids::row_id(
                crate::ui::screens_links::ids::SOL_TO_BASE,
                crate::ui::screens_links::ids::SOL_TO_SPAN,
                row,
            ),
            &text,
            crate::ui::theme::AddressKind::Solana,
            save.into_iter().collect(),
        );
    }

    /// The "토큰" card of S10 (spec/04 §2.6, spec/07 §8.3, §12.3): the allowlisted tokens of the
    /// cluster for the selected account. Balances are read only from each token's derived ATA,
    /// so other tokens and NFTs are never fetched or shown.
    fn sol_token_card(&self, items: &mut Vec<Item>, address: &SolAddress, can_send: bool) {
        let entries: Vec<&'static SplAllowEntry> = spl_entries(self.sol_cluster()).collect();
        let symbols: Vec<&str> = entries.iter().map(|entry| entry.symbol).collect();
        items.push(Item::CardStart(Some("토큰".to_owned())));
        items.push(Item::Help(format!(
            "허용 목록 토큰만 표시합니다 ({}). 다른 토큰·NFT는 보이지 않고 보낼 수 없습니다.",
            symbols.join("·")
        )));
        let (hidden, shown): (Vec<_>, Vec<_>) = entries
            .into_iter()
            .enumerate()
            .partition(|(_, entry)| self.sol_token_hidden(entry));
        if shown.is_empty() {
            items.push(Item::Help(
                "보이는 토큰이 없습니다. 숨긴 토큰은 아래에서 다시 볼 수 있습니다.".to_owned(),
            ));
        }
        // The EVM token card's list rows (2026-11-11): symbol and balance on one line, then
        // the pinned mint whole (a click copies it) with `보내기`·`숨기기` at the right end.
        // What the balance means is said only when it is not a plain one (2026-11-12: no
        // token account yet, frozen, unreadable, not read) — the raw-unit line and the note
        // "SPL Token · mint 허용 목록 고정" were the same on every row.
        for (position, (index, entry)) in shown.into_iter().enumerate() {
            if position > 0 {
                items.push(Item::Rule);
            }
            let holding = self.sol_token_holding(address, entry);
            let (value, note) = token_holding_text(entry, holding);
            items.push(Item::ListRow {
                title: entry.symbol.to_owned(),
                note: String::new(),
                value,
                dim: false,
            });
            if !matches!(holding, Some(TokenHolding::Active(_))) {
                items.push(Item::Help(note));
            }
            let id = ids::TOKEN_SEND_BASE.saturating_add(u16::try_from(index).unwrap_or(0));
            let mut row = vec![
                Ctl::link(id, "보내기").compact().enabled(
                    can_send
                        && holding
                            .and_then(TokenHolding::balance)
                            .is_some_and(|raw| raw > 0),
                ),
            ];
            row.extend(Self::sol_token_hide_button(index, false));
            crate::ui::screens_links::push_address_line(
                items,
                Self::sol_token_copy_id(index),
                &entry.mint.to_base58(),
                crate::ui::theme::AddressKind::Solana,
                row,
            );
        }
        if !hidden.is_empty() {
            let open = self.sol.show_hidden_tokens;
            let count = hidden.len();
            items.push(Item::Row(vec![Ctl::link(
                ids::TOKEN_HIDDEN_TOGGLE,
                &if open {
                    format!("숨긴 토큰 {count}개 접기 ▾")
                } else {
                    format!("숨긴 토큰 {count}개 보기 ▸")
                },
            )]));
            if open {
                items.push(Item::Help(
                    "숨기기는 이 카드에서만 감춥니다. 보내기 화면의 자산 선택, 승인 창의 확인, 활동 기록은 그대로입니다."
                        .to_owned(),
                ));
                for (position, (index, entry)) in hidden.into_iter().enumerate() {
                    if position > 0 {
                        items.push(Item::Rule);
                    }
                    let (value, _) =
                        token_holding_text(entry, self.sol_token_holding(address, entry));
                    items.push(Item::ListRow {
                        title: entry.symbol.to_owned(),
                        note: "숨김".to_owned(),
                        value,
                        dim: true,
                    });
                    crate::ui::screens_links::push_address_line(
                        items,
                        Self::sol_token_copy_id(index),
                        &entry.mint.to_base58(),
                        crate::ui::theme::AddressKind::Solana,
                        Self::sol_token_hide_button(index, true),
                    );
                }
            }
        }
        items.push(Item::CardEnd);
    }

    /// The copy id of allowlist row `index`'s mint (none beyond the id span).
    fn sol_token_copy_id(index: usize) -> Option<u16> {
        u16::try_from(index)
            .ok()
            .filter(|offset| *offset < ids::TOKEN_COPY_SPAN)
            .map(|offset| ids::TOKEN_COPY_BASE.saturating_add(offset))
    }

    /// `숨기기` / `다시 보이기` of allowlist row `index` (none beyond the id span).
    fn sol_token_hide_button(index: usize, hidden: bool) -> Vec<Ctl> {
        u16::try_from(index)
            .ok()
            .filter(|offset| *offset < ids::TOKEN_HIDE_SPAN)
            .map(|offset| {
                Ctl::link(
                    ids::TOKEN_HIDE_BASE.saturating_add(offset),
                    if hidden {
                        "다시 보이기"
                    } else {
                        "숨기기"
                    },
                )
                .compact()
            })
            .into_iter()
            .collect()
    }

    /// The SOL/SPL send form.
    #[expect(clippy::too_many_lines, reason = "the send-form fields in order")]
    pub fn sol_send_screen(&self, items: &mut Vec<Item>) {
        let cluster = self.sol_cluster();
        items.push(crate::ui::screens::back_main());
        items.push(Item::Badged(
            Badge::solana(cluster),
            Box::new(Item::Title(format!("보내기 — {}", cluster.display_name()))),
        ));
        self.sol_cluster_banner(items, false);
        let form = &self.sol.send;
        if self.sol_journal_damaged() {
            items.push(Item::Banner(
                "거래 저널의 Solana 기록이 손상되어 Solana 보내기를 멈췄습니다. (E-VLT-006)"
                    .to_owned(),
                Tone::Blocked,
            ));
        }
        let Some((source, from, label)) = self.sol_form_sender() else {
            self.accounts_loading(items);
            return;
        };
        if let Some(record) = self.sol_pending(cluster, &from) {
            items.push(Item::Banner(
                "이 계정의 이전 전송을 확인 중입니다. 확정된 뒤 보낼 수 있습니다.".to_owned(),
                Tone::Warn,
            ));
            items.push(Item::Help(self.sol_record_status(&record)));
            items.push(Item::Mono(record.tx_id()));
            self.sol_send_now_row(items);
        }
        items.push(Item::CardStart(Some("보내는 계정".to_owned())));
        items.push(Item::Text(label));
        items.push(Item::Mono(grouped(&from)));
        let balance = self
            .sol_balance(&from)
            .map_or_else(String::new, |lamports| {
                format!(" · 잔액 {} (RPC 참고)", App::sol_text(lamports))
            });
        items.push(Item::Help(format!("{}{balance}", source.path_text())));
        // U7: `검토` stays off while the phrase waits for its backup quiz, and while the
        // YubiKey is still on its factory PINs (spec/10 §9.3).
        self.mn_signing_banner(self.sol_backup_gate(source), items);
        self.card_pin_banner(self.sol_card_gate(source), items);
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("받는 사람".to_owned())));
        if form.moving.is_some() {
            items.push(Item::Banner(
                "비표준 경로 계정의 자금을 내 표준 계정으로 옮깁니다. 받는 주소와 '보내기 최대'는 바꿀 수 없습니다."
                    .to_owned(),
                Tone::Warn,
            ));
        }
        if form.moving.is_none() {
            self.favorite_chip_items(BookTarget::Sol, items);
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
        // The format hint only until the address is valid (2026-11-12); the reminder to check
        // all of it then sits under the grouped address.
        if form.check.is_none() {
            items.push(Item::Help(form.token.map_or_else(
                || "Solana 주소 (base58)".to_owned(),
                |entry| {
                    format!(
                        "{0}을(를) 받을 사람의 지갑 주소를 넣으세요 ({0} 토큰 계정(ATA) 주소가 아닙니다).",
                        entry.symbol
                    )
                },
            )));
        }
        if form.picker && form.moving.is_none() {
            self.sol_picker_rows(items);
        }
        if let Some(code) = form.recipient_error {
            items.push(Item::Banner(code.text(), Tone::Danger));
        }
        if form.check.is_some() && !self.sol_move_target_ok() {
            items.push(Item::Banner(
                crate::app_sol::SOL_MOVE_TARGET_TEXT.to_owned(),
                Tone::Danger,
            ));
        }
        if let Some(check) = &form.check {
            items.push(Item::Mono(grouped(&check.to)));
            items.push(Item::Help(
                "굵게 표시된 가운데 부분까지 주소 전체를 확인하세요.".to_owned(),
            ));
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
                    KnownKind::OwnImported => format!("내 계정(가져온 개인키): {}", exact.label),
                    KnownKind::OwnHardware => format!("내 계정(YubiKey): {}", exact.label),
                    KnownKind::OwnMnemonic => {
                        format!("내 계정(추가한 복구 단어): {}", exact.label)
                    }
                    KnownKind::Sent | KnownKind::History => "보낸 적 있는 주소".to_owned(),
                };
                items.push(Item::Banner(note, Tone::Info));
            }
            for lookalike in &check.lookalikes {
                let name = match lookalike.kind {
                    KnownKind::Book { .. } => format!("주소록 '{}'", lookalike.label),
                    KnownKind::Own { .. }
                    | KnownKind::OwnImported
                    | KnownKind::OwnHardware
                    | KnownKind::OwnMnemonic => {
                        format!("내 계정 '{}'", lookalike.label)
                    }
                    KnownKind::Sent | KnownKind::History => "보낸 내역의 주소".to_owned(),
                };
                items.push(Item::Banner(
                    format!(
                        "{name}와(과) 앞 3자 또는 뒤 3자가 같지만 다른 주소입니다. 주소 오염 공격일 수 있습니다. (승인 창 고위험 L03)"
                    ),
                    Tone::HighRisk,
                ));
                items.push(Item::Mono(grouped(&lookalike.address)));
            }
            if check.off_curve {
                items.push(Item::Banner(
                    "일반 지갑이 아님: 프로그램 소유 주소(PDA)나 토큰 계정일 수 있음 (승인 창 고위험 L02)"
                        .to_owned(),
                    Tone::HighRisk,
                ));
            }
            if check.first_time {
                items.push(Item::Banner(
                    "처음 보내는 주소입니다. 주소 전체를 확인하고, 큰 금액은 소액 시험 송금 뒤 보내세요."
                        .to_owned(),
                    Tone::Warn,
                ));
            }
            if form.moving.is_none() {
                self.recipient_save_items(BookTarget::Sol, items);
            }
        }
        items.push(Item::CardEnd);
        self.sol_asset_amount_card(items, &from);
        // What `검토`, the approval or the signature ended with, next to the button.
        if let Some(info) = &form.info {
            items.push(Item::Banner(info.clone(), Tone::Warn));
        }
        self.journal_send_items(crate::app_sidecar::SendChain::Sol, items);
        let blocker = self.sol_review_blocker();
        items.push(Item::Row(vec![
            Ctl::primary(ids::SEND_REVIEW, "검토").enabled(blocker.is_none()),
            Ctl::button(ids::SEND_CANCEL, "취소"),
        ]));
        // What `검토` waits for, or that it sends nothing yet (2026-11-12).
        items.push(Item::Help(
            crate::app_sol::ReviewBlocker::line(blocker).to_owned(),
        ));
    }

    /// The "보낼 자산과 금액" card: asset radios (SOL and the cluster's allowlisted tokens), the
    /// token's pinned facts and balance, the amount in the asset's decimals, send max and fees.
    fn sol_asset_amount_card(&self, items: &mut Vec<Item>, from: &SolAddress) {
        let form = &self.sol.send;
        let asset = form.asset();
        items.push(Item::CardStart(Some("보낼 자산과 금액".to_owned())));
        let radios: Vec<Ctl> = self
            .sol_assets()
            .into_iter()
            .take(usize::from(ids::SEND_ASSET_SPAN))
            .enumerate()
            .map(|(index, choice)| {
                Ctl::radio(
                    ids::SEND_ASSET_BASE.saturating_add(u16::try_from(index).unwrap_or(0)),
                    choice.symbol(),
                    choice == asset,
                    index == 0,
                )
            })
            .collect();
        items.push(Item::LabeledRow("자산".to_owned(), radios));
        if let SolAsset::Spl(entry) = asset {
            let (value, note) = token_holding_text(entry, self.sol_token_holding(from, entry));
            items.push(Item::Help(format!(
                "{} · SPL Token · 보유 {value}",
                entry.symbol
            )));
            items.push(Item::Help(note));
            items.push(Item::Help("mint (허용 목록 고정)".to_owned()));
            items.push(Item::Mono(grouped(&entry.mint)));
        }
        let mut amount_row = vec![
            Ctl::edit(ids::SEND_AMOUNT_EDIT, &form.amount_text, 260, false, 32)
                .enabled(!form.send_max),
        ];
        if form.moving.is_none() {
            amount_row.push(Ctl::check(ids::SEND_MAX, "보내기 최대", form.send_max));
        }
        items.push(Item::LabeledRow(
            format!("금액 ({})", asset.symbol()),
            amount_row,
        ));
        if form.send_max {
            items.push(Item::Help(match asset {
                SolAsset::Sol => "보내기 최대: 잔액 − 최대 수수료를 보내고 이 계정의 SOL 잔액은 0이 됩니다(승인 창에서 확인)."
                    .to_owned(),
                SolAsset::Spl(entry) => format!(
                    "보내기 최대: 이 계정의 {} 전부를 보냅니다. SOL에서는 수수료(와 필요하면 받는 토큰 계정 생성비)만 나갑니다(승인 창에서 확인).",
                    entry.symbol
                ),
            }));
        }
        if let Some(code) = form.amount_error {
            items.push(Item::Banner(code.text(), Tone::Danger));
        }
        // In SOL first (2026-11-08, like the EVM form's "예상 최대 수수료"); lamports and the CU
        // limit behind `수수료 계산 보기`. The caps and the approval window are unchanged.
        items.push(Item::Text(format!(
            "예상 수수료 약 {} (최대 {}) — 최종 수수료는 승인 창에서 확인합니다.",
            App::sol_text(5_000),
            App::sol_text(self.settings.solana.max_fee_lamports)
        )));
        if self.show_advanced {
            items.push(Item::Help(format!(
                "계산: 기본 5,000 lamports + 우선 수수료(CU 한도 {}), 상한 {} lamports.",
                format_raw(u64::from(yw_core::sol::fee::template_cu_limit(asset))),
                format_raw(self.settings.solana.max_fee_lamports)
            )));
        }
        items.push(Item::Row(vec![Ctl::link(
            crate::ui::screens::ids::ADVANCED_TOGGLE,
            if self.show_advanced {
                "수수료 계산 숨기기 ▾"
            } else {
                "수수료 계산 보기 (lamports·CU) ▸"
            },
        )]));
        if let SolAsset::Spl(entry) = asset {
            items.push(Item::Help(format!(
                "받는 사람에게 {} 토큰 계정이 없으면 이 거래가 만들고, 생성 비용(rent)을 보내는 계정의 SOL로 냅니다. 금액은 승인 창에서 확인하세요. 보낸 뒤에도 SOL이 조금 남아야 합니다.",
                entry.symbol
            )));
        }
        items.push(Item::CardEnd);
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
                KnownKind::Book { .. } => {
                    let favorite = self.meta.as_ref().is_some_and(|meta| {
                        meta.is_favorite(BookChain::Sol, &entry.address.to_base58())
                    });
                    let star = if favorite { "★ " } else { "" };
                    Some((format!("{star}주소록: {}", entry.label), entry.address))
                }
                KnownKind::Own { .. }
                | KnownKind::OwnImported
                | KnownKind::OwnHardware
                | KnownKind::OwnMnemonic => {
                    Some((format!("내 계정: {}", entry.label), entry.address))
                }
                KnownKind::Sent | KnownKind::History => None,
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
            items.push(Item::Banner(
                "서명하고 저널에 기록한 뒤 전송했습니다.".to_owned(),
                Tone::Success,
            ));
            items.push(Item::CardStart(None));
            let status = self
                .sol_records()
                .iter()
                .find(|record| record.signature() == signature)
                .map_or_else(
                    || "종결 (활동 참고)".to_owned(),
                    |record| self.sol_record_status(record),
                );
            items.push(Item::Badged(
                Badge::solana(cluster),
                Box::new(Item::Field(
                    "상태".to_owned(),
                    format!("{status} ({})", cluster.display_name()),
                )),
            ));
            items.push(Item::Field("서명(거래 ID)".to_owned(), String::new()));
            items.push(Item::Mono(yw_core::codec::base58::base58_encode(
                &signature,
            )));
            // For checking on an explorer: 88 characters are not retyped by hand.
            let mut buttons = vec![Ctl::button(ids::RESULT_COPY, "해시 복사")];
            buttons.extend(self.explorer_tx_buttons(
                crate::network::NetworkId::Solana(crate::app_explorer::app_cluster(cluster)),
                &yw_core::codec::base58::base58_encode(&signature),
                Some((
                    crate::ui::screens_explorer::ids::RESULT_SOL_OPEN,
                    crate::ui::screens_explorer::ids::RESULT_SOL_COPY,
                )),
            ));
            items.push(Item::Row(buttons));
            items.push(Item::CardEnd);
            self.sol_send_now_row(items);
            self.result_save_items(BookTarget::Sol, items);
        }
        let mut row = vec![Ctl::primary(crate::ui::screens::ids::BACK_MAIN, "메인으로")];
        // A scan move: the kept results, for the account's other assets (spec/07 §3.3).
        let moved = self
            .sol
            .resend
            .as_ref()
            .is_some_and(|(form, _)| form.moving.is_some());
        if moved && self.sol.scan.stage == crate::app_sol::ScanStage::Done {
            row.push(Ctl::button(ids::SCAN_BACK, "스캔 결과로"));
        }
        if self.sol_can_resend() {
            row.push(Ctl::button(ids::SEND_AGAIN, "다시 보내기"));
            items.push(Item::Help(
                "같은 받는 주소·금액으로 보내기 화면을 다시 엽니다. 새로 검토하고 새로 승인해야 합니다(이전 승인은 쓰지 않음).".to_owned(),
            ));
        }
        items.push(Item::Row(row));
    }

    /// "지금 다시 전송" for a pending transfer (spec/07 §14.3): the same signed bytes, so it can
    /// land at most once; a new signature is only offered once the RPC shows the blockhash
    /// expired (`Expired` → "다시 보내기").
    fn sol_send_now_row(&self, items: &mut Vec<Item>) {
        if self.sol_send_now_target().is_none() {
            return;
        }
        items.push(Item::Row(vec![Ctl::button(
            ids::SEND_NOW,
            "지금 다시 전송",
        )]));
        items.push(Item::Help(
            "서명한 같은 거래를 바로 다시 보냅니다. 서명이 같아 한 번만 처리됩니다. 블록해시가 만료된 것이 RPC로 확인되면 새로 서명해 다시 보낼 수 있습니다.".to_owned(),
        ));
    }

    /// S12 for Solana: full address, QR = the base58 text, path, cluster.
    pub fn sol_receive_screen(&self, items: &mut Vec<Item>) {
        items.push(crate::ui::screens::back_main());
        items.push(Item::Badged(
            Badge::solana(self.sol_cluster()),
            Box::new(Item::Title(format!(
                "받기 — {}",
                self.sol_cluster().display_name()
            ))),
        ));
        if self.mode == AppMode::BackupPending {
            items.push(Item::Banner(
                "백업 확인 전입니다. 확인을 마치기 전에는 큰 금액을 받지 마세요.".to_owned(),
                Tone::Warn,
            ));
        }
        let Some((index, label, address)) = self.sol_selected() else {
            self.accounts_loading(items);
            return;
        };
        items.push(Item::CardStart(None));
        // The account only: the screen title above names the cluster (2026-11-12).
        items.push(Item::Subtitle(self.sol_title(index, &label)));
        if self.sol_cluster() == SolCluster::Devnet {
            items.push(Item::Banner(
                "devnet(테스트) 주소입니다. 주소 자체는 mainnet과 같습니다.".to_owned(),
                Tone::Testnet,
            ));
        } else {
            items.push(Item::Banner(
                crate::ui::screens::T_MAINNET.to_owned(),
                Tone::BtcMainnet,
            ));
        }
        self.mn_receive_banner(
            self.mn_backup_gate(
                index.mnemonic().map(yw_core::vault::RecordId::from_bytes),
                matches!(index, crate::app_sol::SolAccountId::Derived(_)),
            ),
            items,
        );
        let tokens: Vec<&str> = spl_entries(self.sol_cluster())
            .map(|entry| entry.symbol)
            .collect();
        items.push(Item::Help(format!(
            "SOL과 허용 목록 토큰({})만 받으세요. 다른 토큰은 이 지갑에 보이지 않고 보낼 수 없습니다.",
            tokens.join("·")
        )));
        // The address on its copy line, then the QR (2026-11-12, all chains: the notes that
        // are not needed to copy follow the QR).
        items.push(crate::ui::screens::receive_address_row(
            &grouped(&address),
            ids::COPY_ADDRESS,
            Vec::new(),
        ));
        items.push(Item::Qr(address.to_base58()));
        items.push(Item::Help(
            "토큰을 보내는 쪽에도 이 지갑 주소를 알려주면 됩니다(토큰 계정 주소는 상대 지갑이 계산합니다)."
                .to_owned(),
        ));
        items.push(Item::Help(index.path_text()));
        items.push(Item::CardEnd);
    }

    /// S15 Solana section (spec/07 §10, §3.3).
    pub fn sol_settings_section(&self, items: &mut Vec<Item>) {
        let solana = &self.settings.solana;
        items.push(Item::CardStart(Some("Solana 네트워크".to_owned())));
        items.push(Item::Help(
            "메인 화면 Solana 탭에서 쓸 네트워크입니다. devnet은 시험용이며 실제 자산이 아닙니다."
                .to_owned(),
        ));
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
        items.push(Item::Help(
            "RPC 주소는 '네트워크(RPC)' 구역의 solana:mainnet·solana:devnet 행에 있습니다."
                .to_owned(),
        ));
        items.push(Item::Rule);
        items.push(Item::Row(vec![Ctl::button(
            ids::SCAN_OPEN,
            "다른 경로 스캔",
        )]));
        items.push(Item::Help(
            "다른 지갑(Ledger Live, solana-keygen 등)에서 쓰던 경로의 계정을 찾습니다.".to_owned(),
        ));
        items.push(Item::CardEnd);
        if self.show_advanced {
            items.push(Item::CardStart(Some(
                "Solana 수수료 상한 (고급)".to_owned(),
            )));
            items.push(Item::Help(
                "지갑이 계산한 수수료가 이 값을 넘으면 보내기를 막습니다. 보통은 바꿀 필요가 없습니다."
                    .to_owned(),
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
                Ctl::primary(ids::FEE_SAVE, "저장"),
                Ctl::button(ids::FEE_DEFAULT, "기본값으로"),
            ]));
            items.push(Item::Help(
                "수수료 상한 10,000–10,000,000, CU 가격 상한 0–100,000,000. 우선 수수료 가격은 최근 값의 p75와 두 상한 중 작은 값입니다."
                    .to_owned(),
            ));
            items.push(Item::CardEnd);
        }
        self.advanced_toggle(items);
    }

    /// The recovery scan screen (spec/07 §3.3).
    pub fn sol_scan_screen(&self, items: &mut Vec<Item>) {
        use crate::app_sol::ScanStage;
        items.push(crate::ui::screens::back_main());
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
                    format!(
                        "조회하는 모든 주소가 RPC 공급자(설정한 {} 엔드포인트의 운영자)에 전달되어 서로 연결될 수 있습니다.",
                        self.sol_cluster().network_id()
                    ),
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
                // Where `표준 계정으로 이동` sends: only a standard account of the primary phrase
                // passes the signing check (spec/07 §3.3, §13.1-6).
                let target = self.sol_scan_target();
                if rows.iter().any(|row| !row.source.is_standard()) {
                    match &target {
                        Some((id, label, _)) => items.push(Item::Field(
                            "옮겨 받을 계정".to_owned(),
                            format!("{label} · {}", id.path_text()),
                        )),
                        None => items.push(Item::Banner(
                            crate::app_sol::SOL_SCAN_NO_TARGET_TEXT.to_owned(),
                            Tone::Warn,
                        )),
                    }
                }
                let movable = target.is_some() && matches!(self.mode, AppMode::Unlocked { .. });
                let shown = usize::from(ids::SCAN_ROW_SPAN / ids::SCAN_ROW_STRIDE);
                for (index, row) in rows.iter().take(shown).enumerate() {
                    let (balance, tokens) = self.sol_scan_balances(row);
                    let mut text =
                        format!("{} · {}", row.source.path_text(), App::sol_text(balance));
                    for (entry, holding) in &tokens {
                        if let Some(raw) = holding.balance().filter(|raw| *raw > 0) {
                            let _ = write!(
                                text,
                                " · {} {}",
                                format_amount(raw, entry.decimals),
                                entry.symbol
                            );
                        }
                    }
                    text.push_str(" (RPC 참고)");
                    items.push(Item::Text(text));
                    items.push(Item::Mono(grouped(&row.address)));
                    if row.source.is_standard() {
                        if let Some(id) = ids::scan_row_id(ids::ScanAction::Add(index)) {
                            items.push(Item::Row(vec![Ctl::button(id, "계정 추가")]));
                        }
                    } else if let Some(id) = ids::scan_row_id(ids::ScanAction::Move(index)) {
                        items.push(Item::Row(vec![
                            Ctl::button(id, "표준 계정으로 이동").enabled(movable),
                        ]));
                    }
                }
                items.push(Item::Muted(
                    "비표준 경로 자금은 주 복구 단어의 표준 계정으로 '보내기 최대'만 할 수 있습니다(승인 창 L07). 자산마다 한 번씩 옮기며, 이 결과는 클러스터를 바꾸거나 잠글 때까지 남습니다. 다른 표준 계정으로 받으려면 Solana 탭에서 그 계정을 고르세요."
                        .to_owned(),
                ));
                items.push(Item::Row(vec![Ctl::button(ids::SCAN_AGAIN, "다시 스캔")]));
            }
        }
    }

    /// The transaction ids of the S10 Solana activity rows, in display order (the rows of
    /// [`Self::sol_activity_counterparties`]), for their `해시 복사`.
    #[must_use]
    pub fn sol_activity_tx_ids(&self) -> Vec<String> {
        let cluster = self.sol_cluster();
        let mut out: Vec<String> = self
            .sol_records()
            .iter()
            .filter(|record| record.cluster == cluster)
            .map(yw_core::journal::sol::SolRecord::tx_id)
            .collect();
        if let Some(meta) = self.meta.as_ref() {
            for entry in meta.activity_of(cluster.network_id()) {
                if out.len() >= crate::app_sol::SOL_MAX_ACTIVITY_ROWS {
                    break;
                }
                out.push(entry.tx_id.clone());
            }
        }
        out
    }

    /// The counterparties of the S10 Solana activity rows, in display order (`""` without one):
    /// the cluster's journal records, then its meta activity, at most `SOL_MAX_ACTIVITY_ROWS`
    /// after the records (as drawn).
    #[must_use]
    pub fn sol_activity_counterparties(&self) -> Vec<String> {
        let cluster = self.sol_cluster();
        let mut out: Vec<String> = self
            .sol_records()
            .iter()
            .filter(|record| record.cluster == cluster)
            .map(|record| {
                record
                    .core()
                    .map_or_else(String::new, |core| core.to.to_base58())
            })
            .collect();
        if let Some(meta) = self.meta.as_ref() {
            for entry in meta.activity_of(cluster.network_id()) {
                if out.len() >= crate::app_sol::SOL_MAX_ACTIVITY_ROWS {
                    break;
                }
                out.push(
                    SolAddress::parse(&entry.counterparty)
                        .map_or_else(|_| String::new(), SolAddress::to_base58),
                );
            }
        }
        out
    }

    /// The transaction id line of activity row `row` (2026-11-11): a click copies it (the
    /// transaction id is public data, as on the other chains), `탐색기에서 열기` ↗ and
    /// `탐색기 링크 복사` 🔗 at its right end when the cluster has a transaction page; then the
    /// open `이 주소 저장` prompt of the row's recipient, if any.
    fn sol_activity_actions(
        &self,
        row: usize,
        tx_id: &str,
        counterparties: &[String],
        prompt_drawn: &mut bool,
        items: &mut Vec<Item>,
    ) {
        use crate::ui::screens_explorer::ids::{
            SOL_ACTIVITY_BASE, SOL_ACTIVITY_SPAN, activity_ids,
        };
        crate::ui::screens_links::push_hash_line(
            items,
            crate::ui::screens_links::ids::row_id(
                ids::ACTIVITY_COPY_BASE,
                ids::ACTIVITY_COPY_SPAN,
                row,
            ),
            tx_id,
            self.explorer_tx_icons(
                crate::network::NetworkId::Solana(self.settings.solana.cluster),
                tx_id,
                activity_ids(SOL_ACTIVITY_BASE, SOL_ACTIVITY_SPAN, row),
            ),
        );
        if let Some(address) = counterparties
            .get(row)
            .filter(|address| !address.is_empty())
            && !*prompt_drawn
        {
            *prompt_drawn =
                self.prompt_items(PromptPlace::Activity, BookChain::Sol, address, items);
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
