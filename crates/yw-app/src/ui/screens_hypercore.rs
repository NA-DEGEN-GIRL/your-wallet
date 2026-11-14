//! `HyperCore` screen contents (spec/11 §8): the card on the EVM tab (S10), the transfer form
//! S-HC and the settings block under `EVM 체인`.

use yw_core::approval::escape_untrusted;
use yw_core::hypercore::{HcNetwork, WITHDRAW_FEE_USDC};
use yw_core::lang::Lang;

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
    /// `최대` (the whole available amount).
    pub const MAX: u16 = 13_468;
    /// Settings: card on/off.
    pub const ENABLED: u16 = 13_490;
    /// Settings: testnet API edit.
    pub const API_EDIT: u16 = 13_491;
    /// Settings: save the testnet API.
    pub const API_SAVE: u16 = 13_492;
    /// Settings: official testnet API.
    pub const API_DEFAULT: u16 = 13_493;
    /// The folded card's `펼치기 ▸` (2026-11-10).
    pub const EXPAND: u16 = 13_494;
    /// The unfolded card's `접기 ▴`.
    pub const COLLAPSE: u16 = 13_495;
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
        MAX,
        ENABLED,
        API_EDIT,
        API_SAVE,
        API_DEFAULT,
        EXPAND,
        COLLAPSE,
    ];
}

/// The EVM chains next to which the `HyperCore` card is always unfolded: `HyperEVM` mainnet and
/// testnet (`HyperEVM으로 이동`·`HyperEVM에서 Core로 이동`) and Arbitrum One and Sepolia (withdrawals
/// arrive there, spec/11 §8).
pub const HC_UNFOLDED_CHAINS: [u64; 4] = [999, 998, 42_161, 421_614];

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

fn network_row(lang: Lang, network: HcNetwork) -> Item {
    Item::Row(vec![
        Ctl::radio(
            ids::NET_MAINNET,
            text::MAINNET.get(lang),
            network == HcNetwork::Mainnet,
            true,
        ),
        Ctl::radio(
            ids::NET_TESTNET,
            text::TESTNET.get(lang),
            network == HcNetwork::Testnet,
            false,
        ),
    ])
}

/// The `HyperCore` screen texts (spec/11 §8; English spec/14).
pub mod text {
    yw_core::texts! {
        MAINNET = "메인넷" / "Mainnet";
        TESTNET = "테스트넷" / "Testnet";
        /// The `HyperCore` mainnet band (named, since the EVM tab above may show a testnet).
        HC_MAINNET = "HyperCore 메인넷: 실제 자산" / "HyperCore mainnet: real assets";
        TESTNET_BAND = "테스트넷 — 실제 자산이 아닙니다" / "Testnet — not real assets";
        FOLDED_STATE(2) = "계정 가치 {0} USDC · 현물 {1}종" / "Account value {0} USDC · {1} spot tokens";
        LOADING = "불러오는 중…" / "Loading…";
        LOAD_FAILED = "잔액을 불러오지 못했습니다" / "Could not load the balances";
        NOT_LOADED = "잔액을 아직 불러오지 않았습니다" / "The balances are not loaded yet";
        NOT_LOADED_DOT = "잔액을 아직 불러오지 않았습니다." / "The balances are not loaded yet.";
        EXPAND = "펼치기 ▸" / "Expand ▸";
        COLLAPSE = "접기 ▴" / "Collapse ▴";
        CARD_HELP = "같은 EVM 주소의 HyperCore(Hyperliquid L1) 잔액입니다. 이 지갑은 전송만 하고 거래(주문)는 하지 않습니다."
            / "HyperCore (Hyperliquid L1) balances of the same EVM address. This wallet only transfers; it does not trade (place orders).";
        PERP_USDC = "선물(perp) USDC" / "Perp USDC";
        PERP_STATE(2) = "계정 가치 {0} · 출금 가능 {1}" / "Account value {0} · withdrawable {1}";
        OPEN_POSITIONS(1) = " · 열린 포지션 {0}개" / " · {0} open positions";
        SPOT = "현물(spot)" / "Spot";
        NONE = "없음" / "None";
        SPOT_COIN(1) = "현물 {0}" / "Spot {0}";
        ON_HOLD(2) = "{0} (주문 보류 {1})" / "{0} (on hold for orders {1})";
        SEND_CORE = "보내기(Core)" / "Send (Core)";
        CLASS = "현물↔선물 이동" / "Spot↔perp";
        WITHDRAW = "Arbitrum으로 출금" / "Withdraw to Arbitrum";
        TO_EVM = "HyperEVM으로 이동" / "Move to HyperEVM";
        FROM_EVM = "HyperEVM에서 Core로 이동" / "Move from HyperEVM to Core";
        REFRESH = "새로고침" / "Refresh";
        ACTIVITY = "HyperCore 활동 (이번 실행)" / "HyperCore activity (this run)";
        ACTIVITY_HELP = "Hyperliquid는 전송에 거래 해시를 돌려주지 않아 활동 줄에는 탐색기 링크가 없습니다. 위 '탐색기에서 주소 보기'에서 이 계정의 기록을 확인하세요."
            / "Hyperliquid returns no transaction hash for transfers, so the activity rows have no explorer link. Check this account's history with 'View address in explorer' above.";
        STATUS_LINE(2) = "상태: {0} · nonce {1}" / "Status: {0} · nonce {1}";
        TITLE_SEND = "보내기 (HyperCore)" / "Send (HyperCore)";
        TITLE_CLASS = "현물↔선물 USDC 이동" / "Move USDC spot↔perp";
        TITLE_WITHDRAW = "Arbitrum으로 USDC 출금" / "Withdraw USDC to Arbitrum";
        TITLE_TO_EVM = "HyperEVM으로 이동" / "Move to HyperEVM";
        SIGNING_ACCOUNT = "서명 계정" / "Signing account";
        CONTENT = "내용" / "Details";
        ASSET_PERP(1) = "USDC — 선물(perp) 잔액 (출금 가능 {0})" / "USDC — perp balance (withdrawable {0})";
        ASSET_SPOT(2) = "현물 {0} — {1}" / "Spot {0} — {1}";
        RECIPIENT_CORE = "받는 주소 (HyperCore)" / "Recipient (HyperCore)";
        SPOT_TO_PERP = "현물(spot) → 선물(perp)" / "Spot → perp";
        PERP_TO_SPOT = "선물(perp) → 현물(spot)" / "Perp → spot";
        CLASS_HELP = "같은 계정 안에서 USDC를 옮깁니다. 받는 주소는 없습니다."
            / "Moves USDC within the same account. There is no recipient.";
        RECIPIENT_ARBITRUM = "받는 주소 (Arbitrum One)" / "Recipient (Arbitrum One)";
        WITHDRAW_BANNER(1) = "고정 출금 수수료 {0} USDC는 입력한 금액에서 빠집니다(받는 금액 = 입력 금액 − {0}). 출금 가능액 전체를 출금할 수 있습니다. Arbitrum One에 USDC로 도착하며 약 5분 걸립니다."
            / "The fixed withdrawal fee of {0} USDC comes out of the amount entered (received = amount − {0}). The whole withdrawable balance can be withdrawn. It arrives as USDC on Arbitrum One in about 5 minutes.";
        NO_EVM_TOKENS = "HyperEVM에 연결된 현물 토큰 잔액이 없습니다."
            / "No balance of a spot token linked to HyperEVM.";
        EVM_TOKEN(2) = "{0} (시스템 주소 {1})" / "{0} (system address {1})";
        TO_EVM_HELP = "토큰의 시스템 주소로 보내면 HyperEVM의 같은 주소(이 계정)로 들어갑니다. HyperCore에서 HYPE로 가스(200k gas)를 냅니다."
            / "Sending to the token's system address delivers it to the same address (this account) on HyperEVM. Gas (200k gas) is paid in HYPE on HyperCore.";
        AMOUNT = "금액" / "Amount";
        MAX = "최대" / "Max";
        AVAILABLE_TO_EVM(2) = "옮길 수 있는 양: {0} {1} (HyperEVM 자릿수를 넘는 끝수는 HyperCore에 남깁니다)"
            / "Movable: {0} {1} (digits beyond HyperEVM's decimals stay on HyperCore)";
        AVAILABLE_WITHDRAW(2) = "출금 가능: {0} {1} (수수료는 이 금액에서 빠집니다)"
            / "Withdrawable: {0} {1} (the fee comes out of this amount)";
        AVAILABLE(2) = "사용 가능: {0} {1}" / "Available: {0} {1}";
        AVAILABLE_LATER = "사용 가능한 양은 잔액을 불러온 뒤 보입니다."
            / "The available amount shows once the balances are loaded.";
        REVIEW = "검토" / "Review";
        CANCEL = "취소" / "Cancel";
        ACK = "주소 전체를 직접 확인했습니다" / "I checked the whole address myself";
        SETTINGS_SHOW = "EVM 탭에 HyperCore 카드 보이기 (잔액·전송, 거래 없음)"
            / "Show the HyperCore card on the EVM tab (balances and transfers, no trading)";
        MAINNET_API = "메인넷 API" / "Mainnet API";
        FIXED(1) = "{0} (고정)" / "{0} (fixed)";
        TESTNET_API = "테스트넷 API" / "Testnet API";
        SAVE = "저장" / "Save";
        OFFICIAL = "공식 주소로" / "Use official";
        API_HELP = "HTTPS만 됩니다. /info와 /exchange가 이 주소 뒤에 붙습니다."
            / "HTTPS only. /info and /exchange are appended to this address.";
        API_SAVED = "테스트넷 API 주소를 저장했습니다." / "Saved the testnet API address.";
        API_INVALID = "HTTPS 주소가 아닙니다 (https://…, ?·# 없이)."
            / "Not an HTTPS address (https://…, without ? or #).";
    }
}

/// The network band of the card and S-HC: testnet, or T-MAINNET like the built-in EVM mainnets
/// (the card's network is its own, independent of the selected EVM chain).
fn network_band(lang: Lang, network: HcNetwork, items: &mut Vec<Item>) {
    items.push(match network {
        HcNetwork::Testnet => Item::Banner(text::TESTNET_BAND.get(lang).to_owned(), Tone::Testnet),
        HcNetwork::Mainnet => Item::Banner(text::HC_MAINNET.get(lang).to_owned(), Tone::BtcMainnet),
    });
}

impl App {
    /// Whether the `HyperCore` card may be folded to one line (2026-11-10): the selected EVM
    /// chain is not one the card works with ([`HC_UNFOLDED_CHAINS`]) and no `HyperCore` action of
    /// the selected account is being signed or sent.
    #[must_use]
    pub fn hc_foldable(&self) -> bool {
        let account = self.selected_account().map(|(account, ..)| account);
        let network = self.hc_network();
        !HC_UNFOLDED_CHAINS.contains(&self.settings.evm_chain_id)
            && !self.hypercore.activity.iter().any(|row| {
                row.network == network
                    && Some(row.account) == account
                    && matches!(
                        row.status,
                        crate::app_hypercore::HcStatus::Signing
                            | crate::app_hypercore::HcStatus::Submitting
                    )
            })
    }

    /// The folded card: the badge and one line (network, account value and spot count, or the
    /// load state), and `펼치기 ▸`. No action button and so no band (every place that draws
    /// the actions draws the network band too). The balances are still read every 60 s.
    fn hc_folded_card(&self, network: HcNetwork, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let state = match self.hc_balances() {
            Some(balances) => text::FOLDED_STATE.fill(
                lang,
                [
                    &balances.perp.account_value,
                    &self.hc_spot_rows().len().to_string(),
                ],
            ),
            None if self.hypercore.loading => text::LOADING.get(lang).to_owned(),
            None if self.hypercore.error.is_some() => text::LOAD_FAILED.get(lang).to_owned(),
            None => text::NOT_LOADED.get(lang).to_owned(),
        };
        items.push(Item::CardStart(None));
        items.push(Item::Badged(
            crate::ui::badge::Badge::hyperliquid(),
            Box::new(Item::Text(format!(
                "Hyperliquid {} · {state}",
                yw_core::hypercore::text::network_label(lang, network)
            ))),
        ));
        items.push(Item::Row(vec![Ctl::link(
            ids::EXPAND,
            text::EXPAND.get(lang),
        )]));
        items.push(Item::CardEnd);
    }

    /// The S10 `HyperCore` card (balances, actions, session activity), folded to one line next
    /// to a chain it does not work with ([`App::hc_foldable`]) until `펼치기 ▸` (this run only).
    #[expect(clippy::too_many_lines, reason = "the card's sections in order")]
    pub fn hc_card(&self, items: &mut Vec<Item>) {
        if !self.hc_visible() {
            return;
        }
        let lang = self.settings.language;
        let network = self.hc_network();
        let foldable = self.hc_foldable();
        if foldable && !self.hypercore.unfolded {
            self.hc_folded_card(network, items);
            return;
        }
        items.push(Item::CardStart(None));
        items.push(Item::Badged(
            crate::ui::badge::Badge::hyperliquid(),
            Box::new(Item::Subtitle(format!(
                "Hyperliquid {}",
                yw_core::hypercore::text::network_label(lang, network)
            ))),
        ));
        if foldable {
            items.push(Item::Row(vec![Ctl::link(
                ids::COLLAPSE,
                text::COLLAPSE.get(lang),
            )]));
        }
        // The network tag always goes with the action buttons below (2026-11-11: a small tag
        // after the radios, as on the network cards; S-HC keeps the full band).
        items.push(network_row(lang, network));
        items.push(match network {
            HcNetwork::Testnet => {
                Item::Pill(text::TESTNET_BAND.get(lang).to_owned(), Tone::Testnet)
            }
            HcNetwork::Mainnet => {
                Item::Pill(text::HC_MAINNET.get(lang).to_owned(), Tone::BtcMainnet)
            }
        });
        items.push(Item::Help(text::CARD_HELP.get(lang).to_owned()));
        match self.hc_balances() {
            Some(balances) => {
                let positions = if balances.perp.positions > 0 {
                    text::OPEN_POSITIONS.fill(lang, [&balances.perp.positions.to_string()])
                } else {
                    String::new()
                };
                items.push(Item::Field(
                    text::PERP_USDC.get(lang).to_owned(),
                    text::PERP_STATE.fill(
                        lang,
                        [&balances.perp.account_value, &balances.perp.withdrawable],
                    ) + &positions,
                ));
                let rows = self.hc_spot_rows();
                if rows.is_empty() {
                    items.push(Item::Field(
                        text::SPOT.get(lang).to_owned(),
                        text::NONE.get(lang).to_owned(),
                    ));
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
                        text::SPOT_COIN.fill(lang, [&escape_untrusted(&coin).text]),
                        match hold {
                            Some(hold) => text::ON_HOLD.fill(lang, [&total, &hold]),
                            None => total,
                        },
                    ));
                }
            }
            None if self.hypercore.loading => {
                items.push(Item::Muted(text::LOADING.get(lang).to_owned()));
            }
            None => items.push(Item::Muted(text::NOT_LOADED_DOT.get(lang).to_owned())),
        }
        if let Some(error) = &self.hypercore.error {
            items.push(Item::Banner(error.clone(), Tone::Warn));
        }
        items.push(Item::Row(vec![
            Ctl::button(ids::OPEN_SEND, text::SEND_CORE.get(lang)),
            Ctl::button(ids::OPEN_CLASS, text::CLASS.get(lang)),
            Ctl::button(ids::OPEN_WITHDRAW, text::WITHDRAW.get(lang)),
        ]));
        items.push(Item::Row(vec![
            Ctl::button(ids::OPEN_TO_EVM, text::TO_EVM.get(lang)),
            Ctl::button(ids::OPEN_FROM_EVM, text::FROM_EVM.get(lang)),
            Ctl::button(ids::REFRESH, text::REFRESH.get(lang)),
        ]));
        // The selected account's rows only, like the balances above.
        let account = self.selected_account().map(|(account, ..)| account);
        // 2026-11-11: the account on Hyperliquid's explorer. `/exchange` answers without a
        // transaction hash, so the activity rows below have no link of their own; this page
        // lists the account's actions.
        let explorer = account.and_then(|account| {
            self.explorer_address_link(
                crate::explorer::ExplorerNet::HyperCore(network),
                &account.to_checksum(),
                crate::ui::screens_explorer::ids::CARD_HC,
            )
        });
        if let Some(link) = explorer {
            items.push(Item::Row(vec![link]));
        }
        let rows: Vec<_> = self
            .hypercore
            .activity
            .iter()
            .filter(|row| row.network == network && Some(row.account) == account)
            .collect();
        if !rows.is_empty() {
            items.push(Item::Rule);
            items.push(Item::Subtitle(text::ACTIVITY.get(lang).to_owned()));
            items.push(Item::Help(text::ACTIVITY_HELP.get(lang).to_owned()));
            for row in rows {
                let to = row
                    .to
                    .map(|to| format!(" → {}", to.to_checksum()))
                    .unwrap_or_default();
                items.push(Item::Text(format!(
                    "{} · {} · {}{to}",
                    local_time(row.nonce),
                    yw_core::hypercore::text::kind_name(lang, row.kind),
                    row.amount
                )));
                items.push(Item::Help(
                    text::STATUS_LINE.fill(lang, [&row.status.text(lang), &row.nonce.to_string()]),
                ));
            }
        }
        self.received_items(crate::received::RecvChain::Hc, items);
        items.push(Item::CardEnd);
    }

    /// S-HC.
    #[expect(
        clippy::too_many_lines,
        reason = "one block per form kind of spec/11 §8"
    )]
    pub fn hc_screen(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let network = self.hc_network();
        let form = &self.hypercore.form;
        items.push(crate::ui::screens::back_main(lang));
        let title = match form.kind {
            HcFormKind::Send => text::TITLE_SEND,
            HcFormKind::ClassTransfer => text::TITLE_CLASS,
            HcFormKind::Withdraw => text::TITLE_WITHDRAW,
            HcFormKind::ToEvm => text::TITLE_TO_EVM,
        }
        .get(lang);
        items.push(Item::Badged(
            crate::ui::badge::Badge::hyperliquid(),
            Box::new(Item::Title(format!(
                "{title} — {}",
                yw_core::hypercore::text::network_label(lang, network)
            ))),
        ));
        network_band(lang, network, items);
        // A failed load is shown and can be retried here (the card is not on this screen).
        if let Some(error) = &self.hypercore.error {
            items.push(Item::Banner(error.clone(), Tone::Warn));
        }
        if self.hypercore.error.is_some() || self.hc_balances().is_none() {
            items.push(Item::Row(vec![Ctl::button(
                ids::REFRESH,
                text::REFRESH.get(lang),
            )]));
        }
        if let Some((account, source, label)) = self.selected_account() {
            items.push(Item::CardStart(Some(
                text::SIGNING_ACCOUNT.get(lang).to_owned(),
            )));
            items.push(Item::Text(label));
            items.push(Item::Mono(yw_core::evm::display::format_address(&account)));
            // U7: `검토` stays off while the phrase waits for its backup quiz, and while the
            // YubiKey is still on its factory PINs (spec/10 §9.3).
            self.mn_signing_banner(self.evm_backup_gate(source), items);
            self.card_pin_banner(self.evm_card_gate(source), items);
            items.push(Item::CardEnd);
        }
        items.push(Item::CardStart(Some(text::CONTENT.get(lang).to_owned())));
        match form.kind {
            HcFormKind::Send => {
                let mut rows = vec![Item::Row(vec![Ctl::radio(
                    ids::ASSET_PERP,
                    &text::ASSET_PERP.fill(
                        lang,
                        [&self
                            .hc_balances()
                            .map_or_else(|| "?".to_owned(), |b| b.perp.withdrawable.clone())],
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
                        &text::ASSET_SPOT.fill(lang, [&escape_untrusted(&coin).text, &total]),
                        form.asset == HcAsset::Spot(index),
                        false,
                    )]));
                }
                items.extend(rows);
                self.hc_recipient_rows(items, text::RECIPIENT_CORE.get(lang));
            }
            HcFormKind::ClassTransfer => {
                items.push(Item::Row(vec![
                    Ctl::radio(
                        ids::DIR_TO_PERP,
                        text::SPOT_TO_PERP.get(lang),
                        form.to_perp,
                        true,
                    ),
                    Ctl::radio(
                        ids::DIR_TO_SPOT,
                        text::PERP_TO_SPOT.get(lang),
                        !form.to_perp,
                        false,
                    ),
                ]));
                items.push(Item::Help(text::CLASS_HELP.get(lang).to_owned()));
            }
            HcFormKind::Withdraw => {
                self.hc_recipient_rows(items, text::RECIPIENT_ARBITRUM.get(lang));
                items.push(Item::Banner(
                    text::WITHDRAW_BANNER.fill(lang, [WITHDRAW_FEE_USDC]),
                    Tone::Info,
                ));
            }
            HcFormKind::ToEvm => {
                let tokens = self.hc_evm_tokens();
                if tokens.is_empty() {
                    items.push(Item::Muted(text::NO_EVM_TOKENS.get(lang).to_owned()));
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
                        &text::EVM_TOKEN.fill(
                            lang,
                            [
                                &escape_untrusted(&token.name).text,
                                &token.system_address().to_checksum(),
                            ],
                        ),
                        form.asset == HcAsset::Spot(token.index),
                        row == 0,
                    )]));
                }
                items.push(Item::Help(text::TO_EVM_HELP.get(lang).to_owned()));
            }
        }
        let available = self.hc_form_available();
        items.push(Item::LabeledRow(
            text::AMOUNT.get(lang).to_owned(),
            vec![
                Ctl::edit(ids::AMOUNT_EDIT, &form.amount_text, 240, false, 40),
                Ctl::button(ids::MAX, text::MAX.get(lang))
                    .enabled(available.as_ref().is_some_and(|(amount, _)| amount != "0")),
            ],
        ));
        match &available {
            Some((amount, symbol)) => items.push(Item::Help(
                match form.kind {
                    HcFormKind::ToEvm => text::AVAILABLE_TO_EVM,
                    HcFormKind::Withdraw => text::AVAILABLE_WITHDRAW,
                    _ => text::AVAILABLE,
                }
                .fill(lang, [amount, symbol]),
            )),
            None if self.hc_balances().is_none() => {
                items.push(Item::Help(text::AVAILABLE_LATER.get(lang).to_owned()));
            }
            None => {}
        }
        if let Some(error) = &form.error {
            // Loading is a status; anything else stops `검토`.
            let loading = crate::app_hypercore::text::LOADING;
            let tone = if *error == loading.ko || *error == loading.en {
                Tone::Info
            } else {
                Tone::Danger
            };
            items.push(Item::Banner(error.clone(), tone));
        }
        // What `검토` or the approval ended with (queue full, expired), also next to it.
        if let Some(info) = &form.info {
            items.push(Item::Banner(info.clone(), Tone::Warn));
        }
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::primary(ids::REVIEW, text::REVIEW.get(lang))
                .enabled(self.hc_can_review() && form.dirty_ms.is_none()),
            Ctl::button(ids::CANCEL, text::CANCEL.get(lang)),
        ]));
    }

    fn hc_recipient_rows(&self, items: &mut Vec<Item>, label: &str) {
        let lang = self.settings.language;
        let form = &self.hypercore.form;
        items.push(Item::LabeledRow(
            label.to_owned(),
            vec![Ctl::edit(ids::TO_EDIT, &form.to_text, 430, false, 64)],
        ));
        for note in &form.notes {
            // Withdrawing to the signing account's own Arbitrum address is the default.
            if form.kind == HcFormKind::Withdraw
                && *note == crate::flow::evm::form::AddressNote::SameAsSender
            {
                items.push(Item::Banner(
                    crate::app_hypercore::text::WITHDRAW_OWN
                        .get(lang)
                        .to_owned(),
                    Tone::Info,
                ));
                continue;
            }
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
        if form
            .notes
            .iter()
            .any(crate::flow::evm::form::AddressNote::needs_ack)
        {
            items.push(Item::Row(vec![Ctl::check(
                ids::ACK,
                text::ACK.get(lang),
                form.ack,
            )]));
        }
    }

    /// Settings → `EVM 체인`: the `HyperCore` block.
    pub fn hc_settings_section(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let hypercore = &self.settings.hypercore;
        items.push(Item::CardStart(Some("Hyperliquid HyperCore".to_owned())));
        items.push(Item::Row(vec![Ctl::check(
            ids::ENABLED,
            text::SETTINGS_SHOW.get(lang),
            hypercore.enabled,
        )]));
        items.push(network_row(lang, hypercore.network));
        items.push(Item::Field(
            text::MAINNET_API.get(lang).to_owned(),
            text::FIXED.fill(lang, [yw_core::hypercore::MAINNET_API]),
        ));
        let api = self
            .hypercore
            .api_text
            .clone()
            .unwrap_or_else(|| hypercore.testnet_api.clone());
        items.push(Item::LabeledRow(
            text::TESTNET_API.get(lang).to_owned(),
            vec![
                Ctl::edit(ids::API_EDIT, &api, 360, false, 256),
                Ctl::button(ids::API_SAVE, text::SAVE.get(lang)),
                Ctl::button(ids::API_DEFAULT, text::OFFICIAL.get(lang)),
            ],
        ));
        items.push(Item::Help(text::API_HELP.get(lang).to_owned()));
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
                if matches!(self.screen, crate::app::Screen::HyperCore) {
                    self.hc_validate();
                }
                self.refresh();
            }
            ids::MAX => self.hc_fill_max(),
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
            ids::ACK => self.hc_toggle_ack(),
            ids::REVIEW => self.hc_review(),
            ids::CANCEL => self.return_to(crate::app::Screen::Main),
            ids::EXPAND | ids::COLLAPSE => {
                self.hypercore.unfolded = id == ids::EXPAND;
                self.refresh();
            }
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
                        Some(text::API_SAVED.get(self.settings.language).to_owned());
                    self.save_settings(settings, "hypercore");
                } else {
                    self.hypercore.settings_message =
                        Some(text::API_INVALID.get(self.settings.language).to_owned());
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
