//! Bitcoin screen contents (M8; spec/04 §2.6–§2.8, §2.11, §2.16, §3.3; spec/08 §2, §3.2, §3.4,
//! §4.7, §7.3, §7.6, §8.2–§8.3, §9, §11.3, §12.1–§12.2): the S10 Bitcoin tab, the BTC send form
//! and its result, the fee-bump form, S12 receive and the S15 Bitcoin section. Every text is a
//! fixed sentence or built by yw-core / the controller ([`crate::wallet::app_btc`]); no
//! server string is shown. Addresses are shown in full in 4-character groups, the first and last
//! 6 characters bold (spec/04 §3.3); activity addresses have no copy or select buttons.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): moved here from yw-app `ui/screens_btc.rs` with the
//! bodies unchanged (`impl App` builders became `impl Screen<'_>`, yw-app paths engine paths); its
//! control ids stay there (`ui::screens_btc::ids`).

use yw_core::bip32::path::BtcChain;
use yw_core::btc::meta::FreezeReason;
use yw_core::btc::policy::texts;
use yw_core::btc::{BtcMeta, BtcNetwork, FeeRate, Sats, Txid, encode_address};
use yw_core::lang::{Lang, Text};

use super::Screen;
use crate::apikeys::KeyName;
use crate::badge::Badge;
use crate::btc::work::FeeQuote;
use crate::cmd::{
    BookPress, BtcActivityAction, BtcPress, CorePress, ExplorerPress, LinksPress, MnPress, Row,
};
use crate::errors::ErrorCode;
use crate::form::EditField;
use crate::meta::BookChain;
use crate::screen::Tone;
use crate::screen::model::{Ctl, Item};
use crate::screen::rows;
use crate::settings::BtcIndexer;
use crate::text::grouped;
use crate::wallet::app_book::{BookTarget, PromptPlace};
use crate::wallet::app_btc::{
    BtcCtx, BtcFeeChoice, BtcFeeForm, BtcFlowStage, BtcGate, BtcUi, DISCOVERY_INCOMPLETE,
    PENDING_INCOMING, PENDING_INCOMING_UNREAD, confirmations_text, record_status,
};
use crate::wallet::{AppMode, Wallet};

pub mod text;

pub use text::T_BTC_ESPLORA_NOTE;

/// The muted line under the balance with the received history's unconfirmed deposits
/// (2026-11-13; spec/04 §2.6, spec/08 §4.7-2). Shared with the Zcash card.
#[must_use]
pub fn pending_incoming_line(lang: Lang, amount: &str) -> String {
    text::PENDING_LINE.fill(lang, [amount])
}

/// The refresh's "미확정 입금 있음" banner (spec/08 §4.7-2, 2026-11-13): shown while the refresh
/// saw unconfirmed incoming funds (`flagged`, on the addresses `at`) unless the received history
/// is on and its last read (`covered`: the receive indices it answered completely) covered
/// every one of them — then the list has the deposit as a row (with the amount line) or as
/// counted dust. With the history off the banner points to the switch; on, it says the list has
/// not found it all. Before the 2026-11-13 review the list also had to have a pending row (any,
/// on any address), so a dust-only deposit kept the banner up while it sat in the mempool.
#[must_use]
pub fn pending_banner(
    flagged: bool,
    at: &[(BtcChain, u32)],
    history_on: bool,
    covered: Option<&[u32]>,
) -> Option<Text> {
    if !flagged {
        return None;
    }
    if !history_on {
        return Some(PENDING_INCOMING);
    }
    let covered = covered.is_some_and(|covered| {
        !at.is_empty()
            && at
                .iter()
                .all(|(chain, index)| *chain == BtcChain::Receive && covered.contains(index))
    });
    (!covered).then_some(PENDING_INCOMING_UNREAD)
}

/// The fee choices in radio order.
const FEE_CHOICES: [BtcFeeChoice; 4] = [
    BtcFeeChoice::Fast,
    BtcFeeChoice::Normal,
    BtcFeeChoice::Slow,
    BtcFeeChoice::Manual,
];

/// The settings name with its Korean particle (`mainnet으로`, `testnet4로`; English: the name).
fn with_particle(lang: Lang, net: BtcNetwork) -> String {
    match net {
        BtcNetwork::Mainnet => text::WITH_EURO.fill(lang, [net.settings_name()]),
        BtcNetwork::Testnet4 => text::WITH_RO.fill(lang, [net.settings_name()]),
    }
}

/// The two mismatch buttons in `lang` (spec/08 §2): [설정을 {`BtcMeta` 값}으로 되돌리기] /
/// [{settings 값}으로 바꾸기].
#[must_use]
pub fn mismatch_labels(lang: Lang, meta: BtcNetwork, settings: BtcNetwork) -> (String, String) {
    (
        text::MISMATCH_KEEP.fill(lang, [&with_particle(lang, meta)]),
        text::MISMATCH_USE.fill(lang, [&with_particle(lang, settings)]),
    )
}

/// The network banner tone (spec/08 §2: mainnet red, testnet4 orange).
#[must_use]
pub const fn network_tone(net: BtcNetwork) -> Tone {
    match net {
        BtcNetwork::Mainnet => Tone::BtcMainnet,
        BtcNetwork::Testnet4 => Tone::BtcTestnet4,
    }
}

/// The network banner (spec/08 §2). Testnet4 shows only `BITCOIN TESTNET4 — 가치 없음` (it already
/// says the coins have no value; a second generic testnet band under it was noise).
fn network_banners(lang: Lang, net: BtcNetwork, items: &mut Vec<Item>) {
    items.push(Item::Banner(
        net.banner_in(lang).to_owned(),
        network_tone(net),
    ));
}

/// `YYYY-MM-DD HH:MM` in local time (spec/04 §2.6); UTC with a suffix if the conversion fails.
fn local_time(facts: &dyn crate::screen::facts::ScreenFacts, unix_ms: u64) -> String {
    let wall = facts.local_wall_ms(unix_ms);
    let text = crate::logging::format_utc(wall.unwrap_or(unix_ms));
    let short = text.get(..16).unwrap_or(&text).replace('T', " ");
    if wall.is_some() {
        short
    } else {
        format!("{short} UTC")
    }
}

/// The rate a fee choice would use with `quote` (the floor when the estimate is below it, like
/// `choose_fee_rate`); `None` for no estimate, no preview or `직접 입력`.
/// The fee radios' presses of the send form (`bump = false`) or the fee-bump form, in
/// [`FEE_CHOICES`] order (2026-11-24 S5-4: the screens drew the ids of `ids::fee_ids`).
#[must_use]
pub const fn fee_presses(bump: bool) -> [BtcPress; 4] {
    if bump {
        [
            BtcPress::BumpFee(BtcFeeChoice::Fast),
            BtcPress::BumpFee(BtcFeeChoice::Normal),
            BtcPress::BumpFee(BtcFeeChoice::Slow),
            BtcPress::BumpFee(BtcFeeChoice::Manual),
        ]
    } else {
        [
            BtcPress::Fee(BtcFeeChoice::Fast),
            BtcPress::Fee(BtcFeeChoice::Normal),
            BtcPress::Fee(BtcFeeChoice::Slow),
            BtcPress::Fee(BtcFeeChoice::Manual),
        ]
    }
}

/// `(edit, 저장, 기본값으로, 테스트)` of a network's Esplora URL row (2026-11-24 S5-4: the
/// screens drew the ids of `ids::esplora_ids`).
#[must_use]
pub const fn esplora_controls(net: BtcNetwork) -> (EditField, BtcPress, BtcPress, BtcPress) {
    let edit = match net {
        BtcNetwork::Mainnet => EditField::BtcEsploraMainnet,
        BtcNetwork::Testnet4 => EditField::BtcEsploraTestnet4,
    };
    (
        edit,
        BtcPress::EsploraSave(net),
        BtcPress::EsploraDefault(net),
        BtcPress::EsploraTest(net),
    )
}

fn quoted_rate(choice: BtcFeeChoice, quote: Option<&FeeQuote>) -> Option<FeeRate> {
    let quote = quote?;
    let slot = match choice {
        BtcFeeChoice::Fast => 0,
        BtcFeeChoice::Normal => 1,
        BtcFeeChoice::Slow => 2,
        BtcFeeChoice::Manual => return None,
    };
    quote
        .rates
        .get(slot)
        .copied()
        .flatten()
        .map(|rate| rate.max(quote.floor))
}

/// A send-form fee radio (2026-11-10): "빠름 · 약 20분 · 12 sat/vB" — the usual wait of 2·6·24
/// blocks — with "· 추정 없음" when the node gave none, the name and wait alone before the preview.
fn fee_choice_label(lang: Lang, choice: BtcFeeChoice, quote: Option<&FeeQuote>) -> String {
    let wait = match choice {
        BtcFeeChoice::Fast => text::WAIT_FAST,
        BtcFeeChoice::Normal => text::WAIT_NORMAL,
        BtcFeeChoice::Slow => text::WAIT_SLOW,
        BtcFeeChoice::Manual => return choice.label(lang).to_owned(),
    }
    .get(lang);
    let label = choice.label(lang);
    match (quote, quoted_rate(choice, quote)) {
        (Some(_), Some(rate)) => format!("{label} · {wait} · {rate}"),
        (Some(_), None) => format!("{label} · {wait} · {}", text::NO_ESTIMATE.get(lang)),
        (None, _) => format!("{label} · {wait}"),
    }
}

/// The plain name of a recipient's address type before its technical name (2026-11-10:
/// "네이티브 세그윗 (P2WPKH)"; the approval window keeps `ScriptKind::type_label`).
const fn kind_text(lang: Lang, kind: &yw_core::btc::ScriptKind) -> &'static str {
    match kind {
        yw_core::btc::ScriptKind::P2pkh(_) => text::KIND_P2PKH,
        yw_core::btc::ScriptKind::P2sh(_) => text::KIND_P2SH,
        yw_core::btc::ScriptKind::P2wpkh(_) => text::KIND_P2WPKH,
        yw_core::btc::ScriptKind::P2wsh(_) => text::KIND_P2WSH,
        yw_core::btc::ScriptKind::P2tr(_) => text::KIND_P2TR,
    }
    .get(lang)
}

/// `X sat/vB` of a recorded fee and vsize (rounded up like spec/08 §8.3 `rate_kvb`).
fn record_rate(fee: Sats, vsize: u32) -> String {
    let kvb = fee
        .get()
        .saturating_mul(1_000)
        .div_ceil(u64::from(vsize.max(1)));
    FeeRate::from_sat_per_kvb(kvb).to_string()
}

/// The selected account's node and type line: `m/86'/0'/0' · 탭루트 (bc1p…)`, or for an
/// imported key `가져온 키 · 레거시 (1…)`.
fn active_detail(ctx: &BtcCtx<'_>) -> String {
    let net = ctx.net();
    ctx.btc_meta().map_or_else(String::new, |meta| {
        format!(
            "{} · {}",
            meta.account().node_text_in(ctx.lang, net),
            crate::wallet::app_btc::account_type_text(ctx.lang, meta.account(), net)
        )
    })
}

fn flow_stage_text(lang: Lang, stage: BtcFlowStage) -> Option<&'static str> {
    match stage {
        BtcFlowStage::Prechecking => Some(text::STAGE_PRECHECK.get(lang)),
        BtcFlowStage::Applying => Some(text::STAGE_APPLYING.get(lang)),
        BtcFlowStage::Sending => Some(text::STAGE_SENDING.get(lang)),
        BtcFlowStage::Waiting | BtcFlowStage::Done => None,
    }
}

impl Screen<'_> {
    /// The selected account's name (meta `btc_account_view`, default `Bitcoin N`; 2026-11-15:
    /// its type and number `네이티브 세그윗 계정 0` before), `Bitcoin 계정` before BTC has one.
    /// Its node and type are the line under it (`active_detail`).
    fn btc_active_label(&self, ctx: &BtcCtx<'_>) -> String {
        ctx.btc_meta().map_or_else(
            || text::ACCOUNT_FALLBACK.get(ctx.lang).to_owned(),
            |meta| self.btc_label_of(meta),
        )
    }

    fn btc_tip(&self, ctx: &BtcCtx<'_>) -> u32 {
        self.btc
            .tip
            .or_else(|| ctx.btc_meta().map(BtcMeta::max_tip_seen))
            .unwrap_or(0)
    }

    fn btc_unlocked(&self) -> bool {
        matches!(self.mode, AppMode::Unlocked { .. })
    }

    /// The gate reason of the tab (disabled is handled by the caller).
    fn btc_gate_items(lang: Lang, gate: BtcGate, items: &mut Vec<Item>) {
        match gate {
            // NoAccount: the account card says it, next to `개인키 가져오기`.
            BtcGate::Disabled | BtcGate::NoAccount => {}
            BtcGate::Locked | BtcGate::NoMeta | BtcGate::JournalLoading => {
                items.push(Item::Muted(gate.text(lang)));
            }
            BtcGate::JournalClosed => items.push(Item::Banner(gate.text(lang), Tone::Blocked)),
            BtcGate::Mismatch { meta, settings } => {
                items.push(Item::Banner(gate.text(lang), Tone::Danger));
                Self::btc_mismatch_row(lang, meta, settings, items);
            }
            BtcGate::NoEndpoint => {
                items.push(Item::Banner(gate.text(lang), Tone::Danger));
                // That network's row with its field open (2026-11-10).
                items.push(Item::Row(vec![Ctl::button(
                    CorePress::BtcRpcOpen,
                    text::RPC_SETUP.get(lang),
                )]));
            }
        }
    }

    fn btc_mismatch_row(lang: Lang, meta: BtcNetwork, settings: BtcNetwork, items: &mut Vec<Item>) {
        let (keep, change) = mismatch_labels(lang, meta, settings);
        items.push(Item::Row(vec![
            Ctl::button(BtcPress::MismatchKeepMeta, &keep),
            Ctl::button(BtcPress::MismatchUseSettings, &change),
        ]));
    }

    /// The S10 status line of the Bitcoin tab (network id and indexer name only, spec/04 §1.9).
    fn btc_status_line(&self, ctx: &BtcCtx<'_>) -> String {
        let net = ctx.net();
        let lang = ctx.lang;
        let rpc = if ctx.core_url(net).is_none() {
            text::STATUS_NO_RPC.get(lang).to_owned()
        } else if self.btc.blocked.is_some() {
            text::STATUS_BLOCKED.get(lang).to_owned()
        } else if let Some(tip) = self.btc.tip {
            text::STATUS_CONNECTED.fill(lang, [&tip.to_string()])
        } else {
            text::STATUS_UNCHECKED.get(lang).to_owned()
        };
        let indexer = crate::btc::indexer_display(ctx.settings.indexer);
        let checked = if self.btc.indexer_verified {
            text::STATUS_GENESIS_OK
        } else {
            text::STATUS_UNCHECKED
        };
        text::STATUS_LINE.fill(
            lang,
            [
                &crate::btc::network_id(net).to_string(),
                &rpc,
                indexer,
                checked.get(lang),
            ],
        )
    }

    fn btc_discovery_items(&self, ctx: &BtcCtx<'_>, items: &mut Vec<Item>) {
        let discovery = &self.btc.discovery;
        let lang = ctx.lang;
        if discovery.running {
            let doing = if discovery.more {
                text::DISCOVERY_MORE
            } else {
                text::DISCOVERY_RUNNING
            };
            items.push(Item::Muted(
                text::DISCOVERY_PROGRESS
                    .fill(lang, [doing.get(lang), &discovery.checked.to_string()]),
            ));
            items.push(Item::Row(vec![Ctl::button(
                BtcPress::DiscoverCancel,
                text::CANCEL.get(lang),
            )]));
            return;
        }
        let incomplete = ctx.btc_meta().is_some_and(|meta| !meta.discovery_done());
        if discovery.error.is_some() || incomplete {
            let text = discovery
                .error
                .clone()
                .unwrap_or_else(|| DISCOVERY_INCOMPLETE.get(lang).to_owned());
            items.push(Item::Banner(text, Tone::Warn));
            items.push(Item::Row(vec![
                Ctl::button(BtcPress::DiscoverRetry, text::RETRY.get(lang))
                    .enabled(ctx.gate().is_ok()),
            ]));
        }
    }

    /// `새로고침` and, for an HD account after discovery, `더 찾기`.
    /// The network card's `더 찾기` (`새로고침` is on the account card since 2026-11-11, like
    /// the other tabs).
    fn btc_discover_row(&self, ctx: &BtcCtx<'_>, usable: bool, items: &mut Vec<Item>) {
        let discovery_done = ctx.btc_meta().is_some_and(BtcMeta::discovery_done);
        let single = ctx.btc_meta().is_some_and(BtcMeta::is_single);
        if discovery_done && !single && !self.btc.discovery.running {
            items.push(Item::Row(vec![
                Ctl::button(BtcPress::DiscoverMore, text::FIND_MORE.get(ctx.lang)).enabled(usable),
            ]));
        }
    }

    /// The account card `내 Bitcoin 계정` (2026-11-15, the shared card of
    /// `screen::build::accounts` like the EVM and Solana tabs): the shared help, the drop-down of the
    /// visible accounts (items `label · source`: recovery words, `가져온 키`, `EVM 계정 {i} 키`,
    /// `YubiKey: {cards}`), the selected account's `이름 바꾸기`·`숨기기` and key buttons, its
    /// address mode and key reminder, the hidden accounts, then `계정 추가` (wallets with recovery
    /// words), `개인키 가져오기` and the recovery-words link, and the choosers they open.
    ///
    /// Before 2026-11-15 an untitled card with the subtitle `Bitcoin 계정` whose items read
    /// `{type} 계정 {n} · {badge} · {type (prefix)} · {balance}`; the selected account's whole
    /// address, type and balance are the card above (`btc_selected_card`).
    #[expect(clippy::too_many_lines, reason = "one block per part of the card")]
    fn btc_account_items(&self, ctx: &BtcCtx<'_>, items: &mut Vec<Item>) {
        use crate::screen::build::accounts::{AccountCard, AccountItem, SelectedLine};
        let net = ctx.net();
        let lang = ctx.lang;
        let usable = ctx.gate().is_ok() && !self.btc.slot;
        let rows = self.btc_visible_rows();
        let empty = if ctx
            .meta
            .is_none_or(|meta| meta.btc_accounts.accounts.is_empty())
        {
            crate::screen::build::keys::no_accounts_text(
                self.settings.language,
                yw_core::keyimport::ImportChain::Btc,
            )
        } else {
            BtcGate::NoAccount.text(lang)
        };
        let mut accounts = Vec::new();
        let mut chosen = None;
        for (index, row) in rows
            .iter()
            .take(usize::from(rows::BTC_ACCOUNTS))
            .enumerate()
        {
            let account = ctx.accounts().into_iter().find(|meta| meta.id() == row.id);
            let source = account.map_or(crate::screen::AccountSource::Card(None), |meta| {
                Wallet::btc_source(meta.account(), net)
            });
            if row.selected {
                chosen = Some((row.id, row.name.clone()));
            }
            accounts.push(AccountItem {
                press: BtcPress::Account(Row(u16::try_from(index).unwrap_or(0))).into(),
                label: row.name.clone(),
                source,
                selected: row.selected,
                enabled: usable,
            });
        }
        let selected = chosen.map(|(id, label)| {
            if self.btc.rename == Some(id) {
                return SelectedLine::Rename {
                    edit: EditField::BtcRename,
                    save: BtcPress::RenameSave.into(),
                    cancel: BtcPress::RenameCancel.into(),
                    label,
                };
            }
            let mut buttons = vec![Ctl::button(BtcPress::Rename, text::RENAME.get(lang)).compact()];
            // Not the default account, not an imported key (it has `삭제`), not the last one
            // shown (2026-11-15, as EVM and Solana).
            if self.btc_can_hide(id) {
                buttons.push(Ctl::button(BtcPress::Hide, text::HIDE.get(lang)).compact());
            }
            buttons.extend(self.btc_key_parts(ctx).0);
            SelectedLine::Buttons(buttons)
        });
        let mut details = Vec::new();
        if let Some(message) = &self.btc.account_message {
            details.push(Item::Banner(message.clone(), Tone::Warn));
        }
        if selected.is_some() {
            self.btc_address_mode_items(ctx, usable, &mut details);
            details.extend(self.btc_key_parts(ctx).1);
        }
        let mut actions = Vec::new();
        let mut footer = Vec::new();
        if ctx.has_mnemonic {
            if self.btc.add_account_open {
                footer.push(Item::Help(text::ADD_ACCOUNT_HELP.get(lang).to_owned()));
                self.btc_add_source_items(ctx, usable, &mut footer);
                for script_type in &yw_core::btc::ScriptType::CHOICES {
                    footer.push(Item::Row(vec![
                        Ctl::button(
                            BtcPress::AccountAddType(*script_type),
                            &script_type.label_in(lang, net),
                        )
                        .enabled(usable),
                    ]));
                }
                footer.push(Item::Row(vec![Ctl::button(
                    BtcPress::AccountAddCancel,
                    text::CANCEL.get(lang),
                )]));
            } else {
                actions.push(
                    Ctl::button(BtcPress::AccountAdd, text::ADD_ACCOUNT.get(lang))
                        .compact()
                        .enabled(usable),
                );
            }
        }
        actions.extend(self.btc_import_action());
        if ctx.has_mnemonic {
            actions.push(self.mnemonics_link());
        }
        self.btc_import_items(&mut footer);
        if ctx.has_mnemonic {
            // The Bitcoin-specific hint (the address format of an account never changes).
            footer.push(Item::Help(text::ACCOUNTS_HELP.get(lang).to_owned()));
        }
        self.push_account_card(
            items,
            AccountCard {
                title: text::MY_ACCOUNTS.get(lang).to_owned(),
                picker: LinksPress::PickerBtc.into(),
                accounts,
                empty: Some(empty),
                locked: None,
                selected,
                details,
                hidden: Some(crate::wallet::app_hidden::Family::Btc),
                actions,
                footer,
            },
        );
    }

    /// The selected HD account's address mode (spec/08 §3.5): `고정 주소 하나만 사용` (default) /
    /// `받을 때마다 새 주소` with the one-line trade-off. One-key accounts have one address only.
    /// The line names the account by its name (2026-11-15; its type and number before).
    fn btc_address_mode_items(&self, ctx: &BtcCtx<'_>, usable: bool, items: &mut Vec<Item>) {
        let Some(meta) = ctx.btc_meta().filter(|meta| meta.account().is_hd()) else {
            return;
        };
        let fixed = meta.fixed_address();
        let lang = ctx.lang;
        items.push(Item::Text(
            text::ADDRESS_MODE.fill(lang, [&self.btc_label_of(meta)]),
        ));
        items.push(Item::Row(vec![
            Ctl::radio(
                BtcPress::AddressModeSingle,
                crate::wallet::app_btc::T_BTC_MODE_SINGLE.get(lang),
                fixed,
                true,
            )
            .enabled(usable),
        ]));
        items.push(Item::Row(vec![
            Ctl::radio(
                BtcPress::AddressModeHd,
                crate::wallet::app_btc::T_BTC_MODE_HD.get(lang),
                !fixed,
                false,
            )
            .enabled(usable),
        ]));
        items.push(Item::Help(
            crate::wallet::app_btc::T_BTC_MODE_HELP.get(lang).to_owned(),
        ));
    }

    /// The add-account key source (spec/08 §3.5): the standard BTC path (default) or the key of
    /// an EVM account (warning and the EVM account radios; adding asks for confirmation).
    fn btc_add_source_items(&self, ctx: &BtcCtx<'_>, usable: bool, items: &mut Vec<Item>) {
        let evm = self.btc.add_source == crate::wallet::app_btc::BtcAddSource::EvmShared;
        let lang = ctx.lang;
        if self.several_mnemonics() {
            // Which recovery phrase the standard-path account comes from (spec/02 §8.6).
            items.push(Item::Text(text::MNEMONIC.get(lang).to_owned()));
            for (row, info) in self.mn.infos.iter().enumerate() {
                let chosen = if info.primary {
                    self.btc.add_mnemonic.is_none()
                } else {
                    self.btc.add_mnemonic == Some(info.id)
                };
                let press = MnPress::BtcPick(Row(u16::try_from(row).unwrap_or(0)));
                items.push(Item::Row(vec![
                    Ctl::radio(press, &self.mnemonic_label(info.id), chosen, row == 0)
                        .enabled(usable),
                ]));
            }
            if self.btc.add_mnemonic.is_some() {
                items.push(Item::Help(text::ADDED_MNEMONIC_HELP.get(lang).to_owned()));
                return;
            }
        }
        items.push(Item::Text(text::KEY_SOURCE.get(lang).to_owned()));
        items.push(Item::Row(vec![
            Ctl::radio(
                BtcPress::AccountSourceStandard,
                crate::wallet::app_btc::T_BTC_SOURCE_STANDARD.get(lang),
                !evm,
                true,
            )
            .enabled(usable),
        ]));
        items.push(Item::Help(
            crate::wallet::app_btc::T_BTC_SOURCE_STANDARD_HELP
                .get(lang)
                .to_owned(),
        ));
        items.push(Item::Row(vec![
            Ctl::radio(
                BtcPress::AccountSourceEvm,
                crate::wallet::app_btc::T_BTC_SOURCE_EVM.get(lang),
                evm,
                false,
            )
            .enabled(usable),
        ]));
        if !evm {
            return;
        }
        items.push(Item::Banner(
            crate::wallet::app_btc::T_BTC_EVM_SHARED
                .get(lang)
                .to_owned(),
            Tone::Warn,
        ));
        let accounts = ctx.evm_accounts();
        if accounts.is_empty() {
            items.push(Item::Muted(text::NO_EVM_ACCOUNTS.get(lang).to_owned()));
        }
        for (row, (index, label, address)) in accounts
            .iter()
            .take(usize::from(rows::BTC_EVM_ACCOUNTS))
            .enumerate()
        {
            let press = BtcPress::EvmAccount(Row(u16::try_from(row).unwrap_or(0)));
            let text = format!(
                "{label} · {} · m/44'/60'/0'/0/{index}",
                crate::wallet::app_btc::short_address(address)
            );
            items.push(Item::Row(vec![
                Ctl::radio(press, &text, self.btc.add_evm_index == *index, row == 0)
                    .enabled(usable),
            ]));
        }
        items.push(Item::Help(text::EVM_PICK_HELP.get(lang).to_owned()));
    }

    fn btc_balance_items(&self, ctx: &BtcCtx<'_>, items: &mut Vec<Item>) {
        let lang = ctx.lang;
        items.push(Item::Subtitle(self.btc_active_label(ctx)));
        items.push(Item::Help(active_detail(ctx)));
        // U7, as on the EVM and Solana tabs: the account's phrase waits for its backup quiz;
        // a YubiKey on its factory PINs likewise (spec/10 §9.3).
        self.mn_signing_banner(self.btc_backup_gate(), items);
        self.card_pin_banner(self.btc_selected_card_gate(), items);
        if let Some(balance) = self.btc.balance(ctx) {
            items.push(Item::Display(BtcUi::amount_text(balance.available)));
            // One status line, like the other tabs (the UTXO explanation is the UTXO card's,
            // 2026-11-11).
            items.push(Item::Help(text::AVAILABLE_NOTE.get(lang).to_owned()));
            if balance.frozen.get() > 0 {
                items.push(Item::Muted(
                    text::FROZEN.fill(lang, [&BtcUi::amount_text(balance.frozen)]),
                ));
            }
            if balance.pending.get() > 0 {
                items.push(Item::Muted(
                    text::PENDING_BALANCE.fill(lang, [&BtcUi::amount_text(balance.pending)]),
                ));
            }
        } else {
            items.push(Item::Display(text::BALANCE_DASH.get(lang).to_owned()));
            items.push(Item::Help(text::BALANCE_UNKNOWN.get(lang).to_owned()));
        }
        // 2026-11-13: the received history's unconfirmed deposits as an amount (display only,
        // never in the balance above); the refresh's yes/no banner stays while that list does
        // not account for every address the refresh flagged.
        let list = self.received_list(crate::received::RecvChain::Btc);
        let pending_sum = list.and_then(crate::wallet::app_received::RecvList::pending_sum);
        if let Some(sats) = pending_sum {
            items.push(Item::Muted(pending_incoming_line(
                lang,
                &BtcUi::amount_text(Sats::new(sats).unwrap_or(Sats::ZERO)),
            )));
        }
        if let Some(text) = pending_banner(
            self.btc.pending_incoming,
            &self.btc.pending_incoming_at,
            self.settings.received_history,
            list.map(|list| list.covered.as_slice()),
        ) {
            items.push(Item::Banner(text.get(lang).to_owned(), Tone::Warn));
        }
        if self.btc.verify_failures > 0 {
            items.push(Item::Banner(
                text::VERIFY_FAILURES.fill(lang, [&self.btc.verify_failures.to_string()]),
                Tone::Warn,
            ));
        }
        if self.btc.skipped_addresses > 0 {
            items.push(Item::Banner(
                text::SKIPPED_ADDRESSES.fill(lang, [&self.btc.skipped_addresses.to_string()]),
                Tone::Warn,
            ));
        }
        if !self.btc.hint_mismatch.is_empty() {
            items.push(Item::Banner(
                text::HINT_MISMATCH.fill(lang, [&self.btc.hint_mismatch.len().to_string()]),
                Tone::Warn,
            ));
        }
        if self.btc.auto_frozen > 0 {
            items.push(Item::Banner(
                text::AUTO_FROZEN.fill(lang, [&self.btc.auto_frozen.to_string()]),
                Tone::Info,
            ));
        }
    }

    fn btc_utxo_items(&self, ctx: &BtcCtx<'_>, items: &mut Vec<Item>) {
        let lang = ctx.lang;
        items.push(Item::Subtitle(text::UTXO_TITLE.get(lang).to_owned()));
        items.push(Item::Help(text::UTXO_HELP.get(lang).to_owned()));
        let utxos = self.btc.utxos(ctx);
        if utxos.is_empty() {
            items.push(Item::Help(text::NO_UTXOS.get(lang).to_owned()));
        }
        let can_freeze = self.btc_unlocked() && ctx.mismatch().is_none();
        for (row, utxo) in utxos.iter().take(usize::from(rows::BTC_UTXOS)).enumerate() {
            let mut line = format!(
                "{} · {}",
                BtcUi::amount_text(utxo.value),
                confirmations_text(lang, utxo.confirmations)
            );
            let mut mark = |text: Text| {
                line.push_str(" · ");
                line.push_str(text.get(lang));
            };
            match utxo.frozen {
                Some(FreezeReason::User) => mark(text::UTXO_FROZEN),
                Some(FreezeReason::Auto) => mark(text::UTXO_AUTO_FROZEN),
                None => {}
            }
            if utxo.in_flight {
                mark(text::UTXO_IN_FLIGHT);
            }
            if utxo.own {
                mark(text::UTXO_OWN);
            }
            if utxo.hint_mismatch {
                mark(text::UTXO_HINT);
            }
            if utxo.indexer_only {
                mark(crate::wallet::app_btc::INDEXER_ONLY);
            }
            items.push(Item::Text(line));
            items.push(Item::Mono(utxo.outpoint.to_string()));
            let press = BtcPress::Utxo(Row(u16::try_from(row).unwrap_or(0)));
            let label = if utxo.frozen.is_some() {
                text::UNFREEZE
            } else {
                text::FREEZE
            }
            .get(lang);
            items.push(Item::Row(vec![
                Ctl::button(press, label).enabled(can_freeze && !utxo.in_flight),
            ]));
        }
        let hidden = utxos.len().saturating_sub(usize::from(rows::BTC_UTXOS));
        if hidden > 0 {
            items.push(Item::Muted(
                text::UTXO_HIDDEN.fill(lang, [&hidden.to_string(), &rows::BTC_UTXOS.to_string()]),
            ));
        }
    }

    #[expect(clippy::too_many_lines, reason = "one block per activity button")]
    fn btc_activity_items(&self, ctx: &BtcCtx<'_>, items: &mut Vec<Item>) {
        let lang = ctx.lang;
        items.push(Item::Badged(
            Badge::bitcoin(ctx.net()),
            Box::new(Item::Subtitle(text::ACTIVITY_TITLE.get(lang).to_owned())),
        ));
        let mut prompt_drawn = false;
        let rows = self.btc.activity_rows(ctx);
        if rows.is_empty() {
            items.push(Item::Help(text::NO_ACTIVITY.get(lang).to_owned()));
        }
        let usable = ctx.gate().is_ok();
        let unlocked = self.btc_unlocked();
        // Display-only names of the recipients (2026-11-10, like EVM's U11): an address-book
        // entry or one of the wallet's own accounts; earlier recipients are not named.
        let known = if rows.iter().any(|row| !row.counterparty.is_empty()) {
            crate::wallet::app_btc::known_addresses_on(ctx, ctx.net())
        } else {
            Vec::new()
        };
        for (index, row) in rows.iter().enumerate() {
            let act = |action| BtcPress::Activity(Row(u16::try_from(index).unwrap_or(0)), action);
            // The status at the end of the first line (2026-11-12: a line of its own before).
            items.push(Item::Text(format!(
                "{} · {} · {} · {}",
                local_time(&self.facts(), row.time_unix_ms),
                self.btc_active_label(ctx),
                row.title,
                row.status
            )));
            let lower = row.counterparty.to_ascii_lowercase();
            let name = known
                .iter()
                .filter(|entry| entry.address == lower)
                .find_map(|entry| match &entry.source {
                    crate::wallet::app_btc::BtcKnownSource::Book { label, .. } => {
                        Some(format!(" {}", text::TO_BOOK.fill(lang, [label])))
                    }
                    crate::wallet::app_btc::BtcKnownSource::Own { account } => {
                        Some(format!(" {}", text::TO_OWN.fill(lang, [account])))
                    }
                    crate::wallet::app_btc::BtcKnownSource::Sent => None,
                })
                .unwrap_or_default();
            if let Some(amount) = row.amount {
                items.push(Item::Muted(
                    text::ROW_AMOUNT_TO.fill(lang, [&BtcUi::amount_text(amount), &name]),
                ));
            } else if !row.counterparty.is_empty() {
                items.push(Item::Muted(text::ROW_TO.fill(lang, [&name])));
            }
            // 2026-11-11: the recipient whole (ends emphasized) and the txid on lines of their
            // own; a click copies either (the wallet's own signed journal — the received
            // history's senders never are), the explorer and address-book actions are icons at
            // the right end of their line.
            if !row.counterparty.is_empty() {
                let save = self.offer_save(BookChain::Btc, &row.counterparty).then(|| {
                    crate::screen::build::links::save_icon(
                        self.settings.language,
                        act(BtcActivityAction::SaveAddress),
                    )
                });
                crate::screen::build::links::push_address_line(
                    items,
                    self.settings.language,
                    rows::row(index, rows::BTC_TO).map(|row| LinksPress::BtcTo(row).into()),
                    &row.counterparty,
                    crate::screen::address::AddressKind::Bitcoin,
                    save.into_iter().collect(),
                );
            }
            crate::screen::build::links::push_hash_line(
                items,
                self.settings.language,
                Some(act(BtcActivityAction::CopyHash).into()),
                &row.txid,
                self.explorer_tx_icons(
                    crate::network::NetworkId::Bitcoin(self.settings.bitcoin.network),
                    &row.txid,
                    crate::screen::build::explorer::activity_links(
                        ExplorerPress::BtcActivity,
                        index,
                        rows::BTC_ACTIVITY_LINKS,
                    ),
                ),
            );
            let flow = Txid::from_display_hex(&row.txid)
                .ok()
                .and_then(|txid| self.btc.flow(&txid));
            if let Some(stage) = flow.and_then(|flow| flow_stage_text(lang, flow.stage)) {
                items.push(Item::Muted(stage.to_owned()));
            }
            if let Some(note) = &row.note {
                let waiting = flow.is_some_and(|flow| flow.stage == BtcFlowStage::Waiting);
                items.push(Item::Banner(
                    note.clone(),
                    if waiting { Tone::Warn } else { Tone::Info },
                ));
            }
            let mut buttons = Vec::new();
            if row.can_bump {
                buttons.push(
                    Ctl::button(act(BtcActivityAction::Bump), text::BUMP_FEE.get(lang))
                        .enabled(usable),
                );
            }
            if row.can_rebroadcast {
                buttons.push(
                    Ctl::button(
                        act(BtcActivityAction::Rebroadcast),
                        text::REBROADCAST.get(lang),
                    )
                    .enabled(usable),
                );
            }
            if row.can_abandon {
                buttons.push(
                    Ctl::button(act(BtcActivityAction::Abandon), text::ABANDON.get(lang))
                        .enabled(unlocked),
                );
            }
            if row.can_esplora {
                buttons.push(
                    Ctl::button(
                        act(BtcActivityAction::Esplora),
                        text::ESPLORA_SEND.get(lang),
                    )
                    .enabled(usable),
                );
            }
            if row.can_continue {
                let retry = flow.is_some_and(|flow| flow.retry_precheck);
                buttons.push(
                    Ctl::button(
                        act(BtcActivityAction::Continue),
                        if retry {
                            text::RETRY
                        } else {
                            text::CONTINUE_SEND
                        }
                        .get(lang),
                    )
                    .enabled(usable),
                );
                buttons.push(
                    Ctl::button(act(BtcActivityAction::Cancel), text::CANCEL.get(lang))
                        .enabled(unlocked),
                );
            }
            if !buttons.is_empty() {
                items.push(Item::Row(buttons));
            }
            if !prompt_drawn && !row.counterparty.is_empty() {
                prompt_drawn = self.prompt_items(
                    PromptPlace::Activity,
                    BookChain::Btc,
                    &row.counterparty,
                    items,
                );
            }
            items.push(Item::Gap(4));
        }
    }

    /// The tab while Bitcoin is off (`설정 → Bitcoin`; a key-only wallet without a Bitcoin key
    /// may import one now).
    fn btc_disabled_items(&self, ctx: &BtcCtx<'_>, items: &mut Vec<Item>) {
        let lang = ctx.lang;
        items.push(Item::CardStart(Some("Bitcoin".to_owned())));
        items.push(Item::Text(BtcGate::Disabled.text(lang)));
        items.push(Item::Help(
            if ctx.has_mnemonic {
                text::DISABLED_HELP_MNEMONIC
            } else {
                text::DISABLED_HELP_KEYS
            }
            .get(lang)
            .to_owned(),
        ));
        items.push(Item::Row(vec![Ctl::primary(
            BtcPress::SectionBtc,
            text::BTC_SETTINGS.get(lang),
        )]));
        items.push(Item::CardEnd);
        if !ctx.has_mnemonic
            && ctx
                .meta
                .is_some_and(|meta| meta.btc_accounts.accounts.is_empty())
        {
            // A key-only wallet without a Bitcoin key: it can be imported now (the account
            // waits for Bitcoin to be turned on).
            self.no_accounts_card(yw_core::keyimport::ImportChain::Btc, items);
        }
    }

    /// The S10 Bitcoin tab.
    pub fn btc_main_screen(&self, items: &mut Vec<Item>) {
        let ctx = self.btc_ctx();
        let net = ctx.net();
        let lang = ctx.lang;
        if !ctx.settings.enabled {
            self.btc_disabled_items(&ctx, items);
            return;
        }
        items.push(Item::CardStart(None));
        // The network as a small tag on a `네트워크` line like the other tabs (2026-11-11; the
        // send, receive and result screens keep the full band of spec/08 §2).
        items.push(Item::LabeledRow(
            text::NETWORK.get(lang).to_owned(),
            Vec::new(),
        ));
        items.push(Item::Pill(
            net.banner_in(lang).to_owned(),
            network_tone(net),
        ));
        let gate = ctx.gate();
        if let Err(reason) = gate {
            Self::btc_gate_items(lang, reason, items);
        }
        let mismatch = matches!(gate, Err(BtcGate::Mismatch { .. }));
        if ctx.journal_damaged() {
            items.push(Item::Banner(
                text::JOURNAL_DAMAGED.get(lang).to_owned(),
                Tone::Blocked,
            ));
        }
        if let Some(text) = self.btc.blocked.as_ref().filter(|_| !mismatch) {
            items.push(Item::Banner(text.clone(), Tone::Blocked));
            if self.btc.tip_regressed {
                items.push(Item::Help(text::TIP_REGRESSED_HELP.get(lang).to_owned()));
                items.push(Item::Row(vec![
                    Ctl::button(BtcPress::ResetTip, text::RESET_TIP.get(lang))
                        .enabled(self.btc_unlocked()),
                ]));
            }
        }
        if let Some(lag) = self.btc.lag_warning {
            items.push(Item::Banner(
                crate::btc::chain::lag_warning_text(lang, lag),
                Tone::Warn,
            ));
        }
        if let Some(text) = &self.btc.status_error {
            items.push(Item::Banner(text.clone(), Tone::Danger));
        }
        items.push(Item::Help(self.btc_status_line(&ctx)));
        let signed = self.btc.signed_records(&ctx).len();
        if signed > 0 {
            items.push(Item::Banner(
                text::SIGNED_PENDING.fill(lang, [&signed.to_string()]),
                Tone::Warn,
            ));
        }
        self.btc_discovery_items(&ctx, items);
        let usable = gate.is_ok();
        self.btc_discover_row(&ctx, usable, items);
        items.push(Item::CardEnd);
        // `YubiKey` accounts (spec/10 §13) are listed even before BIP84 account 0 exists.
        let has_hardware = ctx
            .accounts()
            .iter()
            .any(|meta| meta.account().is_hardware());
        let show_accounts = (ctx.primary_meta().is_some() || !ctx.has_mnemonic || has_hardware)
            && ctx.mismatch().is_none();
        if ctx.btc_meta().is_none() && !ctx.has_mnemonic {
            // A key-only wallet without a Bitcoin key yet: only the account card.
            if show_accounts {
                self.btc_account_items(&ctx, items);
            }
            return;
        }
        // Same order as the EVM and Solana tabs (spec/04 §2.6): the selected account's balance
        // with `보내기`·`받기` first, then the account list.
        self.btc_selected_card(&ctx, usable, items);
        // The account card: a mnemonic wallet once BIP84 account 0 exists, a key-only wallet
        // always (its imported keys are its accounts).
        if show_accounts {
            self.btc_account_items(&ctx, items);
        }
        items.push(Item::CardStart(None));
        self.btc_utxo_items(&ctx, items);
        items.push(Item::CardEnd);
        items.push(Item::CardStart(None));
        self.btc_activity_items(&ctx, items);
        self.received_items(crate::received::RecvChain::Btc, items);
        items.push(Item::CardEnd);
    }

    /// The selected account card, in one layout with the other tabs (2026-11-11): name, path
    /// and type, balance, status, the address with `주소 복사`, then 보내기 · 받기 · 새로고침.
    fn btc_selected_card(&self, ctx: &BtcCtx<'_>, usable: bool, items: &mut Vec<Item>) {
        let lang = ctx.lang;
        items.push(Item::CardStart(None));
        self.btc_balance_items(ctx, items);
        if let Some(address) = self.btc_card_address() {
            items.push(crate::screen::build::core::own_address_row(
                self.settings.language,
                &address,
                crate::screen::address::AddressKind::Bitcoin,
                BtcPress::CardCopy,
                true,
                self.explorer_address_icon(
                    crate::network::NetworkId::Bitcoin(self.settings.bitcoin.network),
                    &address,
                    ExplorerPress::CardBtc,
                ),
            ));
        } else if usable && ctx.btc_meta().is_some() {
            // HD mode with every issued address used: `받기` issues the next one.
            items.push(Item::Help(text::RECEIVE_HINT.get(lang).to_owned()));
        }
        let send_block = self.btc.send_block(ctx);
        let mut actions = vec![
            Ctl::primary(BtcPress::SendOpen, text::SEND.get(lang)).enabled(send_block.is_none()),
            Ctl::primary(BtcPress::ReceiveOpen, text::RECEIVE.get(lang))
                .enabled(self.btc_unlocked()),
        ];
        if BtcUi::bump_target(ctx).is_some() {
            actions.push(
                Ctl::button(BtcPress::BumpOpen, text::BUMP_FEE.get(lang))
                    .enabled(usable && !self.btc.slot && !ctx.journal_damaged()),
            );
        }
        actions.push(
            Ctl::link(BtcPress::Refresh, text::REFRESH.get(lang))
                .tip(crate::screen::build::core::T_REFRESH_TIP.get(self.settings.language))
                .enabled(usable && !self.btc.refresh.busy && !self.btc.discovery.running),
        );
        items.push(Item::Row(actions));
        if self.btc.refresh.busy {
            items.push(Item::Help(text::REFRESHING.get(lang).to_owned()));
        }
        if let Some(reason) = send_block {
            items.push(Item::Help(text::SEND_BLOCKED.fill(lang, [&reason])));
        }
        items.push(Item::CardEnd);
    }

    /// The send form's fee estimate before `검토` (spec/08 §8, 2026-11-10): with a valid recipient
    /// and a typed amount, the chosen rate × the local vsize of one input of the account's type
    /// and two outputs (recipient, change) — `estimate_weight_with`, no call. Display only: `검토`
    /// plans with the node's fresh estimate and floor, and the approval shows the real fee.
    fn btc_fee_estimate_items(
        &self,
        fee: &BtcFeeForm,
        quote: Option<&FeeQuote>,
        items: &mut Vec<Item>,
    ) {
        let form = &self.btc.send;
        let (Some(recipient), Some(_)) = (form.recipient, form.amount) else {
            return;
        };
        if form.send_max || form.recipient_error.is_some() || form.amount_error.is_some() {
            return;
        }
        let rate = match fee.choice {
            BtcFeeChoice::Manual => fee.manual,
            choice => quoted_rate(choice, quote),
        };
        let ctx = self.btc_ctx();
        let lang = ctx.lang;
        let (Some(rate), Some(meta)) = (rate, ctx.btc_meta()) else {
            return;
        };
        let account = meta.account();
        let Some(weight) = yw_core::btc::tx::estimate_weight_with(
            account.input_weight(),
            1,
            &[
                yw_core::btc::script::spk_len(&recipient),
                account.script_type().spk_len(),
            ],
        ) else {
            return;
        };
        let vsize = weight.div_ceil(4);
        let Some(estimate) = yw_core::btc::fee::fee_for(rate, vsize) else {
            return;
        };
        // A label-value row and one muted line (2026-11-12, was a three-sentence paragraph).
        items.push(Item::Field(
            text::EXPECTED_FEE.get(lang).to_owned(),
            text::FEE_ABOUT.fill(
                lang,
                [
                    &yw_core::btc::amount::format_sats_grouped(estimate.get()),
                    &yw_core::btc::amount::format_btc(estimate),
                ],
            ),
        ));
        items.push(Item::Help(text::FEE_ESTIMATE_HELP.get(lang).to_owned()));
        if rate.sat_per_kvb() > yw_core::btc::BTC_FEE_RATE_CAP
            || estimate.get() > yw_core::btc::BTC_FEE_ABS_CAP
        {
            items.push(Item::Banner(
                text::FEE_OVER_CAP.get(lang).to_owned(),
                Tone::Warn,
            ));
        }
    }

    /// The fee radios, manual rate, floor note and typed-fee override of a form. The send form's
    /// radios carry the node's preview (2026-11-10, `BtcUi::fee_quote`): "빠름 · 약 20분 · 12
    /// sat/vB" (the floor when the estimate is below it), "· 추정 없음", or a loading line.
    fn btc_fee_items(&self, fee: &BtcFeeForm, bump: bool, items: &mut Vec<Item>) {
        let radio_presses = fee_presses(bump);
        let lang = self.settings.language;
        let net = self.btc_ctx().net();
        let quote = if bump {
            None
        } else {
            self.btc.fee_quote_of(net).copied()
        };
        let loading = !bump && quote.is_none() && self.btc.fee_quote_job.is_some();
        let radios = FEE_CHOICES
            .iter()
            .zip(radio_presses)
            .enumerate()
            .map(|(index, (choice, press))| {
                let label = if bump {
                    choice.label(lang).to_owned()
                } else {
                    fee_choice_label(lang, *choice, quote.as_ref())
                };
                Ctl::radio(press, &label, fee.choice == *choice, index == 0)
            })
            .collect();
        items.push(Item::LabeledRow(text::FEE.get(lang).to_owned(), radios));
        if loading {
            items.push(Item::Help(text::FEE_LOADING.get(lang).to_owned()));
        }
        // The send form's radios say the wait and the rate themselves: the note only when one
        // of them has no estimate (2026-11-12). The bump form's radios are bare.
        let missing = FEE_CHOICES.iter().any(|choice| {
            *choice != BtcFeeChoice::Manual && quoted_rate(*choice, quote.as_ref()).is_none()
        });
        if bump || (missing && !loading) {
            items.push(Item::Help(text::FEE_CHOICE_HELP.get(lang).to_owned()));
        }
        if fee.choice == BtcFeeChoice::Manual {
            let id = if bump {
                EditField::BtcBumpManual
            } else {
                EditField::BtcFeeManual
            };
            items.push(Item::LabeledRow(
                text::FEE_RATE_LABEL.get(lang).to_owned(),
                vec![Ctl::edit(id, &fee.manual_text, 160, false, 12)],
            ));
        }
        // The preview's floor fills the line before `검토` (2026-11-10).
        let floor = quote.map(|quote| quote.floor).or(self.btc.floor);
        // On the send form only where the floor matters (2026-11-12): `직접 입력`, or a chosen
        // estimate below it (`FEE_CHOICES` starts with the three estimates in `rates` order).
        let floored = quote.is_some_and(|quote| {
            FEE_CHOICES.iter().zip(quote.rates).any(|(choice, rate)| {
                *choice == fee.choice && rate.is_some_and(|rate| rate < quote.floor)
            })
        });
        if bump || fee.choice == BtcFeeChoice::Manual || floored {
            items.push(Item::Help(match floor {
                Some(floor) => text::FLOOR_NOTE.fill(lang, [&floor.to_string()]),
                None => text::FLOOR_UNKNOWN.get(lang).to_owned(),
            }));
        }
        if !bump {
            self.btc_fee_estimate_items(fee, quote.as_ref(), items);
        }
        if let Some(error) = &fee.error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        if let Some(planned) = fee.needs_typed {
            items.push(Item::Banner(
                text::TYPED_FEE_BANNER.fill(lang, [&BtcUi::amount_text(planned)]),
                Tone::Warn,
            ));
            let id = if bump {
                EditField::BtcBumpTyped
            } else {
                EditField::BtcTypedFee
            };
            items.push(Item::LabeledRow(
                text::TYPED_FEE_LABEL.get(lang).to_owned(),
                vec![Ctl::edit(id, &fee.typed_text, 200, false, 20)],
            ));
        }
    }

    /// S11 for Bitcoin (spec/08 §7–§8, spec/04 §2.7).
    #[expect(clippy::too_many_lines, reason = "the Bitcoin S11 fields in order")]
    pub fn btc_send_screen(&self, items: &mut Vec<Item>) {
        let ctx = self.btc_ctx();
        let net = ctx.net();
        let lang = ctx.lang;
        items.push(crate::screen::build::core::back_main(
            self.settings.language,
        ));
        items.push(Item::Badged(
            Badge::bitcoin(net),
            Box::new(Item::Title(
                text::SEND_TITLE.fill(lang, [net.display_name_in(lang)]),
            )),
        ));
        network_banners(lang, net, items);
        let form = &self.btc.send;
        // Why the form cannot send at all is said first; what `검토` ended with is said next
        // to the button (below).
        let block = self.btc.send_block(&ctx);
        if let Some(reason) = &block {
            items.push(Item::Banner(reason.clone(), Tone::Warn));
        }
        if ctx.journal_damaged() {
            items.push(Item::Banner(
                text::JOURNAL_DAMAGED.get(lang).to_owned(),
                Tone::Blocked,
            ));
        }
        items.push(Item::CardStart(Some(
            text::FROM_ACCOUNT.get(lang).to_owned(),
        )));
        items.push(Item::Text(self.btc_active_label(&ctx)));
        items.push(Item::Help(active_detail(&ctx)));
        if let Some(balance) = self.btc.balance(&ctx) {
            items.push(Item::Help(
                text::AVAILABLE_VERIFIED.fill(lang, [&BtcUi::amount_text(balance.available)]),
            ));
        }
        self.mn_signing_banner(self.btc_backup_gate(), items);
        self.card_pin_banner(self.btc_selected_card_gate(), items);
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            text::RECIPIENT_CARD.get(lang).to_owned(),
        )));
        let target = BookTarget::Btc(net);
        self.favorite_chip_items(target, items);
        items.push(Item::LabeledRow(
            text::RECIPIENT_ADDRESS.get(lang).to_owned(),
            vec![
                Ctl::edit(EditField::BtcSendTo, &form.to_text, 430, false, 128),
                Ctl::button(BookPress::BtcPick, text::PICK_FROM_BOOK.get(lang)),
            ],
        ));
        // The format hint only until the address is valid (2026-11-12); the reminder to check
        // all of it then sits under the grouped address.
        if form.recipient.is_none() || form.recipient_error.is_some() {
            items.push(Item::Help(text::ADDRESS_HINT.get(lang).to_owned()));
        }
        self.btc_picker_items(target, items);
        if let Some(error) = &form.recipient_error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        } else if let Some(kind) = form.recipient {
            items.push(Item::Help(
                text::ADDRESS_KIND.fill(lang, [kind_text(lang, &kind)]),
            ));
            let address = encode_address(&kind, net);
            items.push(Item::Mono(grouped(&address)));
            items.push(Item::Help(text::CHECK_WHOLE.get(lang).to_owned()));
            let entry = self
                .meta
                .as_ref()
                .and_then(|meta| meta.contact(BookChain::Btc, &address));
            if let Some(entry) = &entry {
                let verified = if entry.verified {
                    format!(" {}", text::VERIFIED.get(lang))
                } else {
                    String::new()
                };
                items.push(Item::Banner(
                    text::BOOK_ENTRY.fill(lang, [&entry.label, &verified]),
                    Tone::Info,
                ));
            }
            if let Some(note) = &form.look_alike {
                items.push(Item::Banner(note.clone(), Tone::HighRisk));
                items.push(Item::Row(vec![Ctl::check(
                    BtcPress::SendAddrAck,
                    text::ADDR_ACK.get(lang),
                    form.ack,
                )]));
                if entry.as_ref().is_some_and(|entry| !entry.verified) {
                    items.push(Item::Help(
                        crate::wallet::app_book::text::BOOK_VERIFY_HINT
                            .get(self.settings.language)
                            .to_owned(),
                    ));
                }
            }
            self.recipient_save_items(target, items);
        }
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            text::AMOUNT_CARD.get(lang).to_owned(),
        )));
        // What `최대` can send, next to the amount (2026-11-12; only in the sender card before).
        items.push(Item::Help(self.btc.balance(&ctx).map_or_else(
            || text::AVAILABLE_UNREAD.get(lang).to_owned(),
            |balance| text::AVAILABLE.fill(lang, [&BtcUi::amount_text(balance.available)]),
        )));
        items.push(Item::LabeledRow(
            text::AMOUNT.get(lang).to_owned(),
            vec![
                Ctl::edit(EditField::BtcSendAmount, &form.amount_text, 220, false, 32)
                    .enabled(!form.send_max),
                // Right after the field like every chain's `최대` (2026-11-12), then the unit.
                Ctl::tab(BtcPress::SendMax, text::MAX.get(lang), form.send_max),
                Ctl::radio(
                    BtcPress::UnitBtc,
                    "BTC",
                    form.unit == crate::wallet::app_btc::BtcAmountUnit::Btc,
                    true,
                ),
                Ctl::radio(
                    BtcPress::UnitSats,
                    "sats",
                    form.unit == crate::wallet::app_btc::BtcAmountUnit::Sats,
                    false,
                ),
            ],
        ));
        if let Some(error) = &form.amount_error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        } else if let Some(amount) = form.amount {
            items.push(Item::Help(BtcUi::amount_text(amount)));
        }
        if form.send_max {
            items.push(Item::Help(text::MAX_HELP.get(lang).to_owned()));
        }
        // Only until the amount is valid (2026-11-12).
        if !form.send_max && form.amount.is_none() {
            items.push(Item::Help(text::AMOUNT_HINT.get(lang).to_owned()));
        }
        items.push(Item::Rule);
        self.btc_fee_items(&form.fee, false, items);
        // `검토`'s progress, a plan the node refused (funds, dust, no fee estimate, tip ahead),
        // an expired approval or a signature that failed: next to the button, where the user
        // pressed it (the top of the form is below the fold by then).
        if let Some(info) = form
            .info
            .as_ref()
            .filter(|info| block.as_ref() != Some(*info))
        {
            items.push(Item::Banner(
                info.clone(),
                if info.as_str() == crate::wallet::app_btc::BTC_PREPARING.get(lang) {
                    Tone::Info
                } else {
                    Tone::Warn
                },
            ));
        }
        items.push(Item::CardEnd);
        self.journal_send_items(crate::wallet::app_sidecar::SendChain::Btc, items);
        let blocker = self.btc_review_blocker();
        items.push(Item::Row(vec![
            Ctl::primary(BtcPress::SendReview, text::REVIEW.get(lang)).enabled(blocker.is_none()),
            Ctl::button(BtcPress::SendCancel, text::CANCEL.get(lang)),
        ]));
        // What `검토` waits for, or that it sends nothing yet (2026-11-12).
        items.push(Item::Help(
            crate::wallet::app_sol::ReviewBlocker::line(self.settings.language, blocker).to_owned(),
        ));
    }

    /// Whether the send form's `검토` is enabled: the controller's checks, an account whose
    /// phrase has passed its backup quiz (U7; the band above says why), and after a journal reset
    /// the check above the button.
    #[must_use]
    pub fn btc_can_review(&self) -> bool {
        self.btc_review_blocker().is_none()
    }

    /// Why the send form's `검토` is off, `None` when it is on (2026-11-12: the line under the
    /// button).
    #[must_use]
    pub fn btc_review_blocker(&self) -> Option<crate::wallet::app_sol::ReviewBlocker> {
        let held = self.mn_send_blocked(self.btc_backup_gate())
            // spec/10 §9.3: the YubiKey is still on its factory PINs (the band says so).
            || self.btc_selected_card_gate().is_some()
            || self
                .journal_hold(crate::wallet::app_sidecar::SendChain::Btc)
                .is_some();
        if held {
            return Some(crate::wallet::app_sol::ReviewBlocker::Held);
        }
        self.btc.review_blocker(&self.btc_ctx())
    }

    /// Whether the fee-bump form's `검토` is enabled.
    #[must_use]
    pub fn btc_can_review_bump(&self) -> bool {
        let ctx = self.btc_ctx();
        let form = &self.btc.bump;
        ctx.gate().is_ok()
            && !ctx.journal_damaged()
            && !self.btc.slot
            && form.preparing.is_none()
            && form.fee.error.is_none()
            && (form.fee.choice != BtcFeeChoice::Manual || form.fee.manual.is_some())
            && BtcUi::bump_target(&ctx).is_some()
    }

    /// The fee-bump form (spec/08 §9).
    pub fn btc_bump_screen(&self, items: &mut Vec<Item>) {
        let ctx = self.btc_ctx();
        let net = ctx.net();
        let lang = ctx.lang;
        items.push(crate::screen::build::core::back_main(
            self.settings.language,
        ));
        items.push(Item::Title(
            text::BUMP_TITLE.fill(lang, [net.display_name_in(lang)]),
        ));
        network_banners(lang, net, items);
        let form = &self.btc.bump;
        if let Some(info) = &form.info {
            items.push(Item::Banner(info.clone(), Tone::Warn));
        }
        if ctx.journal_damaged() {
            items.push(Item::Banner(
                text::JOURNAL_DAMAGED.get(lang).to_owned(),
                Tone::Danger,
            ));
        }
        let target = form
            .target
            .and_then(|txid| ctx.record(&txid))
            .or_else(|| BtcUi::bump_target(&ctx));
        if let Some(record) = target {
            items.push(Item::Text(text::REPLACED_TX.get(lang).to_owned()));
            items.push(Item::Mono(record.txid.to_display_hex()));
            items.push(Item::Muted(
                text::STATUS.fill(lang, [&record_status(lang, &record, self.btc_tip(&ctx))]),
            ));
            items.push(Item::Muted(text::CURRENT_FEE.fill(
                lang,
                [
                    &BtcUi::amount_text(record.fee),
                    &record_rate(record.fee, record.vsize),
                ],
            )));
            if let Some(amount) = record.recipient_amount() {
                let note = if record.send_max {
                    format!(" {}", text::BUMP_SEND_MAX_NOTE.get(lang))
                } else {
                    String::new()
                };
                items.push(Item::Muted(
                    text::BUMP_AMOUNT.fill(lang, [&BtcUi::amount_text(amount), &note]),
                ));
            }
            if let Some(address) = record.recipient_address() {
                items.push(Item::Mono(grouped(&address)));
            }
        } else {
            items.push(Item::Muted(texts::NOT_BUMPABLE.get(lang).to_owned()));
        }
        items.push(Item::Muted(text::BUMP_HELP.get(lang).to_owned()));
        self.btc_fee_items(&form.fee, true, items);
        items.push(Item::Row(vec![
            Ctl::primary(BtcPress::BumpReview, text::REVIEW.get(lang))
                .enabled(self.btc_can_review_bump()),
            Ctl::button(BtcPress::BumpCancel, text::CANCEL.get(lang)),
        ]));
    }

    /// The S11 result for Bitcoin: the local txid, status and the post-sign flow.
    pub fn btc_send_result_screen(&self, items: &mut Vec<Item>) {
        let ctx = self.btc_ctx();
        let net = ctx.net();
        let lang = ctx.lang;
        let record = self.btc.result.and_then(|txid| ctx.record(&txid));
        let bump = record
            .as_ref()
            .is_some_and(|record| record.replaces.is_some());
        items.push(Item::Title(
            if bump {
                text::RESULT_BUMP
            } else {
                text::RESULT_SEND
            }
            .get(lang)
            .to_owned(),
        ));
        network_banners(lang, net, items);
        let Some(txid) = self.btc.result else {
            items.push(Item::Muted(text::NO_RESULT.get(lang).to_owned()));
            items.push(Item::Row(vec![Ctl::button(
                CorePress::BackMain,
                text::BACK_MAIN.get(lang),
            )]));
            return;
        };
        items.push(Item::Banner(
            text::SIGNED_BANNER.get(lang).to_owned(),
            Tone::Success,
        ));
        items.push(Item::Mono(txid.to_display_hex()));
        let status = record.as_ref().map_or_else(
            || text::FINISHED_SEE_ACTIVITY.get(lang).to_owned(),
            |record| record_status(lang, record, self.btc_tip(&ctx)),
        );
        items.push(Item::Badged(
            Badge::bitcoin(net),
            Box::new(Item::Muted(
                text::RESULT_STATUS.fill(lang, [&status, net.display_name_in(lang)]),
            )),
        ));
        let flow = self.btc.flow(&txid);
        if let Some(stage) = flow.and_then(|flow| flow_stage_text(lang, flow.stage)) {
            items.push(Item::Muted(stage.to_owned()));
        }
        if let Some(note) = flow.and_then(|flow| flow.note.clone()) {
            let waiting = flow.is_some_and(|flow| flow.stage == BtcFlowStage::Waiting);
            items.push(Item::Banner(
                note,
                if waiting { Tone::Warn } else { Tone::Info },
            ));
        }
        let mut row = vec![Ctl::button(BtcPress::ResultCopy, text::COPY_HASH.get(lang))];
        // 2026-11-11: the txid on the network's explorer (also before the broadcast is known:
        // the page then says it does not know the transaction yet).
        row.extend(self.explorer_tx_buttons(
            crate::network::NetworkId::Bitcoin(self.settings.bitcoin.network),
            &txid.to_display_hex(),
            Some((
                ExplorerPress::ResultBtcOpen.into(),
                ExplorerPress::ResultBtcCopy.into(),
            )),
        ));
        let signed = record
            .as_ref()
            .is_some_and(|record| record.state == yw_core::journal::btc::BtcTxState::Signed);
        if signed
            && flow.is_some_and(|flow| flow.retry_precheck && flow.stage == BtcFlowStage::Waiting)
        {
            row.push(
                Ctl::button(BtcPress::ResultRetry, text::RETRY.get(lang))
                    .enabled(ctx.gate().is_ok()),
            );
        }
        let rejected = record
            .as_ref()
            .filter(|record| record.state == yw_core::journal::btc::BtcTxState::Rejected);
        if let Some(rejected) = rejected
            && !bump
        {
            items.push(Item::Muted(
                if rejected.disclosed {
                    yw_core::btc::policy::texts::REJECTED_DISCLOSED
                } else {
                    text::NOT_SENT_KEPT
                }
                .get(lang)
                .to_owned(),
            ));
            row.push(Ctl::button(
                BtcPress::ResultToSend,
                text::TO_SEND_SCREEN.get(lang),
            ));
        }
        row.insert(
            0,
            Ctl::primary(CorePress::BackMain, text::BACK_MAIN.get(lang)),
        );
        items.push(Item::Row(row));
        if !bump {
            self.result_save_items(BookTarget::Btc(net), items);
        }
    }

    /// S12 for Bitcoin (spec/08 §3.2): the address appears only after `receive_next` is stored.
    pub fn btc_receive_screen(&self, items: &mut Vec<Item>) {
        let ctx = self.btc_ctx();
        let net = self
            .btc
            .receive
            .as_ref()
            .map_or_else(|| ctx.net(), |view| view.network);
        let lang = ctx.lang;
        items.push(crate::screen::build::core::back_main(
            self.settings.language,
        ));
        items.push(Item::Badged(
            Badge::bitcoin(net),
            Box::new(Item::Title(
                text::RECEIVE_TITLE.fill(lang, [net.display_name_in(lang)]),
            )),
        ));
        network_banners(lang, net, items);
        if let Some(message) = &self.btc.receive_message {
            items.push(Item::Banner(message.clone(), Tone::Danger));
        }
        // An HD account of the primary phrase or an EVM key's use is the primary phrase's key.
        self.mn_receive_banner(self.btc_backup_gate(), items);
        let Some(view) = &self.btc.receive else {
            if self.btc.receive_message.is_none() {
                items.push(Item::Muted(text::PREPARING_ADDRESS.get(lang).to_owned()));
            }
            return;
        };
        items.push(Item::CardStart(Some(if view.single_key {
            view.account.clone()
        } else if view.fixed {
            text::FIXED_ADDRESS.fill(lang, [&view.account])
        } else {
            text::RECEIVE_INDEX.fill(lang, [&view.account, &view.index.to_string()])
        })));
        items.push(Item::Text(text::ADDRESS_FORMAT.fill(lang, [&view.kind])));
        if view.fixed && !view.single_key {
            // An HD account in fixed-address mode (spec/08 §3.5): said before the QR.
            items.push(Item::Banner(
                crate::wallet::app_btc::T_BTC_FIXED_RECEIVE
                    .get(lang)
                    .to_owned(),
                Tone::Info,
            ));
        }
        // The address on its copy line with `새 주소` beside it, then the QR (2026-11-12, all
        // chains); the account's note follows the QR.
        let mut actions = Vec::new();
        if !view.fixed {
            actions.push(
                Ctl::button(BtcPress::NewAddress, text::NEW_ADDRESS.get(lang))
                    .compact()
                    .enabled(ctx.gate().is_ok()),
            );
        }
        items.push(crate::screen::build::core::receive_address_row(
            self.settings.language,
            &grouped(&view.address),
            BtcPress::CopyAddress,
            actions,
        ));
        items.push(Item::Qr(view.qr.clone()));
        items.push(Item::Help(view.note.clone()));
        items.push(Item::Help(view.path.clone()));
        items.push(Item::CardEnd);
    }

    /// S15 Bitcoin section (spec/04 §2.11, spec/08 §2).
    #[expect(clippy::too_many_lines, reason = "the S15 Bitcoin rows in order")]
    pub fn btc_settings_section(&self, items: &mut Vec<Item>) {
        let ctx = self.btc_ctx();
        let settings = ctx.settings;
        let net = ctx.net();
        let lang = ctx.lang;
        if let Some(message) = &self.btc.settings_message {
            items.push(Item::Banner(message.clone(), Tone::Danger));
        }
        items.push(Item::CardStart(Some(
            text::SETTINGS_CARD.get(lang).to_owned(),
        )));
        items.push(Item::Row(vec![Ctl::check(
            BtcPress::Enable,
            text::ENABLE.get(lang),
            settings.enabled,
        )]));
        items.push(Item::LabeledRow(
            text::NETWORK.get(lang).to_owned(),
            vec![
                Ctl::radio(
                    BtcPress::SetMainnet,
                    "mainnet",
                    net == BtcNetwork::Mainnet,
                    true,
                ),
                Ctl::radio(
                    BtcPress::SetTestnet4,
                    text::TESTNET4_RADIO.get(lang),
                    net == BtcNetwork::Testnet4,
                    false,
                ),
            ],
        ));
        if settings.enabled {
            items.push(Item::Banner(
                net.banner_in(lang).to_owned(),
                network_tone(net),
            ));
            if let Some((meta, current)) = ctx.mismatch() {
                items.push(Item::Banner(
                    texts::NETWORK_MISMATCH.get(lang).to_owned(),
                    Tone::Danger,
                ));
                Self::btc_mismatch_row(lang, meta, current, items);
            }
        }
        items.push(Item::Help(text::ENABLE_HELP.get(lang).to_owned()));
        for known in BtcNetwork::ALL {
            let network = crate::btc::network_id(known);
            let state = if self.apikeys.has(KeyName::Rpc(network)) {
                text::RPC_SET.get(lang).to_owned()
            } else {
                text::RPC_NONE.fill(lang, [ErrorCode::Key005.code()])
            };
            items.push(Item::Help(
                text::RPC_LINE.fill(lang, [&network.to_string(), &state]),
            ));
        }
        items.push(Item::Row(vec![Ctl::button(
            CorePress::GoNetwork,
            text::GO_NETWORK.get(lang),
        )]));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            text::INDEXER_CARD.get(lang).to_owned(),
        )));
        let indexer = settings.indexer;
        items.push(Item::LabeledRow(
            text::INDEXER.get(lang).to_owned(),
            vec![
                Ctl::radio(
                    BtcPress::IdxEsplora,
                    "Esplora",
                    indexer == BtcIndexer::Esplora,
                    true,
                ),
                Ctl::radio(
                    BtcPress::IdxBbRpc,
                    "Blockbook JSON-RPC (bb-rpc)",
                    indexer == BtcIndexer::BbRpc,
                    false,
                ),
                Ctl::radio(
                    BtcPress::IdxBbRest,
                    "Blockbook REST (bb-rest)",
                    indexer == BtcIndexer::BbRest,
                    false,
                ),
            ],
        ));
        items.push(Item::Help(T_BTC_ESPLORA_NOTE.get(lang).to_owned()));
        items.push(Item::Help(text::INDEXER_HELP.get(lang).to_owned()));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("Esplora URL".to_owned())));
        for known in BtcNetwork::ALL {
            let (edit, save, default, test) = esplora_controls(known);
            let value = ctx.esplora_text(known);
            items.push(Item::Subtitle(format!(
                "Esplora URL — {}",
                known.settings_name()
            )));
            items.push(Item::Mono(value.to_owned()));
            items.push(Item::Row(vec![Ctl::edit(edit, value, 420, false, 256)]));
            items.push(Item::Row(vec![
                Ctl::button(save, text::SAVE.get(lang)),
                Ctl::button(default, text::DEFAULT.get(lang)),
                Ctl::button(test, text::TEST.get(lang)),
            ]));
            if let Some((_, message, state)) = self
                .btc
                .esplora_tests
                .iter()
                .find(|(tested, ..)| *tested == known)
            {
                items.push(Item::Banner(message.clone(), state.tone()));
            }
        }
        items.push(Item::Help(text::ESPLORA_TEST_HELP.get(lang).to_owned()));
        items.push(Item::CardEnd);
    }
}
