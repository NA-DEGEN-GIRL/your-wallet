//! Screen contents S01–S15 (spec/04 §2) as [`Item`] lists, and the command ids of their
//! controls. Fixed sentences follow spec/04 §2.16; nothing from RPC or the OS is shown.
//!
//! Layout rules (spec/04 §2.0, design system §1.6): one primary button per screen (two on the
//! chain tabs: 보내기 / 받기), sections in cards with a heading, a plain-language help line under
//! technical fields, technical settings behind `고급 설정 보기`, flows with a step indicator.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): moved here from yw-app `ui/screens.rs` with the bodies
//! unchanged (`impl App` builders became `impl Screen<'_>`, yw-app paths engine paths); its control
//! ids stay there (`ui::screens::ids`).

use core::fmt::Write as _;

use yw_core::evm::chain::SEPOLIA;
use yw_core::evm::display::format_address;

use crate::apikeys::{KeyName, mask_url, template_entry};
use crate::cmd::{
    BtcPress, CorePress, EvmPress, ExplorerPress, ExtPress, KeysPress, LinksPress, LlmPress,
    MnPress, Press, ResetPress, Row, RpcImportPress, RpcRowAction, SitesPress, SolPress,
    YkConnectPress, YkPress,
};
use crate::errors::ErrorCode;
use crate::form::{CredField, EditField};
use crate::meta::EvmAccountPref;
use crate::network::NetworkId;
use crate::screen::AccountSource;
use crate::screen::SettingsSection;
use crate::screen::Tone;
use crate::screen::address::AddressKind;
use crate::screen::build::accounts::{AccountCard, AccountItem, SelectedLine};
use crate::screen::facts::ScreenFacts;
use crate::screen::model::{Ctl, Item};
use crate::screen::rows;
use crate::settings::{LogLevel, RpcTemplate};
use crate::wallet::{AppMode, CREATE_STEPS, Confirm, IMPORT_STEPS, Screen, TestState};
use yw_core::lang::{Lang, Text};

pub mod text;

pub use text::{
    T_ACCOUNTS_BACKUP, T_ACCOUNTS_IMPORTED, T_ACCOUNTS_KEY_ONLY, T_ACCOUNTS_YUBIKEY,
    T_ACCOUNTS_YUBIKEY_WORDS, T_ACTIVITY_RECEIVED, T_ALT_PASS, T_BALANCE_FAILED, T_BALANCE_LOADING,
    T_DISCARD, T_MAINNET, T_REFRESH_TIP, T_REMOVE_KEY, T_TOKEN_DELETE,
};

/// The step indicator item of a flow.
#[must_use]
pub fn steps<const N: usize>(labels: [&str; N], current: usize) -> Item {
    Item::Steps(
        labels.iter().map(|label| (*label).to_owned()).collect(),
        current,
    )
}

/// The `← 메인으로` link.
#[must_use]
pub fn back_main(lang: Lang) -> Item {
    Item::Row(vec![
        Ctl::link(CorePress::BackMain, text::BACK_MAIN.get(lang))
            .tip(text::BACK_MAIN_TIP.get(lang)),
    ])
}

/// The `언어 · Language` card title: the same in both languages (spec/14 §1), like the `한국어`
/// option, so either reader finds the setting.
pub const LANGUAGE_TITLE: &str = "언어 · Language";
/// The `한국어` option of the language card (the language's own name in both languages).
pub const LANGUAGE_KOREAN: &str = "한국어";

/// T-FIRST-1 (S01, three plain sentences).
pub const T_FIRST: [Text; 3] = [text::T_FIRST_1, text::T_FIRST_2, text::T_FIRST_3];

/// The selected-account card of a network without an RPC address (spec/04 §2.6, 2026-11-08):
/// why there is no balance, in place of "RPC 연결을 확인하고 새로고침하세요".
#[must_use]
pub fn no_endpoint_text(lang: Lang, network: &str) -> String {
    text::NO_ENDPOINT.fill(lang, [network])
}

/// `HH:MM` in local time (UTC with a suffix if the conversion fails). 2026-11-24 (spec/15
/// §11.4 S5-3): the local time is the shell's answer [`ScreenFacts::local_wall_ms`] (before,
/// `yw_win::time::local_wall_ms` here; the same call answers it on Windows).
#[must_use]
pub fn local_hh_mm(facts: &dyn ScreenFacts, unix_ms: u64) -> String {
    let wall = facts.local_wall_ms(unix_ms);
    let text = crate::logging::format_utc(wall.unwrap_or(unix_ms));
    let time = text.get(11..16).unwrap_or("--:--").to_owned();
    if wall.is_some() {
        time
    } else {
        format!("{time} UTC")
    }
}

/// The line under a balance read successfully: "블록 N 기준 · HH:MM 갱신" (EVM) or
/// "HH:MM 갱신" (no block number).
#[must_use]
pub fn balance_read_text(
    facts: &dyn ScreenFacts,
    lang: Lang,
    block: Option<u64>,
    at_unix_ms: Option<u64>,
) -> String {
    let when = at_unix_ms.map(|at| text::UPDATED_AT.fill(lang, [&local_hh_mm(facts, at)]));
    match (block, when) {
        (Some(block), Some(when)) => text::AT_BLOCK_WHEN.fill(lang, [&block.to_string(), &when]),
        (Some(block), None) => text::AT_BLOCK.fill(lang, [&block.to_string()]),
        (None, Some(when)) => when,
        (None, None) => String::new(),
    }
}

/// The line under a balance kept from before a failed read (2026-11-12): where the number is
/// from — "블록 N 기준 · HH:MM 이후 갱신 실패" (EVM), "HH:MM 이후 갱신 실패" (no block number).
/// Why it failed is the network card's band.
#[must_use]
pub fn balance_stale_text(
    facts: &dyn ScreenFacts,
    lang: Lang,
    block: Option<u64>,
    at_unix_ms: Option<u64>,
) -> String {
    let since = at_unix_ms.map_or_else(
        || text::UPDATE_FAILED.get(lang).to_owned(),
        |at| text::UPDATE_FAILED_SINCE.fill(lang, [&local_hh_mm(facts, at)]),
    );
    match block {
        Some(block) => text::AT_BLOCK_WHEN.fill(lang, [&block.to_string(), &since]),
        None => since,
    }
}

/// The network card's band of a failed balance read (2026-11-10; one line since 2026-11-12):
/// what failed (the code's short name) and its code. The buttons under it are the next step,
/// and the code's whole §7 text is the answer of `RPC 테스트` and of settings. A code without
/// a short name keeps its whole text.
#[must_use]
pub fn balance_failure_text(lang: Lang, code: ErrorCode) -> String {
    match code.short_name_in(lang) {
        Some(name) => text::BALANCE_FAILURE.fill(lang, [name, code.code()]),
        None => code.text_in(lang),
    }
}

/// The account cards' address line (2026-11-11, spec/04 §2.6): the user's own address without
/// spaces, the 4 characters after its prefix and the last 4 emphasized
/// (`crate::screen::address::own_address_spans`), on a flat button whose click copies it (`copy`, off when
/// `enabled` is not; the `주소 복사` of before), then `explorer` — the ↗ icon
/// `탐색기에서 주소 보기` (`super::Screen::explorer_address_icon`) when the network has an address page —
/// at the right end. Recipient checks (approval, send, receive) keep the grouped form of §3.3.
#[must_use]
pub fn own_address_row(
    lang: Lang,
    address: &str,
    kind: AddressKind,
    copy: impl Into<Press>,
    enabled: bool,
    explorer: Option<Ctl>,
) -> Item {
    Item::CopyLine {
        value: Ctl::value(
            copy.into(),
            crate::screen::build::links::T_ADDRESS_COPY.get(lang),
            crate::screen::address::own_address_spans(address, kind, false),
        )
        .enabled(enabled),
        actions: explorer.into_iter().collect(),
    }
}

/// The receive screens' and the address book's address line (S12, 2026-11-12): the address
/// whole with its ends emphasized like every address (§3.3, `crate::screen::address::address_spans`; `shown`
/// may still be the older grouped form) on the flat copy button — the `주소 복사` button under
/// the address of before; the command still copies the address itself — and `actions`
/// (Bitcoin's `새 주소`) at the right end.
#[must_use]
pub fn receive_address_row(
    lang: Lang,
    shown: &str,
    copy: impl Into<Press>,
    actions: Vec<Ctl>,
) -> Item {
    let spans = crate::screen::address::address_spans(shown)
        .unwrap_or_else(|| vec![(shown.to_owned(), false)]);
    Item::CopyLine {
        value: Ctl::value(
            copy.into(),
            crate::screen::build::links::T_ADDRESS_COPY.get(lang),
            spans,
        ),
        actions,
    }
}

/// The `vault.ywv` facts line (review L17): generation and last write time, so a file swapped
/// for an older copy is noticeable.
#[must_use]
pub fn vault_file_text(
    facts: &dyn ScreenFacts,
    lang: Lang,
    generation: u64,
    written_unix_ms: u64,
) -> String {
    let wall = facts.local_wall_ms(written_unix_ms);
    let text = crate::logging::format_utc(wall.unwrap_or(written_unix_ms));
    let short = text.get(..16).unwrap_or(&text).replace('T', " ");
    let when = if wall.is_some() {
        short
    } else {
        format!("{short} UTC")
    };
    text::VAULT_FILE.fill(lang, [&generation.to_string(), &when])
}

fn header(app: &super::Screen<'_>, items: &mut Vec<Item>) {
    let lang = app.settings.language;
    if app.passphrase_unverified() {
        items.push(Item::Banner(
            T_ALT_PASS.get(lang).to_owned(),
            Tone::HighRisk,
        ));
    }
    app.meta_failed_items(items);
    app.journal_closed_items(items);
    if app.guard.pending.is_some() && app.screen != Screen::Confirm(Confirm::SettingsFile) {
        // What differs, in plain words with both values (2026-11-08); the safe choice is the
        // primary button and `파일 값 사용…` asks once more (spec/04 §6.7).
        items.push(Item::Banner(
            text::SETTINGS_TAMPERED_BANNER
                .fill(lang, [crate::settings::SETTINGS_TAMPERED_TEXT.get(lang)]),
            Tone::Warn,
        ));
        for line in app.settings_file_lines() {
            items.push(Item::Help(line));
        }
        items.push(Item::Row(vec![
            Ctl::primary(CorePress::SettingsRestore, text::SETTINGS_RESTORE.get(lang)),
            Ctl::button(
                CorePress::SettingsAcceptFile,
                text::SETTINGS_ACCEPT_FILE.get(lang),
            ),
        ]));
    }
    for banner in &app.banners {
        items.push(Item::Banner(banner.text.clone(), banner.tone));
    }
    app.yk_pin_needed_items(items);
    if let Some(info) = &app.info {
        items.push(Item::Banner(info.clone(), Tone::Info));
    }
    if !app.banners.is_empty() || app.info.is_some() {
        items.push(Item::Row(vec![Ctl::link(
            CorePress::DismissBanners,
            text::DISMISS_BANNERS.get(lang),
        )]));
    }
}

fn indexer_name(indexer: crate::settings::BtcIndexer) -> &'static str {
    match indexer {
        crate::settings::BtcIndexer::Esplora => "Esplora",
        crate::settings::BtcIndexer::BbRpc => "Blockbook RPC",
        crate::settings::BtcIndexer::BbRest => "Blockbook REST",
    }
}

fn cap_value(lang: Lang, value: &str) -> &str {
    if value.is_empty() {
        text::DEFAULT_VALUE.get(lang)
    } else {
        value
    }
}

impl super::Screen<'_> {
    /// One plain line per value that differs between the settings in use and `settings.json`
    /// (the settings-file banner and its `파일 값 사용` overlay): the value in use, then the
    /// value in the file, with the JSON key in brackets. Nothing here is secret (spec/04 §6.7).
    #[must_use]
    pub fn settings_file_lines(&self) -> Vec<String> {
        let Some(pending) = self.guard.pending.as_ref() else {
            return Vec::new();
        };
        let (file, differing) = (&pending.0, &pending.1);
        let current = &self.settings;
        let lang = current.language;
        let mut lines = Vec::new();
        for kind in differing {
            match kind {
                crate::settings::Differing::AutoLock => lines.push(text::DIFF_AUTO_LOCK.fill(
                    lang,
                    [
                        &current.auto_lock_minutes.to_string(),
                        &file.auto_lock_minutes.to_string(),
                    ],
                )),
                crate::settings::Differing::FeeCaps => {
                    let mut chains: Vec<u64> = current
                        .fee_caps
                        .iter()
                        .chain(&file.fee_caps)
                        .map(|(id, _)| *id)
                        .collect();
                    chains.sort_unstable();
                    chains.dedup();
                    for id in chains {
                        let caps_of = |settings: &crate::settings::Settings| {
                            settings
                                .fee_caps
                                .iter()
                                .find(|(chain, _)| *chain == id)
                                .map(|(_, caps)| caps.clone())
                        };
                        let (now, then) = (caps_of(current), caps_of(file));
                        if now == then {
                            continue;
                        }
                        let part = |caps: Option<&crate::settings::FeeCapsText>,
                                    pick: fn(&crate::settings::FeeCapsText) -> &str| {
                            caps.map_or(text::DEFAULT_VALUE.get(lang), |caps| {
                                cap_value(lang, pick(caps))
                            })
                            .to_owned()
                        };
                        lines.push(text::DIFF_FEE_CAPS.fill(
                            lang,
                            [
                                &self.network_name(NetworkId::Eip155(id)),
                                &part(now.as_ref(), |caps| &caps.max_fee_per_gas_gwei),
                                &part(then.as_ref(), |caps| &caps.max_fee_per_gas_gwei),
                                &part(now.as_ref(), |caps| &caps.max_priority_fee_per_gas_gwei),
                                &part(then.as_ref(), |caps| &caps.max_priority_fee_per_gas_gwei),
                                &part(now.as_ref(), |caps| &caps.max_total_fee),
                                &part(then.as_ref(), |caps| &caps.max_total_fee),
                            ],
                        ));
                    }
                }
                crate::settings::Differing::Indexer => {
                    let server = |bitcoin: &crate::settings::BitcoinSettings| {
                        format!(
                            "{} (mainnet {} · testnet4 {})",
                            indexer_name(bitcoin.indexer),
                            cap_value(lang, &bitcoin.esplora_mainnet),
                            cap_value(lang, &bitcoin.esplora_testnet4)
                        )
                    };
                    lines.push(
                        text::DIFF_INDEXER
                            .fill(lang, [&server(&current.bitcoin), &server(&file.bitcoin)]),
                    );
                }
                crate::settings::Differing::NewChains => {
                    for chain in file.evm_chains.iter().filter(|chain| {
                        !current
                            .evm_chains
                            .iter()
                            .any(|known| known.chain_id == chain.chain_id)
                    }) {
                        lines.push(
                            text::DIFF_NEW_CHAIN
                                .fill(lang, [&chain.name, &chain.chain_id.to_string()]),
                        );
                    }
                }
            }
        }
        lines
    }
}

impl super::Screen<'_> {
    /// The recovery card of a wallet with recovery words (settings → 보안): the backup status
    /// when the first phrase is not the only backup (2026-11-08), and the reveal buttons.
    fn backup_card_rows(&self, unlocked: bool, public: bool, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let lines = self.backup_status_lines();
        if lines.is_empty() {
            items.push(Item::Help(text::BACKUP_CARD_HELP.get(lang).to_owned()));
        } else {
            // Several backups (2026-11-08): the first recovery phrase is no longer the
            // whole wallet's backup, so say what each part needs (status only, no values).
            items.push(Item::Subtitle(
                text::BACKUP_STATUS_TITLE.get(lang).to_owned(),
            ));
            for line in lines {
                items.push(Item::Text(line));
            }
            items.push(Item::Help(text::BACKUP_STATUS_HELP.get(lang).to_owned()));
        }
        let several = self.several_mnemonics();
        let mut row = vec![
            Ctl::button(
                CorePress::RevealMnemonic,
                if several {
                    text::REVEAL_FIRST_MNEMONIC.get(lang)
                } else {
                    text::REVEAL_MNEMONIC.get(lang)
                },
            )
            .enabled(public),
            Ctl::button(CorePress::RevealKey, text::REVEAL_KEY.get(lang))
                .enabled(unlocked && !self.hardware_selected()),
        ];
        if several {
            row.push(Ctl::link(
                MnPress::MainLink,
                text::MANAGE_MNEMONICS.get(lang),
            ));
        }
        items.push(Item::Row(row));
    }

    /// The `내 계정` / `내 Solana 계정` help (2026-11-10): a wallet without recovery words that has
    /// `YubiKey` cards says where their keys' backup is (not the key-only text); a wallet with
    /// words and `YubiKey` accounts says that those come back with the card's own words. Since
    /// 2026-11-12 only what is not backed up by this wallet's words is said: an imported key
    /// always gets its reminder, and a wallet of derived accounts only has no paragraph.
    #[must_use]
    pub(crate) fn accounts_help(&self, has_card: bool, imported: bool) -> Option<String> {
        let lang = self.settings.language;
        if self.key_only() && !self.card.records.is_empty() {
            return Some(if imported {
                format!(
                    "{} {}",
                    T_ACCOUNTS_YUBIKEY.get(lang),
                    T_ACCOUNTS_IMPORTED.get(lang)
                )
            } else {
                T_ACCOUNTS_YUBIKEY.get(lang).to_owned()
            });
        }
        if self.key_only() {
            return Some(T_ACCOUNTS_KEY_ONLY.get(lang).to_owned());
        }
        match (imported, has_card) {
            (true, true) => Some(format!(
                "{} {}",
                T_ACCOUNTS_BACKUP.get(lang),
                T_ACCOUNTS_YUBIKEY_WORDS.get(lang)
            )),
            (true, false) => Some(T_ACCOUNTS_BACKUP.get(lang).to_owned()),
            (false, true) => Some(T_ACCOUNTS_YUBIKEY_WORDS.get(lang).to_owned()),
            (false, false) => None,
        }
    }

    /// The backup status of a wallet whose first recovery phrase is not its only backup
    /// (2026-11-08, settings → 보안): one line per recovery phrase (words, passphrase, quiz),
    /// the imported keys, and one per `YubiKey` key (2026-11-10). Empty for a wallet with one
    /// phrase only.
    #[must_use]
    pub fn backup_status_lines(&self) -> Vec<String> {
        if !self.several_mnemonics()
            && self.imported_key_count() == 0
            && self.card.records.is_empty()
        {
            return Vec::new();
        }
        self.backup_status_all()
    }

    /// The imported keys of every chain.
    fn imported_key_count(&self) -> usize {
        self.meta.as_ref().map_or(0, |meta| {
            meta.evm_raw_accounts.len()
                + meta.sol_raw_accounts.len()
                + meta
                    .btc_accounts
                    .accounts
                    .iter()
                    .filter(|account| account.is_imported())
                    .count()
        })
    }

    /// [`Self::backup_status_lines`] of any wallet (a wallet without recovery words included:
    /// settings → 보안 and S22 show it always, 2026-11-10).
    #[must_use]
    pub fn backup_status_all(&self) -> Vec<String> {
        let lang = self.settings.language;
        let imported = self.imported_key_count();
        let mut lines = Vec::new();
        for info in &self.mn.infos {
            lines.push(text::BACKUP_STATUS_PHRASE.fill(
                lang,
                [
                    &self.mnemonic_label(info.id),
                    &info.words.to_string(),
                    if info.passphrase_used {
                        " + passphrase"
                    } else {
                        ""
                    },
                    if info.primary {
                        text::BACKUP_STATUS_FIRST.get(lang)
                    } else {
                        ""
                    },
                    if info.backup_confirmed {
                        text::BACKUP_CONFIRMED.get(lang)
                    } else {
                        text::BACKUP_NOT_CONFIRMED.get(lang)
                    },
                ],
            ));
        }
        if imported > 0 {
            lines.push(text::BACKUP_STATUS_IMPORTED.fill(lang, [&imported.to_string()]));
        }
        // One line per card key (2026-11-10): where it is, and whether recovery words make it
        // again (a key connected without words is only on its cards).
        let mut seen: Vec<(yw_core::yubikey::plan::Curve, Vec<u32>)> = Vec::new();
        for record in &self.card.records {
            for slot in &record.slots {
                let identity = slot.role.key_identity();
                if seen.contains(&identity) {
                    continue;
                }
                seen.push(identity);
                let holders = crate::yubikey::holders(&self.card.records, slot.role);
                let cards = self.card_name_list(&holders, "·");
                let title = slot.role.title_in(lang);
                lines.push(
                    if yw_core::yubikey::plan::is_unknown_index(slot.role.index()) {
                        if holders.len() > 1 {
                            text::BACKUP_STATUS_CARD_ON.fill(lang, [&title, &cards])
                        } else {
                            text::BACKUP_STATUS_CARD_ONLY.fill(lang, [&title, &cards])
                        }
                    } else {
                        text::BACKUP_STATUS_CARD_WORDS.fill(lang, [&title, &cards])
                    },
                );
            }
        }
        lines
    }
}

/// The one line under the settings tabs, only where something people look for in this section
/// lives elsewhere (spec/04 §2.11). The list of the section's cards that used to open every
/// section ("이 구역: …") repeated the card headings right below it and is gone (2026-11-12).
#[must_use]
pub const fn settings_elsewhere(lang: Lang, section: SettingsSection) -> Option<&'static str> {
    let text = match section {
        SettingsSection::Security => text::ELSEWHERE_SECURITY,
        SettingsSection::Chains => text::ELSEWHERE_CHAINS,
        SettingsSection::Bitcoin => text::ELSEWHERE_BITCOIN,
        SettingsSection::YubiKey => text::ELSEWHERE_YUBIKEY,
        SettingsSection::Other => text::ELSEWHERE_OTHER,
        SettingsSection::Network
        | SettingsSection::Solana
        | SettingsSection::Ai
        | SettingsSection::Mnemonics => return None,
    };
    Some(text.get(lang))
}

/// The items of the current screen.
impl super::Screen<'_> {
    /// Builds the current screen as the neutral screen model (spec/15 §11.3).
    #[must_use]
    pub fn screen_model(&self) -> Vec<Item> {
        let lang = self.settings.language;
        let mut items = Vec::new();
        if self.screen == Screen::Main {
            items.push(Item::Toolbar(
                "Your Wallet".to_owned(),
                vec![
                    Ctl::button(EvmPress::BookOpen, text::ADDRESS_BOOK.get(lang)),
                    Ctl::button(SitesPress::Open, text::SITES_WC.get(lang)),
                    // Shortcuts in the tooltips (2026-11-12; "잠금 (Ctrl+L)" in the label before).
                    Ctl::button(CorePress::OpenSettings, text::SETTINGS.get(lang))
                        .tip(text::SETTINGS_TIP.get(lang)),
                    Ctl::button(CorePress::Lock, text::LOCK.get(lang))
                        .tip(text::LOCK_TIP.get(lang)),
                ],
            ));
        }
        header(self, &mut items);
        match &self.screen {
            Screen::Starting => items.push(Item::Muted(text::STARTING.get(lang).to_owned())),
            Screen::FirstRun => self.first_run(&mut items),
            Screen::CreateIntro => Self::create_intro(lang, &mut items),
            Screen::Processing(text) => {
                items.push(Item::Gap(40));
                items.push(Item::CardStart(None));
                items.push(Item::Subtitle(text::PLEASE_WAIT.get(lang).to_owned()));
                items.push(Item::Text((*text).to_owned()));
                items.push(Item::CardEnd);
                if self.wait.stalled {
                    self.wait_stalled(&mut items);
                }
            }
            Screen::BackupPending => Self::backup_pending(lang, &mut items),
            Screen::Reset => self.reset_screen(&mut items),
            Screen::Extension => self.extension_screen(&mut items),
            Screen::HyperCore => self.hc_screen(&mut items),
            Screen::ImportIntro => Self::import_intro(lang, &mut items),
            Screen::ImportAddress(address) => Self::import_address(lang, address, &mut items),
            Screen::Locked => self.locked(&mut items),
            Screen::PassMismatch => self.pass_mismatch(&mut items),
            Screen::Done => self.done(&mut items),
            Screen::Recovery => self.recovery(&mut items),
            Screen::Main => self.main_screen(&mut items),
            Screen::Settings(section) => self.settings_screen(*section, &mut items),
            Screen::Confirm(kind) => self.confirm(*kind, &mut items),
            Screen::Send => self.send_screen(&mut items),
            Screen::SendResult => self.send_result_screen(&mut items),
            Screen::Receive => self.receive_screen(&mut items),
            Screen::AddressBook => self.book_screen(&mut items),
            Screen::TokenAdd => self.token_screen(&mut items),
            Screen::ChainEdit => self.chain_edit_screen(&mut items),
            Screen::Sites => self.sites_screen(&mut items),
            Screen::SolSend => self.sol_send_screen(&mut items),
            Screen::SolSendResult => self.sol_send_result_screen(&mut items),
            Screen::SolReceive => self.sol_receive_screen(&mut items),
            Screen::SolScan => self.sol_scan_screen(&mut items),
            Screen::BtcSend => self.btc_send_screen(&mut items),
            Screen::BtcSendResult => self.btc_send_result_screen(&mut items),
            Screen::BtcBump => self.btc_bump_screen(&mut items),
            Screen::BtcReceive => self.btc_receive_screen(&mut items),
            Screen::KeyStartIntro => self.key_start_intro(&mut items),
            Screen::KeyStartAddress(view) => self.key_start_address(view, &mut items),
            Screen::YubiKey => self.yk_wizard_screen(&mut items),
            Screen::YubiKeyWalletIntro => self.yk_wallet_intro(&mut items),
        }
        if self.passphrase_unverified() {
            crate::screen::model::disable_receive(&mut items);
        }
        // The copy just made says so at its own control (2026-11-12, `Wallet::copy_text`).
        // 2026-11-20 (S4 P6): the mark holds the press. 2026-11-24 (S5-4): the control is found
        // by that press in the model (before, by `cmd_table::id_of(press)` in the Windows list).
        if let Some(copied) = self.copied {
            crate::screen::model::mark_copied(lang, &mut items, copied.anchor, copied.address);
        }
        items
    }

    fn first_run(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Gap(24));
        items.push(Item::Display("Your Wallet".to_owned()));
        items.push(Item::Gap(4));
        // The first two sentences are true for every path; the third (24 words are the only
        // backup) belongs to the new-wallet card (2026-11-08).
        for sentence in &T_FIRST[..2] {
            items.push(Item::Text(sentence.get(lang).to_owned()));
        }
        items.push(Item::Gap(8));
        if self.leftover {
            items.push(Item::Banner(
                text::LEFTOVER.get(lang).to_owned(),
                Tone::Warn,
            ));
            items.push(Item::Mono(self.facts().data_dir()));
            let mut row = Vec::new();
            if self.facts().flags().open_folders {
                row.push(Ctl::button(
                    CorePress::OpenDataFolder,
                    text::OPEN_FOLDER.get(lang),
                ));
            }
            row.push(Ctl::link(ResetPress::Open, text::LEFTOVER_MOVE.get(lang)));
            items.push(Item::Row(row));
        }
        // Two groups (2026-11-08): start something new, or bring back a wallet already used;
        // all five ways are on the first view of the default window.
        let enabled = !self.leftover;
        items.push(Item::CardStart(Some(
            text::FIRST_NEW_TITLE.get(lang).to_owned(),
        )));
        items.push(Item::Text(text::FIRST_NEW_TEXT.get(lang).to_owned()));
        items.push(Item::Help(T_FIRST[2].get(lang).to_owned()));
        items.push(Item::Row(vec![
            Ctl::primary(CorePress::FirstCreate, text::CREATE_WALLET.get(lang)).enabled(enabled),
            Ctl::button(YkPress::NewWallet, text::FIRST_YK_WALLET.get(lang)).enabled(enabled),
        ]));
        items.push(Item::Help(text::FIRST_YK_WALLET_HELP.fill(
            lang,
            [crate::wallet::app_yubikey::text::YK_WALLET.get(lang)],
        )));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            text::FIRST_EXISTING_TITLE.get(lang).to_owned(),
        )));
        items.push(Item::Row(vec![
            Ctl::button(CorePress::FirstImport, text::FIRST_IMPORT.get(lang)).enabled(enabled),
            Ctl::button(KeysPress::FirstKey, text::FIRST_KEY.get(lang)).enabled(enabled),
            Ctl::button(YkConnectPress::NewWallet, text::FIRST_YK_CONNECT.get(lang))
                .enabled(enabled),
        ]));
        for line in [
            text::FIRST_IMPORT_HELP.get(lang).to_owned(),
            text::FIRST_KEY_HELP.fill(
                lang,
                [crate::screen::build::keys::text::KEY_START_CARD.get(lang)],
            ),
            text::FIRST_YK_CONNECT_HELP.get(lang).to_owned(),
        ] {
            items.push(Item::Help(line));
        }
        items.push(Item::CardEnd);
    }

    fn create_intro(lang: Lang, items: &mut Vec<Item>) {
        items.push(Item::Title(text::CREATE_WALLET.get(lang).to_owned()));
        items.push(steps(CREATE_STEPS.map(|step| step.get(lang)), 0));
        items.push(Item::CardStart(Some(
            text::BEFORE_START.get(lang).to_owned(),
        )));
        for line in [
            text::CREATE_INTRO_1,
            text::CREATE_INTRO_2,
            text::CREATE_INTRO_3,
        ] {
            items.push(Item::Text(line.get(lang).to_owned()));
        }
        items.push(Item::Help(text::CREATE_INTRO_HELP.get(lang).to_owned()));
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::primary(CorePress::CreateNext, text::START.get(lang)),
            Ctl::button(CorePress::IntroCancel, text::CANCEL.get(lang)),
        ]));
    }

    fn backup_pending(lang: Lang, items: &mut Vec<Item>) {
        items.push(Item::Title(text::BACKUP_PENDING_TITLE.get(lang).to_owned()));
        items.push(Item::Banner(
            text::BACKUP_PENDING_BANNER.get(lang).to_owned(),
            Tone::Warn,
        ));
        items.push(Item::CardStart(None));
        items.push(Item::Text(text::BACKUP_PENDING_TEXT.get(lang).to_owned()));
        items.push(Item::Row(vec![
            Ctl::primary(CorePress::BackupCheck, text::BACKUP_CHECK.get(lang)),
            Ctl::button(EvmPress::ReceiveOpen, text::RECEIVE.get(lang)),
            Ctl::button(CorePress::Lock, text::LOCK.get(lang)),
        ]));
        items.push(Item::CardEnd);
        Self::reset_link(lang, items, text::BACKUP_PENDING_RESET.get(lang));
    }

    fn import_intro(lang: Lang, items: &mut Vec<Item>) {
        items.push(Item::Title(text::IMPORT_WALLET.get(lang).to_owned()));
        items.push(steps(IMPORT_STEPS.map(|step| step.get(lang)), 0));
        items.push(Item::CardStart(Some(
            text::IMPORT_NEED_TITLE.get(lang).to_owned(),
        )));
        items.push(Item::Text(text::IMPORT_NEED_WORDS.get(lang).to_owned()));
        items.push(Item::Text(
            text::IMPORT_NEED_PASSPHRASE.get(lang).to_owned(),
        ));
        items.push(Item::Help(text::IMPORT_KEY_HINT.get(lang).to_owned()));
        items.push(Item::Help(
            crate::wallet::app_btc::BTC_IMPORT_NOTE.get(lang).to_owned(),
        ));
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::primary(CorePress::ImportNext, text::START.get(lang)),
            Ctl::button(CorePress::IntroCancel, text::CANCEL.get(lang)),
        ]));
    }

    fn import_address(lang: Lang, address: &str, items: &mut Vec<Item>) {
        items.push(Item::Title(
            crate::wallet::text::STEP_FIRST_ADDRESS.get(lang).to_owned(),
        ));
        items.push(steps(IMPORT_STEPS.map(|step| step.get(lang)), 3));
        items.push(Item::CardStart(None));
        items.push(Item::Text(text::IMPORT_ADDRESS_TEXT.get(lang).to_owned()));
        let shown = yw_core::evm::address::parse_address(address)
            .map_or_else(|_| address.to_owned(), |parsed| format_address(&parsed));
        items.push(Item::Mono(shown));
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::primary(CorePress::ImportCorrect, text::IMPORT_CORRECT.get(lang)),
            Ctl::button(CorePress::ImportWrong, text::IMPORT_WRONG.get(lang)),
        ]));
        items.push(Item::Help(text::IMPORT_ADDRESS_HELP.get(lang).to_owned()));
    }

    fn locked(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Gap(48));
        items.push(Item::Display(text::LOCKED_TITLE.get(lang).to_owned()));
        items.push(Item::Text(text::LOCKED_TEXT.get(lang).to_owned()));
        if let Some(pending) = self.unlock_pending_text() {
            items.push(Item::Banner(pending, Tone::Info));
        }
        // The screen's one action, wider than a default button; the way out for a lost password
        // is a single row at the bottom (2026-11-12).
        items.push(Item::Gap(4));
        items.push(Item::Row(vec![
            Ctl::primary(CorePress::Unlock, text::UNLOCK.get(lang)).width(160),
        ]));
        items.push(Item::Help(
            text::LOCKED_AUTO_LOCK.fill(lang, [&self.settings.auto_lock_minutes.to_string()]),
        ));
        if let Some((generation, written)) = self.guard.vault_file {
            items.push(Item::Muted(vault_file_text(
                &self.facts(),
                lang,
                generation,
                written,
            )));
        }
        if self.unlock_failed && self.prev_on_disk && self.mode == AppMode::Locked {
            // spec/02 §6.3: a damaged key section is indistinguishable from a wrong password.
            items.push(Item::Gap(8));
            items.push(Item::Help(text::LOCKED_DAMAGED.get(lang).to_owned()));
            items.push(Item::Row(vec![Ctl::link(
                CorePress::Recover,
                text::RECOVER_PREV.get(lang),
            )]));
        }
        // What a reset does (the files are moved, not deleted) is the first band of S22.
        items.push(Item::Gap(16));
        items.push(Item::LabeledRow(
            text::FORGOT_PASSWORD.get(lang).to_owned(),
            vec![Ctl::link(ResetPress::Open, text::RESET_WALLET.get(lang))],
        ));
    }

    fn pass_mismatch(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Title(text::MISMATCH_TITLE.get(lang).to_owned()));
        items.push(Item::Banner(
            text::MISMATCH_BANNER.get(lang).to_owned(),
            Tone::Warn,
        ));
        items.push(Item::CardStart(None));
        items.push(Item::Row(vec![Ctl::check(
            CorePress::MismatchCheck(None),
            text::MISMATCH_CHECK.get(lang),
            self.mismatch_checked,
        )]));
        items.push(Item::Row(vec![
            Ctl::primary(CorePress::MismatchRetry, text::MISMATCH_RETRY.get(lang)),
            Ctl::button(
                CorePress::MismatchContinue,
                text::MISMATCH_CONTINUE.get(lang),
            )
            .enabled(self.mismatch_checked),
        ]));
        items.push(Item::CardEnd);
    }

    fn done(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Title(text::DONE_TITLE.get(lang).to_owned()));
        if let Some(done) = self.done_yubikey {
            let (banner, backup) = match done {
                crate::wallet::app_yubikey::YkDone::Created(serial) => (
                    text::DONE_YK_CREATED.fill(lang, [&self.card_name(serial)]),
                    text::DONE_YK_CREATED_BACKUP,
                ),
                crate::wallet::app_yubikey::YkDone::Connected(serial) => (
                    text::DONE_YK_CONNECTED.fill(lang, [&self.card_name(serial)]),
                    text::DONE_YK_CONNECTED_BACKUP,
                ),
            };
            items.push(Item::Banner(banner, Tone::Success));
            items.push(Item::Help(backup.get(lang).to_owned()));
        } else if self.keys.done_start {
            items.push(Item::Banner(
                crate::screen::build::keys::text::KEY_START_OK
                    .get(self.settings.language)
                    .to_owned(),
                Tone::Success,
            ));
            items.push(Item::Banner(
                crate::screen::build::keys::text::KEY_START_BACKUP
                    .get(self.settings.language)
                    .to_owned(),
                Tone::Warn,
            ));
        } else if self.done_imported {
            // No backup check runs on import: the words came from the user's existing backup.
            items.push(Item::Banner(
                text::DONE_IMPORTED.get(lang).to_owned(),
                Tone::Success,
            ));
            items.push(Item::Help(text::DONE_IMPORTED_BACKUP.get(lang).to_owned()));
        } else {
            items.push(Item::Banner(
                text::DONE_BACKUP_OK.get(lang).to_owned(),
                Tone::Success,
            ));
        }
        // One '처음 설정' card (2026-11-10): RPC, the optional dApp connection, a first small
        // deposit; `지갑 열기` always below it.
        items.push(Item::CardStart(Some(text::DONE_SETUP.get(lang).to_owned())));
        self.done_rpc_items(items);
        items.push(Item::Rule);
        self.done_dapp_items(items);
        items.push(Item::Rule);
        self.done_deposit_items(items);
        items.push(Item::CardEnd);
        if self.done_imported || self.keys.done_start {
            self.done_balance_card(items);
        }
        items.push(Item::Row(vec![Ctl::primary(
            CorePress::DoneContinue,
            text::DONE_OPEN_WALLET.get(lang),
        )]));
    }

    /// S08 ① 블록체인 연결(RPC): the `QuickNode` address field while there is no address, the
    /// results of `연결하기`, or how many addresses there are and this run's tests.
    fn done_rpc_items(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Subtitle(text::DONE_RPC_TITLE.get(lang).to_owned()));
        if !self.done_tested.is_empty() {
            self.done_results(items);
            return;
        }
        if !self.apikeys.endpoints().is_empty() {
            let (configured, _, works, failed, _) = self.rpc_summary();
            items.push(Item::Text(text::DONE_RPC_SUMMARY.fill(
                lang,
                [
                    &configured.to_string(),
                    &works.to_string(),
                    &failed.to_string(),
                ],
            )));
            items.push(Item::Row(vec![Ctl::button(
                CorePress::DoneRpc,
                text::OPEN_RPC_SETTINGS.get(lang),
            )]));
            return;
        }
        items.push(Item::Text(text::DONE_RPC_NEED.get(lang).to_owned()));
        if self.settings.rpc_template == RpcTemplate::QuickNode {
            items.push(Item::LabeledRow(
                text::QUICKNODE_ADDRESS.get(lang).to_owned(),
                vec![Ctl::edit(CredField::DoneQn, "", 520, true, 256)],
            ));
            items.push(Item::Help(text::T_DONE_QUICKNODE.get(lang).to_owned()));
            if let Some(error) = &self.done_error {
                items.push(Item::Banner(error.clone(), Tone::Danger));
            }
            items.push(Item::Row(vec![
                Ctl::primary(CorePress::DoneConnect, text::DONE_CONNECT.get(lang)),
                Ctl::link(CorePress::DoneRpc, text::DONE_OTHER_PROVIDERS.get(lang)),
            ]));
        } else {
            items.push(Item::Help(text::DONE_PROVIDER_HELP.get(lang).to_owned()));
            items.push(Item::Row(vec![Ctl::button(
                CorePress::DoneRpc,
                text::DONE_SET_RPC.get(lang),
            )]));
        }
        if self.facts().flags().rpc_json_import && self.facts().rpc_json_present() {
            items.push(Item::Row(vec![Ctl::link(
                CorePress::DoneRpcJson,
                text::DONE_RPC_JSON.get(lang),
            )]));
        }
    }

    /// S08 after `연결하기`: one line per network made (✓ works / ✗ with its §7 text and a link to
    /// its row / … testing), then the count — with how many are still being tested, so a short
    /// count while the queue runs does not read as failures.
    fn done_results(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let networks = self.url_networks();
        let mut works = 0_usize;
        let mut testing = 0_usize;
        let mut failed = false;
        for network in &self.done_tested {
            let name = self.network_name(*network);
            match self
                .rpc_messages
                .iter()
                .find(|(id, _, _)| id == network)
                .map(|(_, message, state)| (message, *state))
            {
                Some((_, TestState::Works)) => {
                    works = works.saturating_add(1);
                    items.push(Item::Text(format!("✓ {name}")));
                }
                Some((message, TestState::Failed)) => {
                    failed = true;
                    items.push(Item::Banner(format!("✗ {name} — {message}"), Tone::Danger));
                    if let Some(row) = networks
                        .iter()
                        .position(|known| known == network)
                        .and_then(|row| u16::try_from(row).ok())
                        .filter(|row| *row < rows::RPC_ROW_OPENS)
                    {
                        items.push(Item::Row(vec![Ctl::link(
                            CorePress::RpcRowOpen(Row(row)),
                            &text::OPEN_ROW.fill(lang, [&name]),
                        )]));
                    }
                }
                Some((_, TestState::Testing)) | None => {
                    testing = testing.saturating_add(1);
                    items.push(Item::Muted(text::TESTING_NAME.fill(lang, [&name])));
                }
            }
        }
        let total = self.done_tested.len();
        let (total, works) = (total.to_string(), works.to_string());
        items.push(Item::Subtitle(if testing == 0 {
            text::WORKS_OF.fill(lang, [&total, &works])
        } else {
            text::WORKS_OF_TESTING.fill(lang, [&total, &works, &testing.to_string()])
        }));
        if failed {
            items.push(Item::Help(text::DONE_FAILED_HELP.get(lang).to_owned()));
        }
        items.push(Item::Row(vec![Ctl::button(
            CorePress::DoneRpc,
            text::OPEN_RPC_SETTINGS.get(lang),
        )]));
    }

    /// S08 ② dApp 연결 (선택): the Chrome extension or `WalletConnect`.
    fn done_dapp_items(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Subtitle(text::DONE_DAPP_TITLE.get(lang).to_owned()));
        if self.facts().flags().browser_extension {
            items.push(Item::Text(
                text::CHROME_EXTENSION_STATUS.fill(lang, [self.extension_status().text_in(lang)]),
            ));
            items.push(Item::Row(vec![Ctl::button(
                ExtPress::Open,
                text::HOW_TO_INSTALL.get(lang),
            )]));
        }
        items.push(Item::Text(format!(
            "WalletConnect: {}",
            if self.settings.walletconnect_project.is_empty() {
                text::NO_PROJECT_ID.get(lang)
            } else {
                text::CONFIGURED.get(lang)
            }
        )));
        items.push(Item::Row(vec![Ctl::button(
            CorePress::DoneWc,
            text::SETTINGS.get(lang),
        )]));
    }

    /// S08 ③ 첫 입금 시험: receive on the wallet's first chain (EVM when it has an account).
    fn done_deposit_items(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Subtitle(
            text::DONE_DEPOSIT_TITLE.get(lang).to_owned(),
        ));
        let evm = self.selected_account().is_some();
        let mut line = text::DONE_DEPOSIT_TEXT.get(lang).to_owned();
        if evm {
            if self.settings.evm_chain_id == SEPOLIA {
                line.push_str(text::DONE_DEPOSIT_SEPOLIA.get(lang));
            } else {
                line.push_str(&text::DONE_DEPOSIT_NETWORK.fill(
                    lang,
                    [&self.network_name(NetworkId::Eip155(self.settings.evm_chain_id))],
                ));
            }
        }
        items.push(Item::Text(line));
        let receive = if evm {
            Some(Press::Evm(EvmPress::ReceiveOpen))
        } else if self.sol_selected().is_some() {
            Some(Press::Sol(SolPress::ReceiveOpen))
        } else if self.settings.bitcoin.enabled {
            Some(Press::Btc(BtcPress::ReceiveOpen))
        } else {
            None
        };
        if let Some(press) = receive {
            items.push(Item::Row(vec![Ctl::button(press, text::RECEIVE.get(lang))]));
        }
    }

    /// S08 after an import or "개인키로 시작하기": why a wallet that held funds may show none
    /// (the network, accounts not searched, chains off).
    fn done_balance_card(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let mut lines: Vec<Item> = Vec::new();
        if self.selected_account().is_some() {
            if self.settings.evm_chain_id == SEPOLIA {
                lines.push(Item::Text(text::DONE_BALANCE_SEPOLIA.get(lang).to_owned()));
                lines.push(Item::Row(vec![Ctl::button(
                    CorePress::DoneMainnet,
                    text::DONE_SHOW_MAINNET.get(lang),
                )]));
            } else {
                lines.push(Item::Text(text::DONE_BALANCE_NETWORK.fill(
                    lang,
                    [&self.network_name(NetworkId::Eip155(self.settings.evm_chain_id))],
                )));
            }
        }
        if self.done_imported {
            lines.push(Item::Text(text::DONE_BALANCE_ACCOUNTS.get(lang).to_owned()));
            let bitcoin = !self.settings.bitcoin.enabled;
            let zcash = !self.settings.zcash.enabled;
            let off = match (bitcoin, zcash) {
                (true, true) => Some(text::DONE_OFF_BOTH),
                (true, false) => Some(text::DONE_OFF_BITCOIN),
                (false, true) => Some(text::DONE_OFF_ZCASH),
                (false, false) => None,
            };
            if let Some(line) = off {
                lines.push(Item::Text(line.get(lang).to_owned()));
            }
        }
        if lines.is_empty() {
            return;
        }
        items.push(Item::CardStart(Some(
            text::DONE_NO_BALANCE.get(lang).to_owned(),
        )));
        items.extend(lines);
        items.push(Item::CardEnd);
    }

    fn recovery(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Title(text::RECOVERY_TITLE.get(lang).to_owned()));
        items.push(Item::CardStart(None));
        let prev = match self.mode {
            AppMode::Corrupt { prev_available } => {
                let code = if self.payload_damaged {
                    ErrorCode::Vlt008
                } else {
                    ErrorCode::Vlt002
                };
                items.push(Item::Banner(code.text_in(lang), Tone::Danger));
                prev_available
            }
            AppMode::MainMissing => {
                items.push(Item::Text(text::RECOVERY_MISSING.get(lang).to_owned()));
                true
            }
            _ => false,
        };
        if prev {
            items.push(Item::Help(text::RECOVERY_PREV_HELP.get(lang).to_owned()));
        }
        items.push(Item::Field(
            text::DATA_FOLDER.get(lang).to_owned(),
            self.facts().data_dir(),
        ));
        let mut row = Vec::new();
        if prev {
            row.push(Ctl::primary(
                CorePress::Recover,
                text::RECOVERY_RESTORE.get(lang),
            ));
        }
        if self.facts().flags().open_folders {
            row.push(Ctl::button(
                CorePress::OpenDataFolder,
                text::OPEN_FOLDER.get(lang),
            ));
        }
        row.push(Ctl::button(CorePress::Exit, text::EXIT.get(lang)));
        items.push(Item::Row(row));
        items.push(Item::CardEnd);
        items.push(Item::Help(
            text::RECOVERY_NEVER_DELETES.get(lang).to_owned(),
        ));
        Self::reset_link(lang, items, text::RECOVERY_RESET.get(lang));
    }

    /// The selected EVM account's hero card: name, big balance, address, 보내기 / 받기.
    #[expect(
        clippy::too_many_lines,
        reason = "the hero card's balance states in order"
    )]
    fn evm_hero(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let chain_id = self.settings.evm_chain_id;
        let Some((address, source, label)) = self.selected_account() else {
            return;
        };
        items.push(Item::CardStart(None));
        items.push(Item::Subtitle(self.evm_account_title(source, &label)));
        items.push(Item::Help(self.evm_path_text(source)));
        self.mn_signing_banner(self.evm_backup_gate(source), items);
        self.card_pin_banner(self.evm_card_gate(source), items);
        let balance = self.native_balance(chain_id, &address);
        let state = self.evm.balances.get(&chain_id);
        let endpoint = self.apikeys.has(KeyName::Rpc(NetworkId::Eip155(chain_id)));
        let blocked = self.evm.blocked(chain_id).is_some();
        let error = state.and_then(|state| state.error);
        let block = state
            .and_then(|state| state.snapshot.as_ref())
            .map(|snapshot| snapshot.block);
        // Three states under the big balance (2026-11-10): loading, read at block N, or failed —
        // the failure is explained once, by the network card above (`evm_balance_failure`).
        match (balance, error) {
            (Some(value), Some(code)) if blocked => {
                // A blocked chain keeps its band and this caption (U17 and E-RPC-006 as before).
                items.push(Item::Display(self.native_text(chain_id, &value)));
                if let Some(block) = block {
                    items.push(Item::Help(
                        text::AT_BLOCK_FAILED.fill(lang, [&block.to_string(), code.code()]),
                    ));
                }
            }
            (Some(value), Some(_)) => {
                // The earlier value, dimmed, and where it is from (2026-11-12: not "잔액을
                // 읽지 못했습니다" under a balance).
                items.push(Item::DisplayMuted(self.native_text(chain_id, &value)));
                items.push(Item::Help(balance_stale_text(
                    &self.facts(),
                    lang,
                    block,
                    state.and_then(|state| state.updated_unix_ms),
                )));
            }
            (Some(value), None) => {
                items.push(Item::Display(self.native_text(chain_id, &value)));
                if let Some(block) = block {
                    items.push(Item::Help(balance_read_text(
                        &self.facts(),
                        lang,
                        Some(block),
                        state.and_then(|state| state.updated_unix_ms),
                    )));
                }
            }
            (None, _) if !endpoint => {
                items.push(Item::Display(text::BALANCE_NONE.get(lang).to_owned()));
                items.push(Item::Help(no_endpoint_text(
                    lang,
                    &self.network_name(NetworkId::Eip155(chain_id)),
                )));
            }
            (None, Some(_)) if !blocked => {
                items.push(Item::Display(text::BALANCE_NONE.get(lang).to_owned()));
                items.push(Item::Help(T_BALANCE_FAILED.get(lang).to_owned()));
            }
            (None, Some(_)) => {
                items.push(Item::Display(text::BALANCE_NONE.get(lang).to_owned()));
                items.push(Item::Help(text::BALANCE_NOT_YET.get(lang).to_owned()));
            }
            (None, None) => {
                items.push(Item::Display(text::BALANCE_NONE.get(lang).to_owned()));
                items.push(Item::Help(T_BALANCE_LOADING.get(lang).to_owned()));
            }
        }
        // The visible tokens with a balance, like the Solana tab's one-line summary.
        let tokens: Vec<String> = self
            .evm_token_rows(chain_id)
            .iter()
            .filter(|row| row.place == crate::token_view::RowPlace::Shown)
            .filter_map(|row| {
                row.balance.filter(|value| !value.is_zero()).map(|value| {
                    yw_core::evm::amount::format_amount(&value, row.decimals, &row.symbol)
                })
            })
            .take(4)
            .collect();
        if !tokens.is_empty() {
            items.push(Item::Help(
                text::TOKENS_LINE.fill(lang, [&tokens.join(" · ")]),
            ));
        }
        // The own address whole, its ends emphasized, with `주소 복사` on the same line
        // (2026-11-11; recipient checks elsewhere keep the grouped form).
        items.push(self.own_address_line(
            NetworkId::Eip155(chain_id),
            &address.to_checksum(),
            AddressKind::Evm,
            EvmPress::CopyAddress,
            true,
            ExplorerPress::CardEvm,
        ));
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        let mut row = vec![
            Ctl::primary(EvmPress::SendOpen, text::SEND.get(lang)).enabled(unlocked),
            Ctl::primary(EvmPress::ReceiveOpen, text::RECEIVE.get(lang)),
        ];
        if endpoint {
            row.push(
                Ctl::link(EvmPress::Refresh, text::REFRESH.get(lang)).tip(T_REFRESH_TIP.get(lang)),
            );
        } else {
            // Nothing to refresh without an address: that network's row with its field open
            // (spec/04 §2.6, 2026-11-10).
            row.push(Ctl::button(
                CorePress::EvmRpcOpen,
                text::DONE_SET_RPC.get(lang),
            ));
        }
        items.push(Item::Row(row));
        items.push(Item::CardEnd);
    }

    #[expect(clippy::too_many_lines, reason = "the S10 sections in order")]
    fn main_screen(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        // T-ALT-PASS is drawn by `header` on every screen.
        self.tab_row(items);
        if self.sol_tab_active() {
            // The cluster band is the tab's own (`sol_cluster_banner`, one per screen; 2026-11-10:
            // a second T-MAINNET above the tab was drawn here since 11-08).
            self.sol_main_screen(items);
            return;
        }
        if self.zec_tab_active() {
            self.zec_main_screen(items);
            return;
        }
        if self.btc_tab_active() {
            // Imported keys are accounts of the Bitcoin account list (a key-only wallet has
            // only those).
            self.btc_main_screen(items);
            return;
        }
        items.push(Item::CardStart(None));
        // One drop-down instead of a grid of chips (2026-11-11): the selected network with its
        // badge, and the network tag on the same line; open, the list hangs under it (each
        // entry is the chip of before: same ids, same handler).
        let selected = self.settings.evm_chain_id;
        let open = self.evm.network_picker;
        let chains = self.settings.registered_evm();
        let labels: Vec<String> = chains
            .iter()
            .take(usize::from(rows::NETWORKS))
            .map(|chain_id| self.network_choice_label(*chain_id))
            .collect();
        items.push(Item::LabeledRow(
            text::NETWORK.get(lang).to_owned(),
            vec![
                Ctl::picker(
                    EvmPress::NetworkPicker,
                    &self.network_choice_label(selected),
                    open,
                )
                .badge(self.evm_badge(selected))
                .fit(labels.iter().map(String::as_str)),
            ],
        ));
        if selected == SEPOLIA {
            items.push(Item::Pill(
                text::TESTNET_PILL.get(lang).to_owned(),
                Tone::Testnet,
            ));
        } else if yw_core::evm::chain::is_builtin_mainnet(selected) {
            // The built-in mainnets (user chains carry no testnet flag, so no tag).
            items.push(Item::Pill(T_MAINNET.get(lang).to_owned(), Tone::BtcMainnet));
        }
        if open {
            items.push(Item::Menu(
                chains
                    .iter()
                    .take(usize::from(rows::NETWORKS))
                    .enumerate()
                    .map(|(index, chain_id)| {
                        Ctl::entry(
                            CorePress::Network(Row(u16::try_from(index).unwrap_or(0))),
                            &self.network_choice_label(*chain_id),
                            *chain_id == selected,
                        )
                        .badge(self.evm_badge(*chain_id))
                    })
                    .collect(),
            ));
        }
        self.evm_banners(items);
        self.evm_balance_failure(items);
        items.push(Item::Help(self.evm_status_line()));
        items.push(Item::CardEnd);
        if self.account_rows().is_empty() && self.meta.is_some() {
            self.no_accounts_card(yw_core::keyimport::ImportChain::Evm, items);
            return;
        }
        self.evm_hero(items);
        // The shared account card (2026-11-15, `screen::build::accounts`): a drop-down like the
        // network's (2026-11-11) whose items read `label · source`; the selected account's
        // actions follow (2026-11-12: its path, balance and address are the hero card's).
        let selected = self.selected_pref();
        let mut accounts = Vec::new();
        let mut chosen = None;
        for (row, (pref, label, ..)) in self
            .account_rows()
            .into_iter()
            .take(usize::from(rows::EVM_ACCOUNTS))
            .enumerate()
        {
            let is_selected = selected == Some(pref);
            let source = match pref {
                EvmAccountPref::Record(_) => AccountSource::Imported,
                EvmAccountPref::Hardware(index) => {
                    AccountSource::Card(crate::screen::evm_card_role(index))
                }
                EvmAccountPref::Index(_) => AccountSource::Words(None),
                EvmAccountPref::Mnemonic(id, _) => AccountSource::Words(Some(id)),
            };
            if is_selected {
                chosen = Some((pref, label.clone()));
            }
            accounts.push(AccountItem {
                press: CorePress::Account(Row(u16::try_from(row).unwrap_or(0))).into(),
                label,
                source,
                selected: is_selected,
                enabled: true,
            });
        }
        let selected = chosen.map(|(pref, label)| {
            if self.rename == Some(pref) {
                return SelectedLine::Rename {
                    edit: EditField::CoreRename,
                    save: CorePress::RenameSave.into(),
                    cancel: CorePress::RenameCancel.into(),
                    label,
                };
            }
            let mut buttons =
                vec![Ctl::button(CorePress::Rename, text::RENAME.get(lang)).compact()];
            match pref {
                // A recovery phrase's first account (…/0) cannot be hidden: no button
                // (2026-11-12; an off button and a line saying why before).
                EvmAccountPref::Index(index) | EvmAccountPref::Mnemonic(_, index) => {
                    if index != 0 {
                        buttons.push(Ctl::button(CorePress::Hide, text::HIDE.get(lang)).compact());
                    }
                }
                EvmAccountPref::Record(_) => {
                    buttons.push(
                        Ctl::danger(CorePress::RemoveKey, text::DELETE.get(lang))
                            .compact()
                            .enabled(self.can_remove_imported()),
                    );
                }
                // A YubiKey account (spec/10 §13): no "개인키 보기" (the key is on the card
                // only); hidden until a card with its key is enrolled again.
                EvmAccountPref::Hardware(_) => {
                    buttons.push(Ctl::button(CorePress::Hide, text::HIDE.get(lang)).compact());
                }
            }
            SelectedLine::Buttons(buttons)
        });
        let mut actions = Vec::new();
        if !self.key_only() {
            actions.push(
                Ctl::button(CorePress::AddAccount, text::ADD_ACCOUNT.get(lang))
                    .compact()
                    .enabled(self.can_add_account()),
            );
        }
        actions.push(
            Ctl::button(CorePress::ImportKey, text::IMPORT_KEY.get(lang))
                .compact()
                .enabled(self.can_import(yw_core::keyimport::ImportChain::Evm)),
        );
        actions.push(self.mnemonics_link());
        let mut footer = Vec::new();
        self.mn_pick_row(&mut footer);
        self.push_account_card(
            items,
            AccountCard {
                title: text::MY_ACCOUNTS.get(lang).to_owned(),
                picker: LinksPress::PickerEvm.into(),
                accounts,
                empty: None,
                locked: None,
                selected,
                details: Vec::new(),
                hidden: Some(crate::wallet::app_hidden::Family::Evm),
                actions,
                footer,
            },
        );
        self.evm_main_sections(items);
    }

    /// The top link of settings and S13: `← 처음 설정으로` while they were opened from S08's
    /// '처음 설정' card (`super::Screen::done_return`, spec/04 §2.3), else `← 메인으로`.
    #[must_use]
    pub fn back_row(&self) -> Item {
        let lang = self.settings.language;
        if self.done_return {
            Item::Row(vec![Ctl::link(
                CorePress::BackDone,
                text::BACK_DONE.get(lang),
            )])
        } else {
            back_main(lang)
        }
    }

    fn settings_screen(&self, section: SettingsSection, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(self.back_row());
        items.push(Item::Title(text::SETTINGS.get(lang).to_owned()));
        items.push(Item::Row(vec![
            Ctl::tab(
                CorePress::SectionSecurity,
                text::TAB_SECURITY.get(lang),
                section == SettingsSection::Security,
            )
            .width(68),
            // Keys and backups first and fixed widths (2026-11-08): the nine tabs keep one row
            // at the default 960 DIP window.
            Ctl::tab(
                MnPress::SectionMnemonics,
                text::TAB_MNEMONICS.get(lang),
                section == SettingsSection::Mnemonics,
            )
            .width(88),
            Ctl::tab(
                YkPress::SectionYubikey,
                "YubiKey",
                section == SettingsSection::YubiKey,
            )
            .width(84),
            Ctl::tab(
                CorePress::SectionNetwork,
                text::TAB_NETWORK.get(lang),
                section == SettingsSection::Network,
            )
            .width(120),
            Ctl::tab(
                EvmPress::SectionChains,
                text::TAB_CHAINS.get(lang),
                section == SettingsSection::Chains,
            )
            .width(92),
            Ctl::tab(
                SolPress::SectionSol,
                "Solana",
                section == SettingsSection::Solana,
            )
            .width(76),
            Ctl::tab(
                BtcPress::SectionBtc,
                "Bitcoin",
                section == SettingsSection::Bitcoin,
            )
            .width(76),
            Ctl::tab(
                LlmPress::SectionAi,
                text::TAB_AI.get(lang),
                section == SettingsSection::Ai,
            )
            .width(80),
            Ctl::tab(
                CorePress::SectionOther,
                text::TAB_OTHER.get(lang),
                section == SettingsSection::Other,
            )
            .width(108),
        ]));
        if let Some(elsewhere) = settings_elsewhere(lang, section) {
            items.push(Item::Help(elsewhere.to_owned()));
        }
        match section {
            SettingsSection::Security => self.security_section(items),
            SettingsSection::Network => self.network_section(items),
            SettingsSection::Chains => self.chains_section(items),
            SettingsSection::Solana => self.sol_settings_section(items),
            SettingsSection::Bitcoin => self.btc_settings_section(items),
            SettingsSection::Ai => self.llm_settings_section(items),
            SettingsSection::Other => self.other_section(items),
            SettingsSection::YubiKey => self.yk_settings_section(items),
            SettingsSection::Mnemonics => self.mn_settings_section(items),
        }
    }

    /// The `고급 설정 보기 ▸` / `고급 설정 숨기기 ▾` link.
    pub(crate) fn advanced_toggle(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Row(vec![Ctl::link(
            CorePress::AdvancedToggle,
            if self.show_advanced {
                text::ADVANCED_HIDE.get(lang)
            } else {
                text::ADVANCED_SHOW.get(lang)
            },
        )]));
    }

    fn security_section(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        self.language_card(items);
        items.push(Item::CardStart(Some(
            text::AUTO_LOCK_TITLE.get(lang).to_owned(),
        )));
        items.push(Item::Help(text::AUTO_LOCK_HELP.get(lang).to_owned()));
        items.push(Item::LabeledRow(
            text::AUTO_LOCK_LABEL.get(lang).to_owned(),
            vec![
                Ctl::edit(
                    EditField::CoreAutoLock,
                    &self.settings.auto_lock_minutes.to_string(),
                    80,
                    false,
                    2,
                ),
                Ctl::button(CorePress::AutolockSave, text::SAVE.get(lang)),
            ],
        ));
        items.push(Item::CardEnd);
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        let public = unlocked || self.mode == AppMode::BackupPending;
        items.push(Item::CardStart(Some(
            text::SECRETS_TITLE.get(lang).to_owned(),
        )));
        if self.key_only() {
            // No recovery words: what brings this wallet back is said anyway (2026-11-10).
            let lines = self.backup_status_all();
            if !lines.is_empty() {
                items.push(Item::Subtitle(
                    text::BACKUP_STATUS_TITLE.get(lang).to_owned(),
                ));
                for line in lines {
                    items.push(Item::Text(line));
                }
            }
            items.push(Item::Help(text::SECRETS_KEY_ONLY.get(lang).to_owned()));
            items.push(Item::Row(vec![
                Ctl::button(CorePress::RevealKey, text::REVEAL_KEY.get(lang)).enabled(
                    unlocked && self.selected_account().is_some() && !self.hardware_selected(),
                ),
            ]));
        } else {
            self.backup_card_rows(unlocked, public, items);
        }
        items.push(Item::Help(text::SECRETS_KEY_NOTE.get(lang).to_owned()));
        if self.facts().flags().secret_copy {
            items.push(Item::Row(vec![Ctl::check(
                CorePress::CopyToggle(None),
                text::ALLOW_COPY.get(lang),
                self.settings.allow_secret_copy,
            )]));
            items.push(Item::Help(text::ALLOW_COPY_HELP.get(lang).to_owned()));
        }
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            text::PASSWORD_TITLE.get(lang).to_owned(),
        )));
        items.push(Item::Help(text::PASSWORD_HELP.get(lang).to_owned()));
        items.push(Item::Help(text::T_PASSWORD_OLD_COPIES.get(lang).to_owned()));
        items.push(Item::Row(vec![
            Ctl::button(CorePress::ChangePassword, text::CHANGE_PASSWORD.get(lang)).enabled(public),
        ]));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            text::FILE_PROTECTION_TITLE.get(lang).to_owned(),
        )));
        if let Some((generation, written)) = self.guard.vault_file {
            items.push(Item::Text(vault_file_text(
                &self.facts(),
                lang,
                generation,
                written,
            )));
        }
        items.push(Item::Help(if self.guard.wer_unprotected {
            crate::wallet::text::T_WER_UNPROTECTED.get(lang).to_owned()
        } else {
            text::WER_PROTECTED.get(lang).to_owned()
        }));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            text::RESET_TITLE.get(lang).to_owned(),
        )));
        items.push(Item::Help(text::RESET_CARD_HELP.get(lang).to_owned()));
        items.push(Item::Row(vec![Ctl::danger(
            ResetPress::Open,
            text::RESET_WALLET.get(lang),
        )]));
        items.push(Item::CardEnd);
    }

    /// `언어 · Language` (spec/04 §2.11, spec/14 §1): the first card of the first settings tab,
    /// its title and options in both languages so a user who cannot read the current one still
    /// finds it. The change applies at once (an approval window already open keeps its language).
    fn language_card(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::CardStart(Some(LANGUAGE_TITLE.to_owned())));
        items.push(Item::Help(text::LANGUAGE_HELP.get(lang).to_owned()));
        items.push(Item::Row(vec![
            Ctl::radio(
                CorePress::Lang(Lang::Ko),
                LANGUAGE_KOREAN,
                lang == Lang::Ko,
                true,
            ),
            Ctl::radio(
                CorePress::Lang(Lang::En),
                "English",
                lang == Lang::En,
                false,
            ),
        ]));
        items.push(Item::CardEnd);
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the RPC provider form and the URL rows"
    )]
    fn network_section(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        // A pending rpc.json import review stays first (it waits for a decision), and so does the
        // advice to delete the plaintext file right after an import.
        let rpc_json = self.facts().flags().rpc_json_import;
        if rpc_json && self.rpc_import.on_top() {
            self.rpc_import_section(items);
        }
        items.push(Item::CardStart(Some(
            text::RPC_PROVIDER_TITLE.get(lang).to_owned(),
        )));
        if rpc_json && !self.rpc_import.on_top() && self.facts().rpc_json_present() {
            items.push(Item::Text(text::RPC_JSON_FOUND.get(lang).to_owned()));
        }
        items.push(Item::Help(text::RPC_PROVIDER_HELP.get(lang).to_owned()));
        let template = self.settings.rpc_template;
        items.push(Item::Row(vec![
            Ctl::radio(
                CorePress::Template(RpcTemplate::QuickNode),
                text::TPL_QUICKNODE.get(lang),
                template == RpcTemplate::QuickNode,
                true,
            ),
            Ctl::radio(
                CorePress::Template(RpcTemplate::Alchemy),
                text::ALCHEMY.get(lang),
                template == RpcTemplate::Alchemy,
                false,
            ),
            Ctl::radio(
                CorePress::Template(RpcTemplate::Manual),
                text::TPL_MANUAL.get(lang),
                template == RpcTemplate::Manual,
                false,
            ),
        ]));
        let stored = self.template_stored();
        let status = if stored {
            text::CONFIGURED.get(lang)
        } else {
            text::NONE.get(lang)
        };
        match template {
            RpcTemplate::QuickNode => {
                items.push(Item::Help(text::QN_STORED.fill(lang, [status])));
                items.push(Item::LabeledRow(
                    text::QN_NAME.get(lang).to_owned(),
                    vec![Ctl::edit(CredField::QnName, "", 320, true, 256)],
                ));
                items.push(Item::Help(text::QN_NAME_HELP.get(lang).to_owned()));
                items.push(Item::LabeledRow(
                    text::QN_TOKEN.get(lang).to_owned(),
                    vec![Ctl::edit(CredField::QnToken, "", 320, true, 256)],
                ));
                items.push(Item::Help(text::QN_TOKEN_HELP.get(lang).to_owned()));
                items.push(Item::Help(text::T_QUICKNODE_CHAINS.get(lang).to_owned()));
            }
            RpcTemplate::Alchemy => {
                items.push(Item::Help(text::ALCHEMY_STORED.fill(lang, [status])));
                items.push(Item::LabeledRow(
                    text::API_KEY.get(lang).to_owned(),
                    vec![Ctl::edit(CredField::AlchemyKey, "", 320, true, 256)],
                ));
                items.push(Item::Help(text::ALCHEMY_KEY_HELP.get(lang).to_owned()));
            }
            RpcTemplate::Manual => {
                items.push(Item::Help(text::MANUAL_HELP.get(lang).to_owned()));
            }
        }
        let manual = template == RpcTemplate::Manual;
        items.push(Item::Row(vec![
            Ctl::primary(CorePress::Generate, text::GENERATE.get(lang)).enabled(!manual),
            Ctl::button(CorePress::TemplateSave, text::TPL_SAVE.get(lang)).enabled(!manual),
            Ctl::danger(CorePress::TemplateDelete, text::TPL_DELETE.get(lang))
                .enabled(!manual && stored),
        ]));
        if self.rpc_removed == Some(crate::wallet::RpcRemoved::Template) {
            items.push(Item::Banner(
                text::TPL_DELETED.get(lang).to_owned(),
                Tone::Success,
            ));
        }
        items.push(Item::Help(text::GENERATE_HELP.get(lang).to_owned()));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            text::RPC_LIST_TITLE.get(lang).to_owned(),
        )));
        self.rpc_summary_items(items);
        items.push(Item::Help(text::RPC_LIST_HELP.get(lang).to_owned()));
        let mut networks = self.url_networks();
        networks.truncate(usize::from(rows::RPC_ROWS));
        // The note above an open field: the stored credentials can make the empty addresses.
        let template_name = match template {
            RpcTemplate::QuickNode => Some("QuickNode"),
            RpcTemplate::Alchemy => Some(text::ALCHEMY.get(lang)),
            RpcTemplate::Manual => None,
        };
        // One line per network (2026-11-12): its name, the three actions and its state as a tag
        // on the same line; a full-width band only for a failure (it has the reason) and for
        // `삭제`. 13 networks fit on one screen instead of three.
        for (row, network) in networks.into_iter().enumerate() {
            let url = self.apikeys.rpc_url(network);
            let row = Row(u16::try_from(row).unwrap_or(0));
            items.push(Item::LabeledRow(
                self.network_name(network),
                vec![
                    Ctl::button(
                        CorePress::RpcRow(row, RpcRowAction::Replace),
                        if url.is_some() {
                            text::REPLACE.get(lang)
                        } else {
                            text::ENTER.get(lang)
                        },
                    )
                    .compact(),
                    Ctl::button(
                        CorePress::RpcRow(row, RpcRowAction::Test),
                        text::TEST.get(lang),
                    )
                    .compact()
                    .enabled(url.is_some()),
                    Ctl::danger(
                        CorePress::RpcRow(row, RpcRowAction::Delete),
                        text::DELETE.get(lang),
                    )
                    .compact()
                    .enabled(url.is_some()),
                ],
            ));
            let message = self.rpc_messages.iter().find(|(id, _, _)| *id == network);
            let pill = match (url.is_some(), message.map(|(_, _, state)| *state)) {
                (false, _) => Some((text::NONE, Tone::Warn)),
                (true, Some(TestState::Works)) => Some((text::WORKS, Tone::Success)),
                (true, Some(TestState::Failed)) => Some((text::FAILED, Tone::Danger)),
                (true, Some(TestState::Testing)) => Some((text::TESTING, Tone::Info)),
                (true, None) => None,
            };
            if let Some((label, tone)) = pill {
                items.push(Item::Pill(label.get(lang).to_owned(), tone));
            }
            if self.replace_target == Some(network) {
                items.push(Item::Help(url.as_ref().map_or_else(
                    || text::ROW_NO_ADDRESS.fill(lang, [&network.to_string()]),
                    |url| text::ROW_ADDRESS.fill(lang, [&network.to_string(), &mask_url(url)]),
                )));
                if let Some(name) = template_name.filter(|_| {
                    stored && template_entry(template, network, &self.settings).is_some()
                }) {
                    items.push(Item::Help(text::ROW_TEMPLATE_STORED.fill(lang, [name])));
                }
                items.push(Item::Row(vec![
                    Ctl::edit(CredField::RpcReplace, "", 420, true, 2_048),
                    Ctl::primary(CorePress::ReplaceSave, text::SAVE.get(lang)),
                    Ctl::button(CorePress::ReplaceCancel, text::CANCEL.get(lang)),
                ]));
                items.push(Item::Help(text::ROW_PASTE_HELP.get(lang).to_owned()));
            }
            if let Some((_, message, TestState::Failed)) = message {
                items.push(Item::Banner(message.clone(), Tone::Danger));
            }
            if self.rpc_removed == Some(crate::wallet::RpcRemoved::Url(network)) {
                items.push(Item::Banner(
                    text::RPC_URL_DELETED.get(lang).to_owned(),
                    Tone::Success,
                ));
            }
        }
        items.push(Item::CardEnd);
        // Block explorers (2026-11-11): per network, like the RPC list above.
        self.explorer_settings_card(items);
        let dormant = self.apikeys.dormant_names();
        if !dormant.is_empty() {
            items.push(Item::CardStart(Some(
                text::DORMANT_TITLE.get(lang).to_owned(),
            )));
            items.push(Item::Help(
                text::DORMANT_HELP.fill(lang, [&dormant.len().to_string()]),
            ));
            items.push(Item::Row(vec![Ctl::danger(
                CorePress::PruneDormant,
                text::DORMANT_DELETE.get(lang),
            )]));
            items.push(Item::CardEnd);
        }
        // The developer import's button last: most owners set RPC with the provider card above.
        if rpc_json && !self.rpc_import.on_top() {
            self.rpc_import_section(items);
        }
    }

    /// The `rpc.json에서 가져오기` card of settings → 네트워크(RPC)
    /// ([`crate::wallet::app_rpc_plan::RpcImportUi::on_top`]): shown only when the file
    /// exists or a plan waits for confirmation. 2026-11-24 (spec/15
    /// §11.4 S5-3): render code, moved here from `app_rpc_import.rs`; whether the file is there
    /// is the shell's answer [`ScreenFacts::rpc_json_present`] (before, `rpc_json_path()` and
    /// `is_file` here; the same probe answers it on Windows). Its texts stay in
    /// `app_rpc_import::text` until the builders move (S5-5).
    pub(crate) fn rpc_import_section(&self, items: &mut Vec<Item>) {
        use crate::screen::build::rpc_import::text;
        let lang = self.settings.language;
        let t = |entry: Text| entry.get(lang).to_owned();
        let Some(plan) = self.rpc_import.plan.as_ref() else {
            if self.facts().rpc_json_present() {
                items.push(Item::CardStart(Some(t(text::CARD_TITLE))));
                if !self.rpc_import.imported {
                    items.push(Item::Help(t(text::CARD_HELP)));
                    items.push(Item::Help(t(text::JSON_PLAINTEXT)));
                }
                if self.rpc_import.confirm_delete {
                    items.push(Item::Banner(t(text::JSON_DELETE_CONFIRM), Tone::Warn));
                    items.push(Item::Row(vec![
                        Ctl::danger(RpcImportPress::DeleteConfirm, text::DELETE.get(lang)),
                        Ctl::button(RpcImportPress::DeleteCancel, text::CANCEL.get(lang)),
                    ]));
                } else {
                    if self.rpc_import.imported {
                        items.push(Item::Banner(t(text::JSON_LEFT), Tone::Warn));
                    }
                    items.push(Item::Row(vec![
                        Ctl::button(RpcImportPress::Import, text::IMPORT_BUTTON.get(lang)),
                        Ctl::button(RpcImportPress::Delete, text::DELETE_FILE.get(lang)),
                    ]));
                }
                items.push(Item::CardEnd);
            }
            return;
        };
        items.push(Item::CardStart(Some(t(text::CONFIRM_TITLE))));
        let mut list = t(text::CONFIRM_LEAD);
        let mut existing = 0_usize;
        for entry in &plan.entries {
            let has = self.apikeys.has(KeyName::Rpc(entry.network));
            if has {
                existing = existing.saturating_add(1);
            }
            let _ = write!(
                list,
                "\n· {} ({}) — {} …/****{}{}",
                self.network_name(entry.network),
                entry.network,
                entry.provider.label(lang),
                if has { text::HAS_ADDRESS.get(lang) } else { "" },
                if plan.quicknode.is_some() && !entry.fits_template {
                    text::OFF_TEMPLATE.get(lang)
                } else {
                    ""
                },
            );
        }
        self.push_rejected(&mut list, plan);
        items.push(Item::Text(list));
        if plan.quicknode.is_some() {
            items.push(Item::Help(t(text::SAME_ENDPOINT)));
        }
        if existing > 0 {
            items.push(Item::Banner(
                text::EXISTING.fill(lang, [&existing.to_string()]),
                Tone::Warn,
            ));
            items.push(Item::Row(vec![
                Ctl::button(RpcImportPress::Overwrite, text::OVERWRITE.get(lang)),
                Ctl::button(RpcImportPress::Fill, text::FILL_EMPTY.get(lang)),
                Ctl::button(RpcImportPress::Cancel, text::CANCEL.get(lang)),
            ]));
        } else {
            items.push(Item::Row(vec![
                Ctl::button(RpcImportPress::Overwrite, text::IMPORT.get(lang)),
                Ctl::button(RpcImportPress::Cancel, text::CANCEL.get(lang)),
            ]));
        }
        items.push(Item::Help(t(text::SAVE_NOTE)));
        items.push(Item::CardEnd);
    }

    /// The RPC list's numbers over the networks that have an address: `(with an address,
    /// networks, works, failed, not tested in this run)`.
    #[must_use]
    pub fn rpc_summary(&self) -> (usize, usize, usize, usize, usize) {
        let networks = self.url_networks();
        let (mut configured, mut works, mut failed) = (0_usize, 0_usize, 0_usize);
        for network in &networks {
            if !self.apikeys.has(KeyName::Rpc(*network)) {
                continue;
            }
            configured = configured.saturating_add(1);
            match self
                .rpc_messages
                .iter()
                .find(|(id, _, _)| id == network)
                .map(|(_, _, state)| *state)
            {
                Some(TestState::Works) => works = works.saturating_add(1),
                Some(TestState::Failed) => failed = failed.saturating_add(1),
                Some(TestState::Testing) | None => {}
            }
        }
        let untested = configured.saturating_sub(works).saturating_sub(failed);
        (configured, networks.len(), works, failed, untested)
    }

    /// The head of "네트워크별 RPC 주소" (2026-11-10): how many addresses there are, this run's
    /// tests, the failed networks as links to their rows, and `모두 테스트`.
    fn rpc_summary_items(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let (configured, total, works, failed, untested) = self.rpc_summary();
        items.push(Item::Text(text::RPC_LIST_SUMMARY.fill(
            lang,
            [
                &configured.to_string(),
                &total.to_string(),
                &works.to_string(),
                &failed.to_string(),
                &untested.to_string(),
            ],
        )));
        let links: Vec<Ctl> = self
            .url_networks()
            .into_iter()
            .enumerate()
            .filter(|(_, network)| {
                self.apikeys.has(KeyName::Rpc(*network))
                    && self
                        .rpc_messages
                        .iter()
                        .any(|(id, _, state)| id == network && *state == TestState::Failed)
            })
            .filter_map(|(row, network)| {
                let row = u16::try_from(row)
                    .ok()
                    .filter(|row| *row < rows::RPC_ROW_OPENS)?;
                Some(Ctl::link(
                    CorePress::RpcRowOpen(Row(row)),
                    &self.network_name(network),
                ))
            })
            .collect();
        if !links.is_empty() {
            items.push(Item::LabeledRow(
                text::FAILED_NETWORKS.get(lang).to_owned(),
                links,
            ));
        }
        let tests = &self.rpc_tests;
        let label = if tests.busy() {
            text::TESTING_PROGRESS.fill(
                lang,
                [
                    &tests
                        .done
                        .saturating_add(1)
                        .min(tests.total.max(1))
                        .to_string(),
                    &tests.total.max(1).to_string(),
                ],
            )
        } else {
            text::TEST_ALL.get(lang).to_owned()
        };
        items.push(Item::Row(vec![
            Ctl::button(CorePress::TestAll, &label).enabled(configured > 0 && !tests.busy()),
        ]));
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the cards of the Other settings section in order (2026-11-24 S5-4: longer by its press names)"
    )]
    fn other_section(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let flags = self.facts().flags();
        if flags.browser_extension {
            items.push(Item::CardStart(Some(
                text::EXTENSION_TITLE.get(lang).to_owned(),
            )));
            items.push(Item::Text(self.extension_status().text_in(lang).to_owned()));
            items.push(Item::Help(
                crate::screen::build::reset::T_EXT_COMPAT_SHORT
                    .get(lang)
                    .to_owned(),
            ));
            items.push(Item::Row(vec![Ctl::button(
                ExtPress::Open,
                text::EXTENSION_OPEN.get(lang),
            )]));
            items.push(Item::CardEnd);
        }
        items.push(Item::CardStart(Some("WalletConnect".to_owned())));
        items.push(Item::Help(text::WC_HELP.get(lang).to_owned()));
        items.push(Item::Field(
            text::STATUS.get(lang).to_owned(),
            if self.settings.walletconnect_project.is_empty() {
                text::WC_OFF.get(lang).to_owned()
            } else {
                text::WC_ON.fill(lang, [&self.wc.sessions.len().to_string()])
            },
        ));
        items.push(Item::Row(vec![Ctl::button(
            SitesPress::Open,
            text::WC_OPEN_SITES.get(lang),
        )]));
        items.push(Item::CardEnd);
        if flags.browser_extension {
            items.push(Item::CardStart(Some(
                text::BROWSER_LINK_TITLE.get(lang).to_owned(),
            )));
            items.push(Item::Help(text::BROWSER_LINK_HELP.get(lang).to_owned()));
            items.push(Item::Row(vec![Ctl::check(
                CorePress::AutolaunchToggle(None),
                text::AUTOLAUNCH.get(lang),
                self.settings.browser_auto_launch,
            )]));
            items.push(Item::Help(text::AUTOLAUNCH_HELP.get(lang).to_owned()));
            items.push(Item::Row(vec![Ctl::check(
                CorePress::LocalhostToggle(None),
                text::LOCALHOST.get(lang),
                self.settings.allow_localhost_dapps,
            )]));
            items.push(Item::Help(text::LOCALHOST_HELP.get(lang).to_owned()));
            items.push(Item::CardEnd);
        }
        items.push(Item::CardStart(Some(
            text::DIAGNOSTICS_TITLE.get(lang).to_owned(),
        )));
        items.push(Item::Help(text::DIAGNOSTICS_HELP.get(lang).to_owned()));
        if flags.open_folders {
            items.push(Item::Row(vec![Ctl::button(
                CorePress::OpenLogFolder,
                text::OPEN_LOG_FOLDER.get(lang),
            )]));
        }
        if self.show_advanced {
            let level = self.settings.log_level;
            items.push(Item::LabeledRow(
                text::LOG_LEVEL.get(lang).to_owned(),
                vec![
                    Ctl::radio(
                        CorePress::LogLevel(LogLevel::Error),
                        "error",
                        level == LogLevel::Error,
                        true,
                    ),
                    Ctl::radio(
                        CorePress::LogLevel(LogLevel::Warn),
                        "warn",
                        level == LogLevel::Warn,
                        false,
                    ),
                    Ctl::radio(
                        CorePress::LogLevel(LogLevel::Info),
                        "info",
                        level == LogLevel::Info,
                        false,
                    ),
                    Ctl::radio(
                        CorePress::LogLevel(LogLevel::Debug),
                        "debug",
                        level == LogLevel::Debug,
                        false,
                    ),
                ],
            ));
            items.push(Item::Help(text::LOG_LEVEL_HELP.get(lang).to_owned()));
        }
        self.advanced_toggle(items);
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            text::ABOUT_TITLE.get(lang).to_owned(),
        )));
        // The installed commit says which build runs (2026-11-10, `build_info`; 2026-11-24 S5-3:
        // the line is the shell's answer, `ScreenFacts::version_text`).
        items.push(Item::Field(
            text::VERSION.get(lang).to_owned(),
            self.facts().version_text(lang),
        ));
        items.push(Item::Field(
            text::DATA_FOLDER.get(lang).to_owned(),
            self.facts().data_dir(),
        ));
        if flags.open_folders {
            items.push(Item::Row(vec![Ctl::button(
                CorePress::OpenDataFolder,
                text::OPEN_FOLDER.get(lang),
            )]));
        }
        items.push(Item::Field(
            text::SHORTCUTS.get(lang).to_owned(),
            text::SHORTCUTS_TEXT.get(lang).to_owned(),
        ));
        items.push(Item::CardEnd);
    }

    #[expect(clippy::too_many_lines, reason = "one arm per overlay")]
    fn confirm(&self, kind: Confirm, items: &mut Vec<Item>) {
        // The E-VLT-006 choices have their own texts and buttons (`app_sidecar`).
        if kind == Confirm::SidecarCorrupt {
            self.meta_overlay(items);
            return;
        }
        if kind == Confirm::JournalCorrupt {
            self.journal_overlay(items);
            return;
        }
        let lang = self.settings.language;
        let btc = self.btc.confirm;
        let (title, text, yes) = match kind {
            Confirm::Btc => btc.map_or(("Bitcoin", String::new(), text::OK.get(lang)), |confirm| {
                confirm.texts(lang)
            }),
            Confirm::CopyOn => (
                text::C_COPY_TITLE.get(lang),
                text::C_COPY_TEXT.get(lang).to_owned(),
                text::C_ALLOW.get(lang),
            ),
            Confirm::LocalhostOn => (
                text::C_LOCALHOST_TITLE.get(lang),
                text::C_LOCALHOST_TEXT.get(lang).to_owned(),
                text::C_TURN_ON.get(lang),
            ),
            Confirm::RevealMnemonic | Confirm::RevealKey => (
                if kind == Confirm::RevealMnemonic {
                    text::REVEAL_MNEMONIC.get(lang)
                } else {
                    text::REVEAL_KEY.get(lang)
                },
                text::C_REVEAL_TEXT.get(lang).to_owned(),
                text::C_CONTINUE.get(lang),
            ),
            Confirm::Generate => (
                text::C_GENERATE_TITLE.get(lang),
                self.generate_text(),
                text::C_CREATE.get(lang),
            ),
            Confirm::RpcUrlDelete(network) => (
                text::C_RPC_DELETE_TITLE.get(lang),
                self.rpc_delete_text(network),
                text::C_REMOVE.get(lang),
            ),
            Confirm::TemplateDelete => (
                text::C_TPL_DELETE_TITLE.get(lang),
                self.template_delete_text(),
                text::C_REMOVE.get(lang),
            ),
            Confirm::LlmKeyDelete => (
                text::C_LLM_KEY_TITLE.get(lang),
                text::C_LLM_KEY_TEXT.get(lang).to_owned(),
                text::C_REMOVE.get(lang),
            ),
            Confirm::YkAbandon => (
                text::C_YK_ABANDON_TITLE.get(lang),
                crate::wallet::app_yubikey::text::YK_ABANDON
                    .get(lang)
                    .to_owned(),
                text::C_YK_ABANDON_YES.get(lang),
            ),
            Confirm::YkPinLater => (
                text::C_PIN_LATER_TITLE.get(lang),
                text::C_PIN_LATER_TEXT.get(lang).to_owned(),
                text::C_PIN_LATER_YES.get(lang),
            ),
            // Drawn above.
            Confirm::SidecarCorrupt | Confirm::JournalCorrupt => ("", String::new(), ""),
            Confirm::RemoveKey => (
                text::C_REMOVE_KEY_TITLE.get(lang),
                T_REMOVE_KEY.get(lang).to_owned(),
                text::C_CONTINUE.get(lang),
            ),
            Confirm::RemoveImported => (
                text::C_REMOVE_KEY_TITLE.get(lang),
                crate::screen::build::keys::text::REMOVE_IMPORTED
                    .get(lang)
                    .to_owned(),
                text::C_CONTINUE.get(lang),
            ),
            Confirm::RemoveYubiKey => (
                text::C_REMOVE_YK_TITLE.get(lang),
                self.yk_remove_text(),
                text::C_CONTINUE.get(lang),
            ),
            Confirm::RevealImported => (
                text::REVEAL_KEY.get(lang),
                text::C_REVEAL_TEXT.get(lang).to_owned(),
                text::C_CONTINUE.get(lang),
            ),
            Confirm::ChainPin => (
                text::C_CHAIN_PIN_TITLE.get(lang),
                self.chain_pin_text(),
                text::C_CHAIN_PIN_YES.get(lang),
            ),
            Confirm::ChainRepin => (
                text::C_REPIN.get(lang),
                self.chain_repin_text(),
                text::C_REPIN.get(lang),
            ),
            Confirm::ChainDelete => (
                text::C_CHAIN_DELETE_TITLE.get(lang),
                text::C_CHAIN_DELETE_TEXT.get(lang).to_owned(),
                text::DELETE.get(lang),
            ),
            Confirm::BookDelete => (
                text::C_BOOK_DELETE_TITLE.get(lang),
                self.book_delete_text(),
                text::DELETE.get(lang),
            ),
            Confirm::TokenDelete => (
                text::C_TOKEN_DELETE_TITLE.get(lang),
                T_TOKEN_DELETE.get(lang).to_owned(),
                text::DELETE.get(lang),
            ),
            Confirm::DisconnectAll => (
                text::C_DISCONNECT_TITLE.get(lang),
                if self.wc.sessions.is_empty() {
                    text::C_DISCONNECT_TEXT.get(lang).to_owned()
                } else {
                    text::C_DISCONNECT_WC_TEXT.fill(lang, [&self.wc.sessions.len().to_string()])
                },
                text::C_DISCONNECT_YES.get(lang),
            ),
            Confirm::SettingsFile => (
                text::C_SETTINGS_FILE_TITLE.get(lang),
                text::C_SETTINGS_FILE_TEXT.get(lang).to_owned(),
                text::C_SETTINGS_FILE_YES.get(lang),
            ),
            Confirm::WcDisconnectAll => (
                text::C_WC_DISCONNECT_TITLE.get(lang),
                text::C_WC_DISCONNECT_TEXT.fill(lang, [&self.wc.sessions.len().to_string()]),
                text::C_WC_DISCONNECT_YES.get(lang),
            ),
            Confirm::Discard => (
                text::C_DISCARD_TITLE.get(lang),
                T_DISCARD.get(lang).to_owned(),
                text::C_DISCARD_YES.get(lang),
            ),
            Confirm::LlmOn => (
                text::C_LLM_ON_TITLE.get(lang),
                self.llm_notice_text().unwrap_or_default(),
                text::C_TURN_ON.get(lang),
            ),
            Confirm::PruneDormant => (
                text::DORMANT_DELETE.get(lang),
                text::C_PRUNE_TEXT.fill(
                    lang,
                    [
                        &self.apikeys.dormant_names().len().to_string(),
                        &self.apikeys.dormant_names().join(", "),
                    ],
                ),
                text::DELETE.get(lang),
            ),
        };
        let destructive = matches!(
            kind,
            Confirm::PruneDormant
                | Confirm::RpcUrlDelete(_)
                | Confirm::TemplateDelete
                | Confirm::LlmKeyDelete
                | Confirm::ChainDelete
                | Confirm::BookDelete
                | Confirm::TokenDelete
                | Confirm::DisconnectAll
                | Confirm::WcDisconnectAll
                | Confirm::Discard
                | Confirm::RemoveKey
                | Confirm::RemoveImported
                | Confirm::RemoveYubiKey
        );
        items.push(Item::Title(title.to_owned()));
        items.push(Item::CardStart(None));
        match kind {
            // The "지워지는 계정" block (2026-11-10), then the imported-key band with the balance
            // sentence inside it (the key is lost for good with its removal).
            Confirm::RemoveKey | Confirm::RemoveImported => {
                let account = if kind == Confirm::RemoveKey {
                    self.remove_key_account()
                } else {
                    self.imported_removed()
                };
                let inside = account.map_or_else(Vec::new, |account| {
                    items.push(Item::Subtitle(text::C_REMOVED_ACCOUNT.get(lang).to_owned()));
                    crate::screen::build::removed::removed_items(lang, &[account], items)
                });
                let mut band = inside.join(" ");
                if !band.is_empty() {
                    band.push(' ');
                }
                band.push_str(&text);
                items.push(Item::Banner(band, Tone::HighRisk));
            }
            Confirm::RemoveYubiKey => {
                items.push(Item::Text(text));
                self.yk_remove_items(items);
            }
            _ => items.push(Item::Text(text)),
        }
        if kind == Confirm::SettingsFile {
            for line in self.settings_file_lines() {
                items.push(Item::Text(line));
            }
        }
        if kind == Confirm::TokenDelete
            && let Some((label, address)) = self.token_delete_target()
        {
            items.push(Item::Field(text::C_TOKEN.get(lang).to_owned(), label));
            items.push(Item::Help(text::C_CONTRACT_ADDRESS.get(lang).to_owned()));
            items.push(Item::Mono(yw_core::evm::display::format_address(&address)));
        }
        if kind == Confirm::RevealImported
            && let Some((label, address)) = self.imported_target_text()
        {
            items.push(Item::Field(text::C_ACCOUNT.get(lang).to_owned(), label));
            items.push(Item::Mono(address));
        }
        if kind == Confirm::Generate {
            items.push(Item::Row(vec![Ctl::check(
                CorePress::OverwriteCheck(None),
                text::C_OVERWRITE.get(lang),
                self.overwrite_checked,
            )]));
        }
        if matches!(kind, Confirm::ChainRepin | Confirm::LlmOn) {
            let (check, check_text, checked) = if kind == Confirm::LlmOn {
                (
                    Press::Llm(LlmPress::NoticeCheck(None)),
                    text::C_UNDERSTOOD.get(lang),
                    self.llm_ui.notice_checked,
                )
            } else {
                (
                    Press::Evm(EvmPress::RepinCheck(None)),
                    text::C_REPIN_CHECK.get(lang),
                    self.evm.repin.as_ref().is_some_and(|repin| repin.checked),
                )
            };
            items.push(Item::Row(vec![Ctl::check(check, check_text, checked)]));
            items.push(Item::Row(vec![
                Ctl::primary(CorePress::ConfirmYes, yes).enabled(checked),
                Ctl::button(CorePress::ConfirmNo, text::CANCEL.get(lang)),
            ]));
            items.push(Item::CardEnd);
            return;
        }
        if kind == Confirm::YkAbandon {
            // Going on is the main choice; giving up discards the words (spec/10 §7.1-1).
            items.push(Item::Row(vec![
                Ctl::primary(CorePress::ConfirmNo, text::C_KEEP_CREATING.get(lang)),
                Ctl::danger(CorePress::ConfirmYes, yes),
            ]));
            items.push(Item::CardEnd);
            return;
        }
        if kind == Confirm::YkPinLater {
            // Setting the PIN now is the main choice (back to the result and its PIN card).
            items.push(Item::Row(vec![
                Ctl::primary(CorePress::ConfirmNo, text::C_PIN_NOW.get(lang)),
                Ctl::button(CorePress::ConfirmYes, yes),
            ]));
            items.push(Item::CardEnd);
            return;
        }
        let no = match (kind, btc) {
            (Confirm::Btc, Some(confirm)) => confirm.no_label(lang),
            _ => text::CANCEL.get(lang),
        };
        items.push(Item::Row(vec![
            if destructive {
                Ctl::danger(CorePress::ConfirmYes, yes)
            } else {
                Ctl::primary(CorePress::ConfirmYes, yes)
            },
            Ctl::button(CorePress::ConfirmNo, no),
        ]));
        items.push(Item::CardEnd);
    }

    /// The EVM imported key about to be removed (`Confirm::RemoveKey`) as the "지워지는 계정"
    /// block shows it (2026-11-10, was `remove_key_balance`): the selected EVM network's native
    /// balance as last read; other networks and tokens are not checked.
    fn remove_key_account(&self) -> Option<crate::screen::RemovedAccount> {
        let (label, address) = self.pending_remove.and_then(|id| {
            self.meta.as_ref()?.evm_raw_accounts.iter().find_map(|raw| {
                (raw.record_id == *id.as_bytes())
                    .then(|| yw_core::evm::address::parse_address(&raw.address).ok())
                    .flatten()
                    .map(|address| (raw.label.clone(), address))
            })
        })?;
        Some(self.evm_removed(label, &address, true))
    }

    /// `RpcUrlDelete`'s text (2026-11-10): the address cannot be shown again, how it comes back,
    /// and what stops meanwhile.
    fn rpc_delete_text(&self, network: NetworkId) -> String {
        let lang = self.settings.language;
        let again = match self.settings.rpc_template {
            RpcTemplate::Manual => text::C_RPC_AGAIN_MANUAL.get(lang).to_owned(),
            template => text::C_RPC_AGAIN_TEMPLATE.fill(
                lang,
                [
                    if template == RpcTemplate::QuickNode {
                        "QuickNode"
                    } else {
                        text::ALCHEMY.get(lang)
                    },
                    if self.template_stored() {
                        text::CONFIGURED.get(lang)
                    } else {
                        text::NONE.get(lang)
                    },
                ],
            ),
        };
        // A stored template credential fills an empty network at the next start (2026-11-11).
        let refill = if self.template_stored()
            && template_entry(self.settings.rpc_template, network, &self.settings).is_some()
        {
            text::C_RPC_REFILL.get(lang)
        } else {
            ""
        };
        text::C_RPC_DELETE_TEXT.fill(
            lang,
            [
                &self.network_name(network),
                &network.to_string(),
                &again,
                refill,
            ],
        )
    }

    /// `TemplateDelete`'s text (2026-11-10).
    fn template_delete_text(&self) -> String {
        let lang = self.settings.language;
        if self.settings.rpc_template == RpcTemplate::Alchemy {
            text::C_TPL_DELETE_ALCHEMY.get(lang).to_owned()
        } else {
            text::C_TPL_DELETE_QUICKNODE.get(lang).to_owned()
        }
    }

    fn generate_text(&self) -> String {
        let lang = self.settings.language;
        let (targets, skipped) = self.generation_plan();
        let mut out = text::C_GENERATE_TEXT.get(lang).to_owned();
        for network in targets {
            let existing = if self.apikeys.has(KeyName::Rpc(network)) {
                text::C_GENERATE_EXISTING.get(lang)
            } else {
                ""
            };
            let _ = write!(
                out,
                "\n· {} ({network}){existing}",
                self.network_name(network)
            );
        }
        if !skipped.is_empty() {
            out.push_str(text::C_GENERATE_SKIPPED.get(lang));
            for network in skipped {
                let _ = write!(out, "\n· {} ({network})", self.network_name(network));
            }
        }
        out
    }
}
