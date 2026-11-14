//! Hidden accounts (spec/04 §2.6, 2026-11-08). `숨기기` only marks meta `hidden` (and takes the
//! account out of every dApp grant, spec/05 §4.9); until now nothing showed those accounts again.
//! The EVM and Solana `내 계정` cards list them under `숨긴 계정 n개 보기 ▸`, and `다시 보이기`
//! clears the mark. Site connections are not restored (the user connects again from the dApp).

use crate::app::App;
use crate::app_sol::SolAccountId;
use crate::meta::EvmAccountPref;
use crate::ui::main_window::{Ctl, Item, Tone};
use yw_core::lang::Lang;

/// The fixed texts of the hidden-account rows (spec/14).
pub mod text {
    yw_core::texts! {
        /// The note after `숨기기`: {0} the account's label.
        HIDDEN_NOTE(1) = "'{0}'을(를) 숨겼습니다. 이 계정의 사이트 연결도 해제했습니다. '내 계정' 아래 '숨긴 계정'에서 다시 볼 수 있습니다."
            / "'{0}' is hidden. Its site connections were removed too. You can see it again under 'Hidden accounts' in 'My accounts'.";
        /// The opened toggle: {0} count.
        TOGGLE_CLOSE(1) = "숨긴 계정 {0}개 접기 ▾" / "Hide hidden accounts ({0}) ▾";
        /// The closed toggle: {0} count.
        TOGGLE_OPEN(1) = "숨긴 계정 {0}개 보기 ▸" / "Show hidden accounts ({0}) ▸";
        /// The help line of the opened list.
        HIDDEN_HELP = "숨긴 계정은 목록·보내기·사이트 연결에서 빠질 뿐 블록체인의 자산은 그대로입니다. '다시 보이기'를 누르면 목록으로 돌아옵니다(사이트 연결은 dApp에서 다시 하세요)."
            / "Hidden accounts are only left out of the list, sending and site connections; their assets on the blockchain stay as they are. 'Unhide' brings an account back to the list (connect it to sites again from the dApp).";
        /// A hidden row's title: {0} label, {1} source.
        HIDDEN_ROW(2) = "{0} · {1} · 숨김" / "{0} · {1} · hidden";
        /// A Solana balance: {0} amount.
        BALANCE(1) = "잔액 {0}" / "Balance {0}";
        /// The last-read balance line: {0} the balance text.
        LAST_READ(1) = "마지막으로 읽은 {0}" / "{0} (last read)";
        /// The row button.
        UNHIDE = "다시 보이기" / "Unhide";
        /// The note after `다시 보이기`: {0} label.
        UNHIDDEN_NOTE(1) = "'{0}'을(를) 다시 보이게 했습니다. 사이트에서 쓰려면 dApp에서 다시 연결하세요."
            / "'{0}' is visible again. To use it on a site, connect again from the dApp.";
    }
}

/// Command ids (block 16,200–16,599 of `ui::command_ids`).
pub mod ids {
    /// EVM `숨긴 계정 n개 보기 ▸` / `접기 ▾`.
    pub const EVM_TOGGLE: u16 = 16_200;
    /// Solana `숨긴 계정 n개 보기 ▸` / `접기 ▾`.
    pub const SOL_TOGGLE: u16 = 16_201;
    /// EVM `다시 보이기` (one id per hidden row).
    pub const EVM_ROW_BASE: u16 = 16_210;
    /// Solana `다시 보이기` (one id per hidden row).
    pub const SOL_ROW_BASE: u16 = 16_400;
    /// Rows of each list.
    pub const ROW_SPAN: u16 = 190;
    /// Every fixed id.
    pub const FIXED: &[u16] = &[EVM_TOGGLE, SOL_TOGGLE];
}

/// Which `내 계정` card.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// EVM tab.
    Evm,
    /// Solana tab.
    Sol,
}

/// A hidden account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiddenId {
    /// An EVM account.
    Evm(EvmAccountPref),
    /// A Solana account.
    Sol(SolAccountId),
}

/// One row of the hidden list: which account, its label, address text and source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiddenRow {
    /// The account.
    pub id: HiddenId,
    /// Its label.
    pub label: String,
    /// Its address (as stored).
    pub address: String,
    /// Where it comes from (`m/…`, the recovery phrase, `YubiKey`).
    pub source: String,
}

/// The note after `숨기기` (the way back is in the same card).
#[must_use]
pub fn hidden_note(lang: Lang, label: &str) -> String {
    text::HIDDEN_NOTE.fill(lang, [label])
}

impl App {
    /// The hidden accounts of `family`, in the order of the visible rows' sources.
    #[must_use]
    pub fn hidden_rows(&self, family: Family) -> Vec<HiddenRow> {
        let Some(meta) = self.meta.as_ref() else {
            return Vec::new();
        };
        let mut rows = Vec::new();
        match family {
            Family::Evm => {
                for account in meta.evm_accounts.iter().filter(|account| account.hidden) {
                    rows.push(HiddenRow {
                        id: HiddenId::Evm(EvmAccountPref::Index(account.index)),
                        label: account.label.clone(),
                        address: account.address.clone(),
                        source: format!("m/44'/60'/0'/0/{}", account.index),
                    });
                }
                for entry in &meta.mnemonics {
                    for account in entry.evm.iter().filter(|account| account.hidden) {
                        rows.push(HiddenRow {
                            id: HiddenId::Evm(EvmAccountPref::Mnemonic(
                                entry.record_id,
                                account.index,
                            )),
                            label: account.label.clone(),
                            address: account.address.clone(),
                            source: format!("{} · m/44'/60'/0'/0/{}", entry.label, account.index),
                        });
                    }
                }
                for account in meta.hw_accounts.evm.iter().filter(|account| account.hidden) {
                    rows.push(HiddenRow {
                        id: HiddenId::Evm(EvmAccountPref::Hardware(account.index)),
                        label: account.label.clone(),
                        address: account.address.clone(),
                        source: "YubiKey".to_owned(),
                    });
                }
            }
            Family::Sol => {
                for account in meta.sol_accounts.iter().filter(|account| account.hidden) {
                    rows.push(HiddenRow {
                        id: HiddenId::Sol(SolAccountId::Derived(account.index)),
                        label: account.label.clone(),
                        address: account.address.clone(),
                        source: SolAccountId::Derived(account.index)
                            .path_text_in(self.settings.language),
                    });
                }
                for (id, account) in meta
                    .mnemonic_accounts
                    .sol
                    .iter()
                    .filter(|(_, account)| account.hidden)
                {
                    let source = meta
                        .mnemonics
                        .iter()
                        .find(|entry| entry.record_id == *id)
                        .map(|entry| entry.label.clone());
                    let path = SolAccountId::Mnemonic(*id, account.index)
                        .path_text_in(self.settings.language);
                    rows.push(HiddenRow {
                        id: HiddenId::Sol(SolAccountId::Mnemonic(*id, account.index)),
                        label: account.label.clone(),
                        address: account.address.clone(),
                        source: source
                            .map_or_else(|| path.clone(), |name| format!("{name} · {path}")),
                    });
                }
                for account in meta.hw_accounts.sol.iter().filter(|account| account.hidden) {
                    rows.push(HiddenRow {
                        id: HiddenId::Sol(SolAccountId::Hardware(account.index)),
                        label: account.label.clone(),
                        address: account.address.clone(),
                        source: "YubiKey".to_owned(),
                    });
                }
            }
        }
        rows
    }

    /// The end of a `내 계정` card: `숨긴 계정 n개 보기 ▸` and, opened, the hidden rows with
    /// `다시 보이기` (nothing when no account is hidden).
    pub fn hidden_items(&self, family: Family, items: &mut Vec<Item>) {
        let rows = self.hidden_rows(family);
        if rows.is_empty() {
            return;
        }
        let (toggle, base) = match family {
            Family::Evm => (ids::EVM_TOGGLE, ids::EVM_ROW_BASE),
            Family::Sol => (ids::SOL_TOGGLE, ids::SOL_ROW_BASE),
        };
        let lang = self.settings.language;
        let open = self.hidden_open;
        let count = rows.len().to_string();
        items.push(Item::Row(vec![Ctl::link(
            toggle,
            &if open {
                text::TOGGLE_CLOSE.fill(lang, [&count])
            } else {
                text::TOGGLE_OPEN.fill(lang, [&count])
            },
        )]));
        if !open {
            return;
        }
        items.push(Item::Help(text::HIDDEN_HELP.get(lang).to_owned()));
        for (row, hidden) in rows
            .into_iter()
            .take(usize::from(ids::ROW_SPAN))
            .enumerate()
        {
            items.push(Item::Muted(
                text::HIDDEN_ROW.fill(lang, [&hidden.label, &hidden.source]),
            ));
            let (shown, balance) = match family {
                Family::Evm => (
                    yw_core::evm::address::parse_address(&hidden.address).map_or_else(
                        |_| hidden.address.clone(),
                        |parsed| yw_core::evm::display::format_address(&parsed),
                    ),
                    self.balance_text(&hidden.address),
                ),
                Family::Sol => (
                    crate::ui::screens_btc::grouped(&hidden.address),
                    yw_core::sol::SolAddress::parse(&hidden.address)
                        .ok()
                        .and_then(|address| self.sol_balance(&address))
                        .map(|lamports| text::BALANCE.fill(lang, [&Self::sol_text(lamports)])),
                ),
            };
            items.push(Item::Mono(shown));
            if let Some(balance) = balance {
                items.push(Item::Help(text::LAST_READ.fill(lang, [&balance])));
            }
            items.push(Item::Row(vec![Ctl::button(
                base.saturating_add(u16::try_from(row).unwrap_or(u16::MAX)),
                text::UNHIDE.get(lang),
            )]));
        }
    }

    /// The hidden-account commands; `false` when `id` is not one.
    pub fn on_hidden_command(&mut self, id: u16) -> bool {
        let family = match id {
            ids::EVM_TOGGLE | ids::SOL_TOGGLE => {
                self.hidden_open = !self.hidden_open;
                self.refresh();
                return true;
            }
            _ if (ids::EVM_ROW_BASE..ids::EVM_ROW_BASE + ids::ROW_SPAN).contains(&id) => {
                (Family::Evm, id - ids::EVM_ROW_BASE)
            }
            _ if (ids::SOL_ROW_BASE..ids::SOL_ROW_BASE + ids::ROW_SPAN).contains(&id) => {
                (Family::Sol, id - ids::SOL_ROW_BASE)
            }
            _ => return false,
        };
        self.unhide(family.0, usize::from(family.1));
        true
    }

    /// `다시 보이기` of hidden row `row`: clears the mark only (no site grant comes back).
    pub fn unhide(&mut self, family: Family, row: usize) {
        let Some(hidden) = self.hidden_rows(family).into_iter().nth(row) else {
            return;
        };
        let Some(meta) = self.meta.as_mut() else {
            return;
        };
        let mark = |hidden: &mut bool| *hidden = false;
        match hidden.id {
            HiddenId::Evm(EvmAccountPref::Index(index)) => meta
                .evm_accounts
                .iter_mut()
                .filter(|account| account.index == index)
                .for_each(|account| mark(&mut account.hidden)),
            HiddenId::Evm(EvmAccountPref::Mnemonic(record, index)) => meta
                .mnemonics
                .iter_mut()
                .filter(|entry| entry.record_id == record)
                .flat_map(|entry| entry.evm.iter_mut())
                .filter(|account| account.index == index)
                .for_each(|account| mark(&mut account.hidden)),
            HiddenId::Evm(EvmAccountPref::Hardware(index)) => meta
                .hw_accounts
                .evm
                .iter_mut()
                .filter(|account| account.index == index)
                .for_each(|account| mark(&mut account.hidden)),
            HiddenId::Evm(EvmAccountPref::Record(_)) | HiddenId::Sol(SolAccountId::Imported(_)) => {
                return;
            }
            HiddenId::Sol(SolAccountId::Derived(index)) => meta
                .sol_accounts
                .iter_mut()
                .filter(|account| account.index == index)
                .for_each(|account| mark(&mut account.hidden)),
            HiddenId::Sol(SolAccountId::Mnemonic(record, index)) => meta
                .mnemonic_accounts
                .sol
                .iter_mut()
                .filter(|(id, account)| *id == record && account.index == index)
                .for_each(|(_, account)| mark(&mut account.hidden)),
            HiddenId::Sol(SolAccountId::Hardware(index)) => meta
                .hw_accounts
                .sol
                .iter_mut()
                .filter(|account| account.index == index)
                .for_each(|account| mark(&mut account.hidden)),
        }
        self.save_meta();
        self.notice(
            text::UNHIDDEN_NOTE.fill(self.settings.language, [&hidden.label]),
            Tone::Info,
        );
        self.refresh();
    }
}
