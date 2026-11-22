//! Hidden accounts (spec/04 §2.6, 2026-11-08). `숨기기` only marks meta `hidden` (and takes the
//! account out of every dApp grant, spec/05 §4.9); until now nothing showed those accounts again.
//! The EVM, Solana and Bitcoin account cards (`내 EVM 계정`, `내 Solana 계정`, `내 Bitcoin 계정`)
//! list them under `숨긴 계정 n개 보기 ▸`, and `다시 보이기` clears the mark. Site connections
//! are not restored (the user connects again from the dApp). Bitcoin accounts can be hidden since
//! 2026-11-15 (meta `btc_account_view`, spec/08 §12.3d); the list shows the settings network's.
//!
//! 2026-11-22 (S4d E0c): the command ids and the render builder `hidden_items` moved to
//! `ui::screens_hidden` (shell code); this file keeps the rows, the presses and `unhide`.

use crate::app::{App, Wallet};
use crate::app_sol::SolAccountId;
use crate::meta::EvmAccountPref;
use yw_core::lang::Lang;
use yw_engine::cmd::{HiddenPress, Row};
use yw_engine::screen::Tone;

/// The fixed texts of the hidden-account rows (spec/14).
pub mod text {
    yw_core::texts! {
        /// The note after `숨기기`: {0} the account's label (2026-11-15: "… '내 계정' 아래 …" before;
        /// the cards are `내 EVM 계정` and `내 Solana 계정`).
        HIDDEN_NOTE(1) = "'{0}'을(를) 숨겼습니다. 이 계정의 사이트 연결도 해제했습니다. 계정 카드 아래 '숨긴 계정'에서 다시 볼 수 있습니다."
            / "'{0}' is hidden. Its site connections were removed too. You can see it again under 'Hidden accounts' on the accounts card.";
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

/// Which account card.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// EVM tab.
    Evm,
    /// Solana tab.
    Sol,
    /// Bitcoin tab (the settings network's accounts).
    Btc,
}

/// A hidden account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiddenId {
    /// An EVM account.
    Evm(EvmAccountPref),
    /// A Solana account.
    Sol(SolAccountId),
    /// A Bitcoin account of a network.
    Btc(yw_core::btc::BtcNetwork, yw_core::btc::BtcAccountId),
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

impl Wallet {
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
                        // The holder cards as on the drop-down (2026-11-15; `YubiKey` before).
                        source: self.card_source(yw_engine::screen::evm_card_role(account.index)),
                    });
                }
            }
            Family::Btc => {
                let network = self.btc_network_now();
                let ctx = self.btc_ctx();
                for (account, label) in meta.btc_labels(network, self.settings.language) {
                    if !meta.btc_hidden(network, account) {
                        continue;
                    }
                    let Some(stored) = ctx.accounts().into_iter().find(|m| m.id() == account)
                    else {
                        continue;
                    };
                    rows.push(HiddenRow {
                        id: HiddenId::Btc(network, account),
                        label,
                        address: stored
                            .address(yw_core::bip32::path::BtcChain::Receive, 0)
                            .map(|address| address.as_str().to_owned())
                            .unwrap_or_default(),
                        source: self.btc_source_text(stored.account(), network),
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
                        source: self.card_source(yw_engine::screen::sol_card_role(account.index)),
                    });
                }
            }
        }
        rows
    }
}

impl Wallet {
    /// The hidden-account presses (2026-11-18, S3 C1: a `HiddenPress`; before, the control id).
    pub(crate) fn on_hidden(&mut self, press: HiddenPress) {
        let family = match press {
            HiddenPress::EvmToggle | HiddenPress::SolToggle | HiddenPress::BtcToggle => {
                self.hidden_open = !self.hidden_open;
                self.refresh();
                return;
            }
            HiddenPress::EvmUnhide(Row(row)) => (Family::Evm, row),
            HiddenPress::SolUnhide(Row(row)) => (Family::Sol, row),
            HiddenPress::BtcUnhide(Row(row)) => (Family::Btc, row),
        };
        self.unhide(family.0, usize::from(family.1));
    }
}

impl App {
    /// Test adapter (S3 C1, plan §3.2): presses hidden-account control `id` directly, as the
    /// tests did before; `false` when `id` is not one.
    #[cfg(test)]
    pub(crate) fn on_hidden_command(&mut self, id: u16) -> bool {
        self.press_family(
            id,
            |press| match press {
                yw_engine::cmd::Press::Hidden(press) => Some(press),
                _ => None,
            },
            |app, press| {
                app.on_hidden(press);
                true
            },
        )
    }
}

impl Wallet {
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
            HiddenId::Btc(network, account) => {
                meta.btc_view_update(network, account, |view| view.hidden = false);
            }
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
