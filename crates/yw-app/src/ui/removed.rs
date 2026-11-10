//! The "지워지는 계정" block (spec/04 §2.18, spec/10 §15, 2026-11-10): what a removal takes out
//! of the wallet, account by account — its name, chain, full address in the §3.3 groups and the
//! native balance as last read on the network shown now (the same caches as the hidden-account
//! rows; no new RPC). A positive balance is a 고위험 band, an unknown one a 주의 band; for a key
//! that is lost for good the sentence goes inside that removal's own band instead (T-YK-KEY-LOST
//! or the imported-key band). The confirmation overlays, typed words and holds are unchanged.

use yw_core::evm::address::Address;
use yw_core::sol::SolAddress;
use yw_core::yubikey::plan::KeyRole;
use yw_core::yubikey::record::{HwKeyRecord, RecordedSlot};

use crate::app::App;
use crate::ui::main_window::{Item, Tone};

/// A native balance as last read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LastBalance {
    /// More than zero: the amount text and the network.
    Positive {
        /// `1.25 SepoliaETH`.
        text: String,
        /// The network it was read on.
        network: String,
    },
    /// Zero on `network`.
    Zero {
        /// The network it was read on.
        network: String,
    },
    /// Never read on the network shown now.
    Unknown,
}

/// One account a removal takes out of the wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemovedAccount {
    /// The account's name.
    pub label: String,
    /// `EVM`, `Solana`, `Bitcoin`, `Zcash`.
    pub chain: &'static str,
    /// Full addresses, grouped (§3.3).
    pub addresses: Vec<String>,
    /// The balance as last read.
    pub balance: LastBalance,
    /// The key is gone for good with this removal (no recovery words and on no other card; an
    /// imported key).
    pub lost: bool,
    /// What still signs for it, when that is the question ("`YubiKey` #m(으)로 계속 서명").
    pub note: Option<String>,
    /// The account stays usable (another card holds the key): its balance is only shown.
    pub kept: bool,
}

/// The unknown-balance sentence.
pub const T_BALANCE_UNKNOWN: &str = "잔액을 확인하지 못했습니다(이 네트워크를 연 적 없음).";
/// The block's last line while an account leaves the wallet: what the balances above cover
/// (the EVM imported-key confirmation said it before the block, 2026-11-10).
pub const T_BALANCE_SCOPE: &str = "위 잔액은 지금 네트워크의 기본 자산만 마지막으로 읽은 값입니다 — 다른 네트워크와 토큰 잔액은 확인하지 않았습니다.";

/// The balance sentence of an account about to be removed (none for zero).
#[must_use]
pub fn balance_sentence(balance: &LastBalance) -> Option<String> {
    match balance {
        LastBalance::Positive { text, network } => Some(format!(
            "이 계정에 잔액이 있습니다: {text} ({network}). 지우기 전에 다른 계정으로 옮기세요."
        )),
        LastBalance::Unknown => Some(T_BALANCE_UNKNOWN.to_owned()),
        LastBalance::Zero { .. } => None,
    }
}

/// Pushes the block of `accounts`. Returns the balance sentences of the accounts lost for good:
/// the caller puts them inside its own band (T-YK-KEY-LOST, the imported-key band).
pub fn removed_items(accounts: &[RemovedAccount], items: &mut Vec<Item>) -> Vec<String> {
    let mut inside = Vec::new();
    for account in accounts {
        items.push(Item::Text(format!("{} · {}", account.label, account.chain)));
        for address in &account.addresses {
            items.push(Item::Mono(address.clone()));
        }
        if let Some(note) = &account.note {
            items.push(Item::Help(note.clone()));
        }
        match (&account.balance, balance_sentence(&account.balance)) {
            (LastBalance::Zero { network }, _) => {
                items.push(Item::Help(format!("마지막으로 읽은 잔액: 0 ({network})")));
            }
            (LastBalance::Positive { text, network }, _) if account.kept => {
                items.push(Item::Help(format!(
                    "마지막으로 읽은 잔액: {text} ({network})"
                )));
            }
            (LastBalance::Unknown, _) if account.kept => {}
            (_, Some(sentence)) if account.lost => inside.push(sentence),
            (LastBalance::Positive { .. }, Some(sentence)) => {
                items.push(Item::Banner(sentence, Tone::HighRisk));
            }
            (_, Some(sentence)) => items.push(Item::Banner(sentence, Tone::Warn)),
            (_, None) => {}
        }
    }
    // Only the shown network's native balance was looked at: said once, while an account
    // leaves the wallet (not when every key stays on another card).
    if accounts.iter().any(|account| !account.kept) {
        items.push(Item::Help(T_BALANCE_SCOPE.to_owned()));
    }
    inside
}

/// The chain name of a card key.
const fn role_chain(role: KeyRole) -> &'static str {
    match role {
        KeyRole::Evm { btc: None, .. } => "EVM",
        KeyRole::Evm { btc: Some(_), .. } => "EVM·Bitcoin",
        KeyRole::Btc { .. } => "Bitcoin",
        KeyRole::Sol { .. } => "Solana",
        KeyRole::Zec { .. } => "Zcash",
    }
}

impl App {
    /// The EVM native balance of `address` on the selected network, as last read.
    #[must_use]
    pub fn evm_last_balance(&self, address: &Address) -> LastBalance {
        let chain_id = self.settings.evm_chain_id;
        let network = self.network_label(chain_id);
        match self.native_balance(chain_id, address) {
            Some(balance) if balance.is_zero() => LastBalance::Zero { network },
            Some(balance) => LastBalance::Positive {
                text: self.native_text(chain_id, &balance),
                network,
            },
            None => LastBalance::Unknown,
        }
    }

    /// The SOL balance of `address` on the cluster shown now, as last read.
    #[must_use]
    pub fn sol_last_balance(&self, address: &SolAddress) -> LastBalance {
        let network = self.sol_cluster().display_name().to_owned();
        match self.sol_balance(address) {
            Some(0) => LastBalance::Zero { network },
            Some(lamports) => LastBalance::Positive {
                text: Self::sol_text(lamports),
                network,
            },
            None => LastBalance::Unknown,
        }
    }

    /// The BTC balance of the account whose stable address is `address` on the settings
    /// network, as last read (`Unknown` until a refresh saw that network).
    #[must_use]
    pub fn btc_last_balance(&self, address: &str) -> LastBalance {
        let ctx = self.btc_ctx();
        let network = ctx.net().display_name().to_owned();
        let meta = ctx.accounts().into_iter().find(|meta| {
            meta.address(yw_core::bip32::path::BtcChain::Receive, 0)
                .is_ok_and(|own| own.as_str() == address)
        });
        let Some(meta) = meta.filter(|meta| meta.max_tip_seen() > 0) else {
            return LastBalance::Unknown;
        };
        let balance = meta.balance(meta.max_tip_seen(), &[]);
        let total = balance
            .available
            .checked_add(balance.frozen)
            .and_then(|sum| sum.checked_add(balance.pending))
            .unwrap_or(yw_core::btc::Sats::MAX);
        if total.get() == 0 {
            LastBalance::Zero { network }
        } else {
            LastBalance::Positive {
                text: crate::app_btc::BtcUi::amount_text(total),
                network,
            }
        }
    }

    /// The ZEC balance of `address` when it is the account the shown network's last refresh
    /// read (`Unknown` otherwise).
    #[must_use]
    pub fn zec_last_balance(&self, address: &str) -> LastBalance {
        let network = self.zec_network();
        let read = self.zec.snapshot.as_ref().filter(|(net, snapshot)| {
            *net == network
                && snapshot.utxo_error.is_none()
                && self
                    .zec_account()
                    .is_some_and(|account| account.address() == address)
        });
        let Some((_, snapshot)) = read else {
            return LastBalance::Unknown;
        };
        let zats = snapshot
            .utxos
            .iter()
            .fold(0_u64, |sum, utxo| sum.saturating_add(utxo.value));
        let network = network.display_name().to_owned();
        if zats == 0 {
            LastBalance::Zero { network }
        } else {
            LastBalance::Positive {
                text: format!("{} ZEC", yw_core::zec::format_zec(zats)),
                network,
            }
        }
    }

    /// An EVM account about to be removed.
    #[must_use]
    pub fn evm_removed(&self, label: String, address: &Address, lost: bool) -> RemovedAccount {
        RemovedAccount {
            label,
            chain: "EVM",
            addresses: vec![yw_core::evm::display::format_address(address)],
            balance: self.evm_last_balance(address),
            lost,
            note: None,
            kept: false,
        }
    }

    /// A Solana account about to be removed.
    #[must_use]
    pub fn sol_removed(&self, label: String, address: &SolAddress, lost: bool) -> RemovedAccount {
        RemovedAccount {
            label,
            chain: "Solana",
            addresses: vec![yw_core::sol::address::grouped(address)],
            balance: self.sol_last_balance(address),
            lost,
            note: None,
            kept: false,
        }
    }

    /// A Bitcoin account (its stable address) about to be removed.
    #[must_use]
    pub fn btc_removed(&self, label: String, address: &str, lost: bool) -> RemovedAccount {
        RemovedAccount {
            label,
            chain: "Bitcoin",
            addresses: vec![crate::ui::screens_btc::grouped(address)],
            balance: self.btc_last_balance(address),
            lost,
            note: None,
            kept: false,
        }
    }

    /// A Zcash account about to be removed.
    #[must_use]
    pub fn zec_removed(&self, label: String, address: &str, lost: bool) -> RemovedAccount {
        RemovedAccount {
            label,
            chain: "Zcash",
            addresses: vec![crate::ui::screens_btc::grouped(address)],
            balance: self.zec_last_balance(address),
            lost,
            note: None,
            kept: false,
        }
    }

    /// A card key that leaves a card (a cleared or re-slotted slot, a removed record): its
    /// addresses and balance; lost when it has no recovery words and `others` hold none of it
    /// (`lose_key`: the key itself goes — false when only the record goes); the note says what
    /// still signs for it.
    #[must_use]
    pub fn card_removed(
        &self,
        slot: &RecordedSlot,
        others: &[HwKeyRecord],
        lose_key: bool,
    ) -> RemovedAccount {
        let texts =
            yw_core::yubikey::plan::address_texts(slot.role, &slot.public).unwrap_or_default();
        let balance = texts
            .first()
            .map_or(LastBalance::Unknown, |first| match slot.role {
                KeyRole::Evm { .. } => yw_core::evm::address::parse_address(first)
                    .map_or(LastBalance::Unknown, |address| {
                        self.evm_last_balance(&address)
                    }),
                KeyRole::Btc { .. } => self.btc_last_balance(first),
                KeyRole::Sol { .. } => SolAddress::parse(first)
                    .map_or(LastBalance::Unknown, |address| {
                        self.sol_last_balance(&address)
                    }),
                KeyRole::Zec { .. } => self.zec_last_balance(first),
            });
        let addresses = texts
            .iter()
            .map(|text| {
                yw_core::evm::address::parse_address(text).map_or_else(
                    |_| crate::ui::screens_btc::grouped(text),
                    |address| yw_core::evm::display::format_address(&address),
                )
            })
            .collect();
        let holders = crate::yubikey::holders(others, slot.role);
        let note = if holders.is_empty() {
            "이 지갑에서 서명 불가".to_owned()
        } else {
            let list: Vec<String> = holders.iter().map(|serial| format!("#{serial}")).collect();
            let cards = list.join("·");
            // The particle follows how the last digit is read (#…2 → 로, #…3 → 으로).
            format!(
                "YubiKey {cards}{} 계속 서명",
                crate::ui::theme::direction_particle(&cards)
            )
        };
        RemovedAccount {
            label: format!("{} ({})", slot.role.title(), slot.path_text()),
            chain: role_chain(slot.role),
            addresses,
            balance,
            lost: lose_key && holders.is_empty() && !slot.path_known,
            note: Some(note),
            kept: !holders.is_empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LastBalance, RemovedAccount, T_BALANCE_SCOPE, T_BALANCE_UNKNOWN, removed_items};
    use crate::ui::main_window::{Item, Tone};

    fn account(balance: LastBalance, lost: bool) -> RemovedAccount {
        RemovedAccount {
            label: "계정 2".to_owned(),
            chain: "EVM",
            addresses: vec!["0x9858 EfFD 232B 4033 E47d 9000 3D41 EC34 EcaE da94".to_owned()],
            balance,
            lost,
            note: None,
            kept: false,
        }
    }

    /// 2026-11-10: a cached balance above zero is a 고위험 band, no cache a 주의 band; zero is a
    /// muted line; a key lost for good hands its sentence to the caller's band; the block ends by
    /// saying other networks and tokens were not checked.
    #[test]
    fn removed_accounts_say_their_last_balance() {
        let mut items = Vec::new();
        let inside = removed_items(
            &[
                account(
                    LastBalance::Positive {
                        text: "1.25 SepoliaETH".to_owned(),
                        network: "Sepolia 테스트넷".to_owned(),
                    },
                    false,
                ),
                account(LastBalance::Unknown, false),
                account(
                    LastBalance::Zero {
                        network: "Sepolia 테스트넷".to_owned(),
                    },
                    false,
                ),
                account(LastBalance::Unknown, true),
            ],
            &mut items,
        );
        let bands: Vec<(&str, Tone)> = items
            .iter()
            .filter_map(|item| match item {
                Item::Banner(text, tone) => Some((text.as_str(), *tone)),
                _ => None,
            })
            .collect();
        assert_eq!(
            bands,
            [
                (
                    "이 계정에 잔액이 있습니다: 1.25 SepoliaETH (Sepolia 테스트넷). 지우기 전에 다른 계정으로 옮기세요.",
                    Tone::HighRisk
                ),
                (T_BALANCE_UNKNOWN, Tone::Warn),
            ]
        );
        assert!(items.iter().any(|item| matches!(
            item,
            Item::Help(text) if text == "마지막으로 읽은 잔액: 0 (Sepolia 테스트넷)"
        )));
        assert_eq!(inside, [T_BALANCE_UNKNOWN]);
        // What the balances cover, once, at the end.
        assert!(matches!(items.last(), Some(Item::Help(text)) if text == T_BALANCE_SCOPE));
        assert_eq!(
            items
                .iter()
                .filter(|item| matches!(item, Item::Mono(_)))
                .count(),
            4
        );
    }
}
