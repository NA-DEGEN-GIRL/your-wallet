//! The wallet half of the "지워지는 계정" block (spec/04 §2.18, spec/10 §15): what a removal takes
//! out of the wallet, account by account, with the native balance as last read on the network
//! shown now (the same caches as the hidden-account rows; no new RPC). The block is drawn by
//! `ui::removed`.
//!
//! 2026-11-23 (spec/15 §11.4 S4d E0b): moved here from `ui::removed` unchanged (bodies, docs), so
//! every `impl Wallet` sits in a file that moves to yw-engine at E1.

use yw_core::evm::address::Address;
use yw_core::sol::SolAddress;

use crate::screen::{LastBalance, RemovedAccount};
use crate::wallet::Wallet;

impl Wallet {
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
        let network = self
            .sol_cluster()
            .display_name_in(self.settings.language)
            .to_owned();
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
        let network = ctx.net().display_name_in(self.settings.language).to_owned();
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
                text: crate::wallet::app_btc::BtcUi::amount_text(total),
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
            addresses: vec![crate::text::grouped(address)],
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
            addresses: vec![crate::text::grouped(address)],
            balance: self.zec_last_balance(address),
            lost,
            note: None,
            kept: false,
        }
    }
}
