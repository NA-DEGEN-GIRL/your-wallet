//! Token-row visibility of the S10 token cards (spec/04 §2.6): `숨기기`·`다시 보이기`,
//! `잔액 0인 토큰 숨기기`, `숨긴 토큰 n개 보기`, and `삭제` of a user-added EVM token (S16).
//!
//! Display only (`crate::token_view`): `App::chain_tokens` still lists every registry and user
//! token, balances are still fetched for all of them, and the approval window, risk rules and
//! token recognition (registry trust, E19 lookalikes) never read meta `token_view`.

use yw_core::evm::address::Address;
use yw_core::evm::amount::U256;
use yw_core::sol::SplAllowEntry;
use yw_core::sol::template::spl_entries;

use crate::app::{App, Confirm, Screen};
use crate::app_evm::SendAsset;
use crate::network::NetworkId;
use crate::token_view::{MAX_HIDDEN_PER_NETWORK, MAX_HIDDEN_TOTAL, RowPlace, place};

/// One token of an EVM chain and where its card row goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmTokenRow {
    /// Index in [`App::chain_tokens`]: row buttons and send radios use it, so hiding a token
    /// never renumbers the others.
    pub index: usize,
    /// Contract.
    pub address: Address,
    /// Symbol (registry) or label (user token).
    pub symbol: String,
    /// The short ticker of the token card's amounts (2026-11-11): the registry's on-chain
    /// symbol (`USDG`), or a user token's label.
    pub ticker: String,
    /// The small note after the ticker on the token card: a pegged/bridged registry label's
    /// words (`Global Dollar, Paxos`), `사용자 추가` for a user token, else empty.
    pub name: String,
    /// Decimals.
    pub decimals: u8,
    /// A registry token: it can be hidden, not deleted.
    pub registered: bool,
    /// Balance of the selected account (`None`: not read).
    pub balance: Option<U256>,
    /// Card placement.
    pub place: RowPlace,
}

/// The words of a registry token's label without its symbol: `USDG (Global Dollar, Paxos)` →
/// `Global Dollar, Paxos`; a label of another form whole; empty without a label.
fn token_note(token: &yw_core::evm::chain::KnownToken) -> String {
    let Some(label) = token.label else {
        return String::new();
    };
    label
        .strip_prefix(token.symbol)
        .map(str::trim_start)
        .and_then(|rest| rest.strip_prefix('('))
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or(label)
        .to_owned()
}

fn evm_network(chain_id: u64) -> String {
    NetworkId::Eip155(chain_id).to_string()
}

fn limit_text() -> String {
    format!(
        "더 숨길 수 없습니다(네트워크당 {MAX_HIDDEN_PER_NETWORK}개, 전체 {MAX_HIDDEN_TOTAL}개까지)."
    )
}

impl App {
    /// Whether the user hid `token` on `chain_id` (meta `token_view`).
    #[must_use]
    pub fn evm_token_hidden(&self, chain_id: u64, token: &Address) -> bool {
        self.meta.as_ref().is_some_and(|meta| {
            meta.token_view
                .is_hidden(&evm_network(chain_id), &token.to_lower_hex())
        })
    }

    /// `잔액 0인 토큰 숨기기` (meta `token_view.hide_zero`).
    #[must_use]
    pub fn evm_hide_zero(&self) -> bool {
        self.meta
            .as_ref()
            .is_some_and(|meta| meta.token_view.hide_zero)
    }

    /// Every token of `chain_id` (registry, then user tokens) with its balance and placement.
    #[must_use]
    pub fn evm_token_rows(&self, chain_id: u64) -> Vec<EvmTokenRow> {
        let hide_zero = self.evm_hide_zero();
        let registry = yw_core::evm::chain::builtin_chain(chain_id)
            .map(|chain| chain.tokens)
            .unwrap_or_default();
        self.chain_tokens(chain_id)
            .into_iter()
            .enumerate()
            .map(|(index, (address, symbol, decimals, registered))| {
                let balance = self.token_balance(chain_id, &address);
                let known = registry
                    .iter()
                    .find(|token| registered && token.address == address);
                let (ticker, name) = match known {
                    Some(token) => (token.symbol.to_owned(), token_note(token)),
                    None if registered => (symbol.clone(), String::new()),
                    None => (symbol.clone(), "사용자 추가".to_owned()),
                };
                EvmTokenRow {
                    index,
                    address,
                    symbol,
                    ticker,
                    name,
                    decimals,
                    registered,
                    balance,
                    place: place(
                        self.evm_token_hidden(chain_id, &address),
                        balance.map(|value| value == U256::ZERO),
                        hide_zero,
                    ),
                }
            })
            .collect()
    }

    /// `숨기기` / `다시 보이기` of token row `index` on the active chain.
    pub fn toggle_evm_token_hidden(&mut self, index: usize) {
        let chain_id = self.settings.evm_chain_id;
        let Some((address, ..)) = self.chain_tokens(chain_id).into_iter().nth(index) else {
            return;
        };
        let hide = !self.evm_token_hidden(chain_id, &address);
        let Some(meta) = self.meta.as_mut() else {
            return;
        };
        if meta
            .token_view
            .set_hidden(&evm_network(chain_id), &address.to_lower_hex(), hide)
        {
            if meta.token_view.hidden_of(&evm_network(chain_id)).is_empty() {
                self.evm.show_hidden_tokens = false;
            }
            self.save_meta();
        } else {
            self.info = Some(limit_text());
        }
        self.refresh();
    }

    /// `잔액 0인 토큰 숨기기` changed.
    pub fn set_evm_hide_zero(&mut self, on: bool) {
        if let Some(meta) = self.meta.as_mut()
            && meta.token_view.hide_zero != on
        {
            meta.token_view.hide_zero = on;
            self.save_meta();
        }
        self.refresh();
    }

    /// `삭제` of token row `index`: user tokens only (registry tokens can only be hidden).
    pub fn request_delete_token(&mut self, index: usize) {
        let chain_id = self.settings.evm_chain_id;
        if let Some((address, _, _, false)) = self.chain_tokens(chain_id).into_iter().nth(index) {
            self.evm.token_delete = Some((chain_id, address));
            self.set_screen(Screen::Confirm(Confirm::TokenDelete));
        }
    }

    /// The label and contract of the user token awaiting the delete confirmation.
    #[must_use]
    pub fn token_delete_target(&self) -> Option<(String, Address)> {
        let (chain_id, address) = self.evm.token_delete?;
        let entry = self
            .meta
            .as_ref()?
            .tokens_of(&evm_network(chain_id))
            .into_iter()
            .find(|entry| entry.address == address.to_lower_hex())?;
        Some((entry.label, address))
    }

    /// The delete confirmation's `삭제`: removes the token from meta `tokens` (and its hidden
    /// mark). Activity rows that name it stay (they show raw units from then on).
    pub fn delete_token(&mut self) {
        let Some((chain_id, address)) = self.evm.token_delete.take() else {
            return;
        };
        if self.token_delete_target_of(chain_id, &address)
            && let Some(meta) = self.meta.as_mut()
        {
            meta.remove_token(&evm_network(chain_id), &address.to_lower_hex());
            self.save_meta();
            if self.evm.send.asset == SendAsset::Token(address) {
                self.evm.send.asset = SendAsset::Native;
                self.evm.send.quote = None;
            }
        }
    }

    fn token_delete_target_of(&self, chain_id: u64, address: &Address) -> bool {
        self.meta.as_ref().is_some_and(|meta| {
            meta.tokens_of(&evm_network(chain_id))
                .iter()
                .any(|entry| entry.address == address.to_lower_hex())
        })
    }

    // ----- Solana allowlist rows ----------------------------------------------------------

    /// The `NetworkId` string of the selected Solana cluster.
    #[must_use]
    pub fn sol_token_network(&self) -> String {
        NetworkId::Solana(self.settings.solana.cluster).to_string()
    }

    /// Whether the user hid this allowlisted token on the selected cluster.
    #[must_use]
    pub fn sol_token_hidden(&self, entry: &SplAllowEntry) -> bool {
        self.meta.as_ref().is_some_and(|meta| {
            meta.token_view
                .is_hidden(&self.sol_token_network(), &entry.mint.to_base58())
        })
    }

    /// `숨기기` / `다시 보이기` of allowlist row `index` of the selected cluster.
    pub fn toggle_sol_token_hidden(&mut self, index: usize) {
        let Some(entry) = spl_entries(self.sol_cluster()).nth(index) else {
            return;
        };
        let hide = !self.sol_token_hidden(entry);
        let network = self.sol_token_network();
        let Some(meta) = self.meta.as_mut() else {
            return;
        };
        if meta
            .token_view
            .set_hidden(&network, &entry.mint.to_base58(), hide)
        {
            if meta.token_view.hidden_of(&network).is_empty() {
                self.sol.show_hidden_tokens = false;
            }
            self.save_meta();
        } else {
            self.info = Some(limit_text());
        }
        self.refresh();
    }
}
