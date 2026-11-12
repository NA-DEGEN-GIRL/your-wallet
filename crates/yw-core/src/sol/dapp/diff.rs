//! The simulation diff of a dApp transaction (spec/07 §20.7): which accounts the simulation is
//! asked to return (always a subset of the transaction's own keys) and what changed between the
//! RPC pre-state and the simulated post-state. Both states are RPC references shown in
//! `0x0515`; nothing here is signed.
#![deny(clippy::indexing_slicing)]

use crate::sol::address::{SolAddress, SolCluster, TOKEN_PROGRAM};
use crate::sol::template::spl_entry;
use crate::sol::token::{MintView, TokenAccountView, parse_token_account_any};

/// Most accounts the simulation returns.
pub const SOL_DAPP_MAX_WATCH: usize = 64;

/// One account as the RPC returned it (pre-state: the first 166 data bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountSnapshot {
    /// Owner program.
    pub owner: SolAddress,
    /// Lamports.
    pub lamports: u64,
    /// Data (pre-state: `dataSlice 0/166`).
    pub data: Vec<u8>,
}

impl AccountSnapshot {
    /// The token account view of a Token or Token-2022 account.
    #[must_use]
    pub fn token(&self) -> Option<TokenAccountView> {
        parse_token_account_any(&self.owner, &self.data)
    }
}

/// A snapshot of `account` in `states` (`None`: not listed or the account does not exist).
fn find<'a>(
    states: &'a [(SolAddress, Option<AccountSnapshot>)],
    account: &SolAddress,
) -> Option<&'a AccountSnapshot> {
    states
        .iter()
        .find(|(address, _)| address == account)
        .and_then(|(_, snapshot)| snapshot.as_ref())
}

/// Whether a token account is the wallet's: it owns it, is its delegate or may close it.
fn wallet_related(view: &TokenAccountView, wallet: &SolAddress) -> bool {
    view.owner == *wallet || view.delegate == Some(*wallet) || view.close_authority == Some(*wallet)
}

/// The accounts the simulation returns (`accounts.addresses`): the wallet, the writable token
/// accounts the wallet owns, may spend or may close, and the writable accounts that do not exist
/// yet — in that order, without repeats, only keys of the transaction itself, at most
/// `min(64, tx_keys.len())`.
#[must_use]
pub fn watch_set(
    wallet: &SolAddress,
    tx_keys: &[SolAddress],
    writable: &[SolAddress],
    pre: &[(SolAddress, Option<AccountSnapshot>)],
) -> Vec<SolAddress> {
    let cap = SOL_DAPP_MAX_WATCH.min(tx_keys.len());
    let mut out: Vec<SolAddress> = Vec::new();
    let mut add = |address: &SolAddress| {
        if out.len() < cap && tx_keys.contains(address) && !out.contains(address) {
            out.push(*address);
        }
    };
    add(wallet);
    for address in writable {
        if find(pre, address)
            .and_then(AccountSnapshot::token)
            .is_some_and(|view| wallet_related(&view, wallet))
        {
            add(address);
        }
    }
    for address in writable {
        let missing = pre
            .iter()
            .any(|(listed, snapshot)| listed == address && snapshot.is_none());
        if missing {
            add(address);
        }
    }
    out
}

/// Which authority changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityKind {
    /// The owner of a token account.
    Owner,
    /// The delegate of a token account.
    Delegate,
    /// The close authority of a token account.
    CloseAuthority,
    /// The owner program of the wallet account (Assign).
    WalletOwnerProgram,
}

/// One change between pre-state and simulated post-state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// The wallet's lamports (the fee included when the wallet pays it).
    Sol {
        /// Before.
        pre: u64,
        /// After.
        post: u64,
    },
    /// The public balance of a token account the wallet owns.
    Token {
        /// Token account.
        account: SolAddress,
        /// Mint.
        mint: SolAddress,
        /// Token-2022 account.
        program2022: bool,
        /// Raw amount before.
        pre: u64,
        /// Raw amount after.
        post: u64,
        /// Decimals: `(decimals, true)` from the allowlist, `(decimals, false)` from the RPC
        /// mint; `None`: raw units.
        decimals: Option<(u8, bool)>,
    },
    /// An authority of a token account, or the wallet's owner program.
    Authority {
        /// The account.
        account: SolAddress,
        /// Which authority.
        what: AuthorityKind,
        /// Before (`None`: none).
        before: Option<SolAddress>,
        /// After (`None`: none).
        after: Option<SolAddress>,
    },
    /// A token account that existed and is gone (or no longer a token account).
    Closed {
        /// The account.
        account: SolAddress,
    },
    /// An account that did not exist and does after.
    Created {
        /// The account.
        account: SolAddress,
        /// Its mint when it is a token account.
        mint: Option<SolAddress>,
    },
}

impl Change {
    /// Whether this is an authority change (X15).
    #[must_use]
    pub const fn is_authority(&self) -> bool {
        matches!(self, Self::Authority { .. })
    }
}

/// The decimals to show for `mint`: the allowlist of `cluster`, else the RPC mint.
#[must_use]
pub fn mint_decimals(
    cluster: SolCluster,
    mint: &SolAddress,
    mints: &[(SolAddress, MintView)],
) -> Option<(u8, bool)> {
    if let Some(entry) = spl_entry(cluster, mint) {
        return Some((entry.decimals, true));
    }
    mints
        .iter()
        .find(|(address, _)| address == mint)
        .map(|(_, view)| (view.decimals, false))
}

fn authority_changes(
    account: SolAddress,
    before: &TokenAccountView,
    after: &TokenAccountView,
    out: &mut Vec<Change>,
) {
    for (what, old, new) in [
        (AuthorityKind::Owner, Some(before.owner), Some(after.owner)),
        (AuthorityKind::Delegate, before.delegate, after.delegate),
        (
            AuthorityKind::CloseAuthority,
            before.close_authority,
            after.close_authority,
        ),
    ] {
        if old != new {
            out.push(Change::Authority {
                account,
                what,
                before: old,
                after: new,
            });
        }
    }
}

/// The changes of the accounts in `post` against `pre` (spec/07 §20.7), authority changes
/// first: the wallet's lamports and owner program; for token accounts, the public balance of
/// those the wallet owns (before or after), every owner, delegate or close-authority change,
/// closing; and accounts the pre-state lists as missing that exist after.
#[must_use]
pub fn changes(
    wallet: &SolAddress,
    cluster: SolCluster,
    pre: &[(SolAddress, Option<AccountSnapshot>)],
    post: &[(SolAddress, Option<AccountSnapshot>)],
    mints: &[(SolAddress, MintView)],
) -> Vec<Change> {
    let mut authority = Vec::new();
    let mut other = Vec::new();
    for (account, after) in post {
        let before = find(pre, account);
        let listed_missing = pre
            .iter()
            .any(|(listed, snapshot)| listed == account && snapshot.is_none());
        if account == wallet {
            let (pre_lamports, post_lamports) = (
                before.map_or(0, |snapshot| snapshot.lamports),
                after.as_ref().map_or(0, |snapshot| snapshot.lamports),
            );
            if pre_lamports != post_lamports {
                other.push(Change::Sol {
                    pre: pre_lamports,
                    post: post_lamports,
                });
            }
            if let (Some(before), Some(after)) = (before, after)
                && before.owner != after.owner
            {
                authority.push(Change::Authority {
                    account: *account,
                    what: AuthorityKind::WalletOwnerProgram,
                    before: Some(before.owner),
                    after: Some(after.owner),
                });
            }
            continue;
        }
        let pre_view = before.and_then(AccountSnapshot::token);
        let post_view = after.as_ref().and_then(AccountSnapshot::token);
        match (before, &pre_view, &post_view) {
            (_, Some(old), Some(new)) => {
                authority_changes(*account, old, new, &mut authority);
                let mine = old.owner == *wallet || new.owner == *wallet;
                if mine && old.amount != new.amount {
                    other.push(Change::Token {
                        account: *account,
                        mint: new.mint,
                        program2022: after
                            .as_ref()
                            .is_some_and(|snapshot| snapshot.owner != TOKEN_PROGRAM),
                        pre: old.amount,
                        post: new.amount,
                        decimals: mint_decimals(cluster, &new.mint, mints),
                    });
                }
            }
            (_, Some(_), None) => other.push(Change::Closed { account: *account }),
            (None, None, _) if listed_missing && after.is_some() => {
                other.push(Change::Created {
                    account: *account,
                    mint: post_view.map(|view| view.mint),
                });
                if let (Some(new), Some(snapshot)) = (&post_view, after)
                    && new.owner == *wallet
                    && new.amount != 0
                {
                    other.push(Change::Token {
                        account: *account,
                        mint: new.mint,
                        program2022: snapshot.owner != TOKEN_PROGRAM,
                        pre: 0,
                        post: new.amount,
                        decimals: mint_decimals(cluster, &new.mint, mints),
                    });
                }
            }
            _ => {}
        }
    }
    authority.extend(other);
    authority
}
