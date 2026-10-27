//! Connection grants (spec/05 §4.1; limits canonical in spec/02 §5.3, D31): one grant per origin,
//! 1..=16 accounts in return order (first = selected), at most 256 grants. The meta JSON form is
//! parsed and written by yw-app; this module holds the pure rules.

use super::BrowserOrigin;
use crate::evm::address::Address;

/// Most grants in meta `connected_sites`.
pub const MAX_GRANTS: usize = 256;
/// Most accounts in one grant (and in an `accountsChanged` payload).
pub const MAX_GRANT_ACCOUNTS: usize = 16;

/// A connected site (meta `connected_sites` entry).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectedSite {
    /// The origin (key).
    pub origin: BrowserOrigin,
    /// 1..=16 distinct accounts, return order, first = selected.
    pub accounts: Vec<Address>,
    /// The origin chain stored with the grant (a registered EVM chain when written).
    pub chain_id: u64,
    /// When the connection was approved (Unix ms).
    pub granted_at_unix_ms: u64,
}

/// Whether a connect-window selection of `count` accounts may be approved (`연결` enabled).
#[must_use]
pub const fn valid_selection(count: usize) -> bool {
    count >= 1 && count <= MAX_GRANT_ACCOUNTS
}

impl ConnectedSite {
    /// A grant, or `None` when the account list is empty, longer than 16 or repeats an account,
    /// or the chain id is 0.
    #[must_use]
    pub fn new(
        origin: BrowserOrigin,
        accounts: Vec<Address>,
        chain_id: u64,
        granted_at_unix_ms: u64,
    ) -> Option<Self> {
        let distinct = accounts
            .iter()
            .enumerate()
            .all(|(index, account)| !accounts.iter().take(index).any(|other| other == account));
        (valid_selection(accounts.len()) && distinct && chain_id >= 1).then_some(Self {
            origin,
            accounts,
            chain_id,
            granted_at_unix_ms,
        })
    }

    /// Whether `account` is granted.
    #[must_use]
    pub fn allows(&self, account: &Address) -> bool {
        self.accounts.contains(account)
    }

    /// Removes `account` (hidden or deleted wallet account, spec/05 §4.1); returns `false` when
    /// the grant became empty and must be deleted.
    pub fn remove_account(&mut self, account: &Address) -> bool {
        self.accounts.retain(|granted| granted != account);
        !self.accounts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{BrowserOrigin, ConnectedSite, MAX_GRANT_ACCOUNTS, valid_selection};
    use crate::evm::address::Address;

    fn account(byte: u8) -> Address {
        Address::from_bytes([byte; 20])
    }

    #[test]
    fn grant_limits() {
        let origin = BrowserOrigin::parse("https://app.example").unwrap();
        assert!(!valid_selection(0));
        assert!(valid_selection(1));
        assert!(valid_selection(MAX_GRANT_ACCOUNTS));
        assert!(!valid_selection(MAX_GRANT_ACCOUNTS + 1));
        let sixteen: Vec<_> = (1..=16).map(account).collect();
        assert!(ConnectedSite::new(origin.clone(), sixteen.clone(), 1, 0).is_some());
        let mut seventeen = sixteen.clone();
        seventeen.push(account(17));
        assert!(ConnectedSite::new(origin.clone(), seventeen, 1, 0).is_none());
        assert!(ConnectedSite::new(origin.clone(), Vec::new(), 1, 0).is_none());
        assert!(ConnectedSite::new(origin.clone(), vec![account(1), account(1)], 1, 0).is_none());
        assert!(ConnectedSite::new(origin.clone(), vec![account(1)], 0, 0).is_none());
        let mut site = ConnectedSite::new(origin, vec![account(1), account(2)], 1, 0).unwrap();
        assert!(site.allows(&account(2)));
        assert!(site.remove_account(&account(1)));
        assert!(!site.remove_account(&account(2)));
    }
}
