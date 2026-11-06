//! Per-chain derivation paths (D29, spec/02 §3.3). `sol_path` (M7) lives with `slip10` and is
//! re-exported here.

use super::{Bip32Path, HARDENED};
use crate::error::KeyError;
pub use crate::slip10::sol_path;

/// Highest account index the core accepts (EVM and Solana).
pub const MAX_ACCOUNT_INDEX: u32 = 999;

/// An account index in `0..=MAX_ACCOUNT_INDEX`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountIndex(u32);

impl AccountIndex {
    /// Account 0 (the backup-confirmation and passphrase-check account).
    pub const ZERO: Self = Self(0);

    /// Validates the index.
    ///
    /// # Errors
    ///
    /// [`KeyError::InvalidAccountIndex`] above 999.
    pub const fn new(index: u32) -> Result<Self, KeyError> {
        if index > MAX_ACCOUNT_INDEX {
            return Err(KeyError::InvalidAccountIndex);
        }
        Ok(Self(index))
    }

    /// The index value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// BIP43 purpose of a Bitcoin account node: BIP44 (P2PKH), BIP49 (P2SH-P2WPKH), BIP84 (P2WPKH),
/// BIP86 (P2TR key path).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BtcPurpose {
    /// `44'`.
    Bip44,
    /// `49'`.
    Bip49,
    /// `84'`.
    Bip84,
    /// `86'`.
    Bip86,
}

impl BtcPurpose {
    /// The purpose number (44, 49, 84, 86).
    #[must_use]
    pub const fn number(self) -> u32 {
        match self {
            Self::Bip44 => 44,
            Self::Bip49 => 49,
            Self::Bip84 => 84,
            Self::Bip86 => 86,
        }
    }
}

/// A Bitcoin account node `m/{purpose}'/{coin}'/{account}'` (coin type: mainnet `0'`, testnet4
/// `1'`). The name is kept from the BIP84-only version, where it selected the coin type alone:
/// the vault passes it through unchanged (`Vault::btc_account_xpub`, `KeyRef::Btc`), and
/// [`BtcCoin::Mainnet`] / [`BtcCoin::Test`] are still the BIP84 account 0 nodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BtcCoin {
    test: bool,
    purpose: BtcPurpose,
    account: u32,
}

#[expect(
    non_upper_case_globals,
    reason = "the former enum variants `BtcCoin::Mainnet` / `BtcCoin::Test` keep their names"
)]
impl BtcCoin {
    /// `m/84'/0'/0'` (mainnet BIP84 account 0).
    pub const Mainnet: Self = Self {
        test: false,
        purpose: BtcPurpose::Bip84,
        account: 0,
    };
    /// `m/84'/1'/0'` (testnet4 BIP84 account 0).
    pub const Test: Self = Self {
        test: true,
        purpose: BtcPurpose::Bip84,
        account: 0,
    };
}

impl BtcCoin {
    /// The node `m/{purpose}'/{0|1}'/{account}'`.
    ///
    /// # Errors
    ///
    /// [`KeyError::InvalidPath`] when `account` is hardened (≥ 2^31).
    pub const fn new(test: bool, purpose: BtcPurpose, account: u32) -> Result<Self, KeyError> {
        if account >= HARDENED {
            return Err(KeyError::InvalidPath);
        }
        Ok(Self {
            test,
            purpose,
            account,
        })
    }

    /// Coin type `1'` (testnet4) instead of `0'`.
    #[must_use]
    pub const fn is_test(self) -> bool {
        self.test
    }

    /// The coin type number (0 or 1).
    #[must_use]
    pub const fn coin_index(self) -> u32 {
        if self.test { 1 } else { 0 }
    }

    /// The purpose.
    #[must_use]
    pub const fn purpose(self) -> BtcPurpose {
        self.purpose
    }

    /// The account number (`< 2^31`).
    #[must_use]
    pub const fn account(self) -> u32 {
        self.account
    }
}

/// Bitcoin chain: receive `0`, change `1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BtcChain {
    /// External chain `0`.
    Receive,
    /// Internal (change) chain `1`.
    Change,
}

const fn hardened(index: u32) -> u32 {
    index | HARDENED
}

/// `m/44'/60'/0'/0/i` (all EVM chains).
#[must_use]
pub fn evm_path(index: AccountIndex) -> Bip32Path {
    Bip32Path {
        components: vec![hardened(44), hardened(60), hardened(0), 0, index.get()],
    }
}

/// The account node `m/{purpose}'/{0|1}'/{account}'` (cached as `AccountXpub`, spec/08 §3.1).
#[must_use]
pub fn btc_account_path(coin: BtcCoin) -> Bip32Path {
    Bip32Path {
        components: vec![
            hardened(coin.purpose.number()),
            hardened(coin.coin_index()),
            hardened(coin.account & !HARDENED),
        ],
    }
}

/// `m/{purpose}'/{0|1}'/{account}'/{0|1}/index` (BIP44/49/84/86).
///
/// # Errors
///
/// [`KeyError::InvalidPath`] when `index` is hardened (≥ 2^31).
pub fn btc_path(coin: BtcCoin, chain: BtcChain, index: u32) -> Result<Bip32Path, KeyError> {
    if index >= HARDENED {
        return Err(KeyError::InvalidPath);
    }
    let mut path = btc_account_path(coin);
    path.components.push(chain.index());
    path.components.push(index);
    Ok(path)
}

/// SLIP-44 coin type of Zcash mainnet (`133'`); testnet uses `1'`.
pub const ZEC_COIN_MAINNET: u32 = 133;

/// `m/44'/{133|1}'/{account}'/0/{index}` (Zcash transparent, BIP44; spec/12 §2.2).
///
/// # Errors
///
/// [`KeyError::InvalidPath`] when `account` or `index` is hardened (≥ 2^31).
pub fn zec_path(test: bool, account: u32, index: u32) -> Result<Bip32Path, KeyError> {
    if account >= HARDENED || index >= HARDENED {
        return Err(KeyError::InvalidPath);
    }
    let coin = if test { 1 } else { ZEC_COIN_MAINNET };
    Ok(Bip32Path {
        components: vec![hardened(44), hardened(coin), hardened(account), 0, index],
    })
}

impl BtcChain {
    /// The path component: receive `0`, change `1`.
    #[must_use]
    pub const fn index(self) -> u32 {
        match self {
            Self::Receive => 0,
            Self::Change => 1,
        }
    }
}
