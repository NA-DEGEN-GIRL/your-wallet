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

/// Bitcoin coin type: mainnet `0'`, testnet4 `1'`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcCoin {
    /// `m/84'/0'/0'`.
    Mainnet,
    /// `m/84'/1'/0'` (testnet4).
    Test,
}

/// Bitcoin chain: receive `0`, change `1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// `m/84'/{0|1}'/0'/{0|1}/index` (BIP84).
///
/// # Errors
///
/// [`KeyError::InvalidPath`] when `index` is hardened (≥ 2^31).
pub fn btc_path(coin: BtcCoin, chain: BtcChain, index: u32) -> Result<Bip32Path, KeyError> {
    if index >= HARDENED {
        return Err(KeyError::InvalidPath);
    }
    let coin = match coin {
        BtcCoin::Mainnet => 0,
        BtcCoin::Test => 1,
    };
    let chain = match chain {
        BtcChain::Receive => 0,
        BtcChain::Change => 1,
    };
    Ok(Bip32Path {
        components: vec![hardened(84), hardened(coin), hardened(0), chain, index],
    })
}
