//! The Zcash transparent account (spec/12 §2.2): one fixed P2PKH address per network, from one
//! of three key sources. Only the compressed public key is cached (meta `zcash`); the private
//! key is lent by the vault at signing time (or the `YubiKey` signs, spec/10).
#![deny(clippy::indexing_slicing)]

use super::address::ZecDest;
use super::network::ZecNetwork;
use crate::btc::address::hash160;

/// Largest BIP44 account / address index accepted for a derived key.
pub const ZEC_MAX_INDEX: u32 = 999;

/// Where the account's key comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ZecKeySource {
    /// `m/44'/{133|1}'/{account}'/0/{index}` from the mnemonic (default `account = index = 0`).
    Derived {
        /// BIP44 account.
        account: u32,
        /// Receive index.
        index: u32,
    },
    /// The EVM key `m/44'/60'/0'/0/{evm_index}` (explicit opt-in, linkage warning).
    EvmShared {
        /// EVM account index (0–999).
        evm_index: u32,
    },
    /// A `YubiKey` OpenPGP secp256k1 slot holding `m/44'/{coin}'/0'/0/{index}` (spec/10 §3.4).
    Hardware {
        /// Receive index on account 0.
        index: u32,
    },
}

impl ZecKeySource {
    /// The default: `m/44'/{coin}'/0'/0/0`.
    pub const DEFAULT: Self = Self::Derived {
        account: 0,
        index: 0,
    };

    /// Stored code: 1 derived, 2 EVM key, 3 `YubiKey`.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Derived { .. } => 1,
            Self::EvmShared { .. } => 2,
            Self::Hardware { .. } => 3,
        }
    }

    /// `(a, b)` parameters of the stored form (`account, index` / `evm_index, 0` / `index, 0`).
    #[must_use]
    pub const fn params(self) -> (u32, u32) {
        match self {
            Self::Derived { account, index } => (account, index),
            Self::EvmShared { evm_index } => (evm_index, 0),
            Self::Hardware { index } => (index, 0),
        }
    }

    /// The source of a stored form (range checked).
    #[must_use]
    pub const fn from_parts(code: u8, a: u32, b: u32) -> Option<Self> {
        let source = match code {
            1 => Self::Derived {
                account: a,
                index: b,
            },
            2 if b == 0 => Self::EvmShared { evm_index: a },
            3 if b == 0 => Self::Hardware { index: a },
            _ => return None,
        };
        if source.in_range() {
            Some(source)
        } else {
            None
        }
    }

    /// Every index ≤ [`ZEC_MAX_INDEX`].
    #[must_use]
    pub const fn in_range(self) -> bool {
        match self {
            Self::Derived { account, index } => account <= ZEC_MAX_INDEX && index <= ZEC_MAX_INDEX,
            Self::EvmShared { evm_index } => evm_index <= ZEC_MAX_INDEX,
            Self::Hardware { index } => index <= ZEC_MAX_INDEX,
        }
    }

    /// The derivation path text on `network`.
    #[must_use]
    pub fn path_text(self, network: ZecNetwork) -> String {
        match self {
            Self::Derived { account, index } => {
                format!("m/44'/{}'/{account}'/0/{index}", network.coin_type())
            }
            Self::EvmShared { evm_index } => format!("m/44'/60'/0'/0/{evm_index}"),
            Self::Hardware { index } => format!("m/44'/{}'/0'/0/{index}", network.coin_type()),
        }
    }

    /// Display name of the source.
    #[must_use]
    pub fn label(self) -> String {
        match self {
            Self::Derived {
                account: 0,
                index: 0,
            } => "Zcash 표준 경로".to_owned(),
            Self::Derived { account, index } => {
                format!("Zcash 경로 (계정 {account}, 주소 {index})")
            }
            Self::EvmShared { evm_index } => format!("EVM 계정 {evm_index} 키"),
            Self::Hardware { index } => format!("YubiKey (주소 {index})"),
        }
    }
}

/// The account: network, key source and the cached compressed public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ZecAccount {
    /// Network.
    pub network: ZecNetwork,
    /// Key source.
    pub source: ZecKeySource,
    /// Compressed secp256k1 public key (`02`/`03`).
    pub pubkey: [u8; 33],
}

impl ZecAccount {
    /// HASH160 of the public key.
    #[must_use]
    pub fn pubkey_hash(&self) -> [u8; 20] {
        hash160(&self.pubkey)
    }

    /// The P2PKH destination.
    #[must_use]
    pub fn dest(&self) -> ZecDest {
        ZecDest::P2pkh(self.pubkey_hash())
    }

    /// The `t1…` / `tm…` address.
    #[must_use]
    pub fn address(&self) -> String {
        self.dest().encode(self.network)
    }

    /// Our `scriptPubKey`.
    #[must_use]
    pub fn script_pubkey(&self) -> Vec<u8> {
        self.dest().script_pubkey()
    }

    /// Whether the key is on a `YubiKey`.
    #[must_use]
    pub const fn is_hardware(&self) -> bool {
        matches!(self.source, ZecKeySource::Hardware { .. })
    }
}
