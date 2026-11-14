//! The Zcash transparent account (spec/12 §2.2): one fixed P2PKH address per network, from one
//! of four key sources. Only the compressed public key is cached (meta `zcash`); the private
//! key is lent by the vault at signing time (or the `YubiKey` signs, spec/10).
#![deny(clippy::indexing_slicing)]

use super::address::ZecDest;
use super::network::ZecNetwork;
use crate::btc::address::hash160;
use crate::vault::RecordId;

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
    /// An imported transparent private key (vault tag 6, spec/12 §2.3): the vault record whose
    /// public key is the account's (no path).
    Imported,
    /// `m/44'/{133|1}'/{account}'/0/{index}` of an added mnemonic (the vault `Bip39` record
    /// `mnemonic`, spec/02 §8.6). Stored code 5: the journal (record version 2) and the approval
    /// transcript carry the record id after `(a, b)`; meta keeps it in `mnemonic_accounts`.
    Mnemonic {
        /// The added mnemonic.
        mnemonic: RecordId,
        /// BIP44 account.
        account: u32,
        /// Receive index.
        index: u32,
    },
}

impl ZecKeySource {
    /// The default: `m/44'/{coin}'/0'/0/0`.
    pub const DEFAULT: Self = Self::Derived {
        account: 0,
        index: 0,
    };

    /// Stored code: 1 derived, 2 EVM key, 3 `YubiKey`, 4 imported key, 5 an added mnemonic's
    /// derived key.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Derived { .. } => 1,
            Self::EvmShared { .. } => 2,
            Self::Hardware { .. } => 3,
            Self::Imported => 4,
            Self::Mnemonic { .. } => 5,
        }
    }

    /// The added mnemonic of a code-5 source (`None` for every other source).
    #[must_use]
    pub const fn mnemonic(self) -> Option<RecordId> {
        match self {
            Self::Mnemonic { mnemonic, .. } => Some(mnemonic),
            _ => None,
        }
    }

    /// The code-5 source of a stored form (range checked, non-zero record id).
    #[must_use]
    pub fn from_mnemonic_parts(id: [u8; 16], a: u32, b: u32) -> Option<Self> {
        if id == [0; 16] || a > ZEC_MAX_INDEX || b > ZEC_MAX_INDEX {
            return None;
        }
        Some(Self::Mnemonic {
            mnemonic: RecordId::from_bytes(id),
            account: a,
            index: b,
        })
    }

    /// `(a, b)` parameters of the stored form (`account, index` / `evm_index, 0` / `index, 0`).
    #[must_use]
    pub const fn params(self) -> (u32, u32) {
        match self {
            Self::Derived { account, index } | Self::Mnemonic { account, index, .. } => {
                (account, index)
            }
            Self::EvmShared { evm_index } => (evm_index, 0),
            Self::Hardware { index } => (index, 0),
            Self::Imported => (0, 0),
        }
    }

    /// The source of a stored form (range checked; code 5 needs the record id,
    /// [`ZecKeySource::from_mnemonic_parts`]).
    #[must_use]
    pub const fn from_parts(code: u8, a: u32, b: u32) -> Option<Self> {
        let source = match code {
            1 => Self::Derived {
                account: a,
                index: b,
            },
            2 if b == 0 => Self::EvmShared { evm_index: a },
            3 if b == 0 => Self::Hardware { index: a },
            4 if a == 0 && b == 0 => Self::Imported,
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
            Self::Derived { account, index } | Self::Mnemonic { account, index, .. } => {
                account <= ZEC_MAX_INDEX && index <= ZEC_MAX_INDEX
            }
            Self::EvmShared { evm_index } => evm_index <= ZEC_MAX_INDEX,
            Self::Hardware { index } => index <= ZEC_MAX_INDEX,
            Self::Imported => true,
        }
    }

    /// The derivation path text on `network` in `lang`.
    #[must_use]
    pub fn path_text_in(self, lang: crate::lang::Lang, network: ZecNetwork) -> String {
        use super::text as t;
        match self {
            Self::Hardware { index } if crate::yubikey::plan::is_unknown_index(index) => {
                t::PATH_UNKNOWN.get(lang).to_owned()
            }
            Self::Derived { account, index } | Self::Mnemonic { account, index, .. } => {
                format!("m/44'/{}'/{account}'/0/{index}", network.coin_type())
            }
            Self::EvmShared { evm_index } => format!("m/44'/60'/0'/0/{evm_index}"),
            Self::Hardware { index } => format!("m/44'/{}'/0'/0/{index}", network.coin_type()),
            Self::Imported => t::PATH_IMPORTED.get(lang).to_owned(),
        }
    }

    /// Display name of the source in `lang`.
    #[must_use]
    pub fn label_in(self, lang: crate::lang::Lang) -> String {
        use super::text as t;
        match self {
            Self::Derived {
                account: 0,
                index: 0,
            } => t::SOURCE_STANDARD.get(lang).to_owned(),
            Self::Derived { account, index } => {
                t::SOURCE_PATH.fill(lang, [&account.to_string(), &index.to_string()])
            }
            // The app names the mnemonic by its label instead ("[니모닉 2] Zcash 표준 경로").
            Self::Mnemonic {
                account: 0,
                index: 0,
                ..
            } => t::SOURCE_STANDARD_ADDED.get(lang).to_owned(),
            Self::Mnemonic { account, index, .. } => {
                t::SOURCE_PATH_ADDED.fill(lang, [&account.to_string(), &index.to_string()])
            }
            Self::EvmShared { evm_index } => t::SOURCE_EVM.fill(lang, [&evm_index.to_string()]),
            Self::Hardware { index } if crate::yubikey::plan::is_unknown_index(index) => {
                t::SOURCE_YUBIKEY_CARD.fill(
                    lang,
                    [&index
                        .saturating_sub(crate::yubikey::plan::UNKNOWN_PATH_FIRST)
                        .saturating_add(1)
                        .to_string()],
                )
            }
            Self::Hardware { index } => t::SOURCE_YUBIKEY.fill(lang, [&index.to_string()]),
            Self::Imported => t::SOURCE_IMPORTED.get(lang).to_owned(),
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
