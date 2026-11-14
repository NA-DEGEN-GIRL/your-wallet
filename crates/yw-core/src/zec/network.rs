//! Zcash networks (spec/12 §2): one network per wallet setting, pinned genesis, coin type and
//! the address encodings of the protocol specification §5.6.1.1 (transparent), ZIP 320 (TEX) and
//! ZIP 316 (unified addresses).
#![deny(clippy::indexing_slicing)]

use crate::hex;

/// Mainnet genesis block hash (display order; zcashd `chainparams.cpp`, spec/12 §2).
pub const ZEC_GENESIS_MAINNET: &str =
    "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08";
/// Testnet genesis block hash (display order).
pub const ZEC_GENESIS_TESTNET: &str =
    "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38";

/// A Zcash network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ZecNetwork {
    /// Mainnet (id 1).
    Mainnet,
    /// Testnet (id 2).
    Testnet,
}

impl ZecNetwork {
    /// Both networks in id order.
    pub const ALL: [Self; 2] = [Self::Mainnet, Self::Testnet];

    /// Stored id (journal, approval digest): 1 mainnet, 2 testnet.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::Mainnet => 1,
            Self::Testnet => 2,
        }
    }

    /// The network of a stored id.
    #[must_use]
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            1 => Some(Self::Mainnet),
            2 => Some(Self::Testnet),
            _ => None,
        }
    }

    /// The settings / endpoint name (`"mainnet"`, `"testnet"`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
        }
    }

    /// The settings value back to a network.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|network| network.name() == name)
    }

    /// The endpoint id (`zcash:mainnet`, `zcash:testnet`; D13).
    #[must_use]
    pub const fn endpoint_id(self) -> &'static str {
        match self {
            Self::Mainnet => "zcash:mainnet",
            Self::Testnet => "zcash:testnet",
        }
    }

    /// SLIP-44 coin type of the BIP44 path `m/44'/{coin}'/0'/0/0`: 133 mainnet, 1 testnet.
    #[must_use]
    pub const fn coin_type(self) -> u32 {
        match self {
            Self::Mainnet => 133,
            Self::Testnet => 1,
        }
    }

    /// `getblockchaininfo.chain` (`"main"`, `"test"`).
    #[must_use]
    pub const fn chain_name(self) -> &'static str {
        match self {
            Self::Mainnet => "main",
            Self::Testnet => "test",
        }
    }

    /// Genesis hash as lowercase display hex.
    #[must_use]
    pub const fn genesis_hex(self) -> &'static str {
        match self {
            Self::Mainnet => ZEC_GENESIS_MAINNET,
            Self::Testnet => ZEC_GENESIS_TESTNET,
        }
    }

    /// Genesis hash bytes in display order (the approval chain reference).
    #[must_use]
    pub fn genesis(self) -> [u8; 32] {
        hex::decode_array::<32>(self.genesis_hex()).unwrap_or([0; 32])
    }

    /// Base58Check version bytes of a P2PKH address (`t1…` / `tm…`).
    #[must_use]
    pub const fn p2pkh_prefix(self) -> [u8; 2] {
        match self {
            Self::Mainnet => [0x1c, 0xb8],
            Self::Testnet => [0x1d, 0x25],
        }
    }

    /// Base58Check version bytes of a P2SH address (`t3…` / `t2…`).
    #[must_use]
    pub const fn p2sh_prefix(self) -> [u8; 2] {
        match self {
            Self::Mainnet => [0x1c, 0xbd],
            Self::Testnet => [0x1c, 0xba],
        }
    }

    /// ZIP 320 TEX bech32m HRP.
    #[must_use]
    pub const fn tex_hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "tex",
            Self::Testnet => "textest",
        }
    }

    /// ZIP 316 unified address HRP (revision 0).
    #[must_use]
    pub const fn ua_hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "u",
            Self::Testnet => "utest",
        }
    }

    /// WIF version byte (zcashd `SECRET_KEY`, same as Bitcoin: 0x80 / 0xEF).
    #[must_use]
    pub const fn wif_version(self) -> u8 {
        match self {
            Self::Mainnet => 0x80,
            Self::Testnet => 0xef,
        }
    }

    /// Display name of the network banner in `lang`.
    #[must_use]
    pub const fn banner_in(self, lang: crate::lang::Lang) -> &'static str {
        match self {
            Self::Mainnet => "ZCASH MAINNET",
            Self::Testnet => super::text::BANNER_TESTNET.get(lang),
        }
    }

    /// Short display name (`Zcash mainnet`, `Zcash testnet`).
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Mainnet => "Zcash mainnet",
            Self::Testnet => "Zcash testnet",
        }
    }
}
