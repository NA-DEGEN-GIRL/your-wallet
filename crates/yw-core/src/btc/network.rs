//! Bitcoin networks (spec/08 §2): one network per wallet, pinned by genesis hash and Core
//! `getblockchaininfo.chain`. Address strings never select the network; the wallet setting does.
//! testnet3 and signet share `tb`/`0x6f`/`0xc4` with testnet4, so only the genesis check tells
//! them apart (their genesis hashes are here for that check's tests).
#![deny(clippy::indexing_slicing)]

use super::{BTC_ESPLORA_DEFAULT_MAINNET, BTC_ESPLORA_DEFAULT_TESTNET4};
use crate::bip32::path::BtcCoin;
use crate::hex::const_decode;

/// Mainnet genesis block hash in display order (`getblockhash 0`).
pub const MAINNET_GENESIS_HEX: &str =
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
/// testnet4 genesis block hash in display order.
pub const TESTNET4_GENESIS_HEX: &str =
    "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043";
/// testnet3 genesis block hash (unsupported; must fail the chain check).
pub const TESTNET3_GENESIS_HEX: &str =
    "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943";
/// Default signet genesis block hash (unsupported; must fail the chain check).
pub const SIGNET_GENESIS_HEX: &str =
    "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6";
/// [`MAINNET_GENESIS_HEX`] decoded (display-order bytes, as `GenesisHash` and `ChainRef` use).
pub const MAINNET_GENESIS: [u8; 32] = const_decode::<32>(MAINNET_GENESIS_HEX);
/// [`TESTNET4_GENESIS_HEX`] decoded (display-order bytes).
pub const TESTNET4_GENESIS: [u8; 32] = const_decode::<32>(TESTNET4_GENESIS_HEX);

/// The wallet's Bitcoin network (digest/journal byte: mainnet 1, testnet4 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BtcNetwork {
    /// `bitcoin:mainnet`, coin type `0'`.
    Mainnet = 1,
    /// `bitcoin:testnet4`, coin type `1'`.
    Testnet4 = 2,
}

impl BtcNetwork {
    /// Both networks in id order.
    pub const ALL: [Self; 2] = [Self::Mainnet, Self::Testnet4];

    /// Network byte (1 mainnet, 2 testnet4) for digests and journal records.
    #[must_use]
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// Inverse of [`BtcNetwork::id`].
    #[must_use]
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            1 => Some(Self::Mainnet),
            2 => Some(Self::Testnet4),
            _ => None,
        }
    }

    /// The BIP84 account 0 node `m/84'/{coin}'/0'` (D29): coin type mainnet `0'`, testnet4 `1'`.
    #[must_use]
    pub const fn coin_type(self) -> BtcCoin {
        match self {
            Self::Mainnet => BtcCoin::Mainnet,
            Self::Testnet4 => BtcCoin::Test,
        }
    }

    /// The coin type number (0 mainnet, 1 testnet4).
    #[must_use]
    pub const fn coin_number(self) -> u32 {
        match self {
            Self::Mainnet => 0,
            Self::Testnet4 => 1,
        }
    }

    /// The account node `m/{purpose}'/{coin}'/{account}'` of this network (D29).
    ///
    /// # Errors
    ///
    /// [`crate::error::KeyError::InvalidPath`] for a hardened `account`.
    pub const fn account_node(
        self,
        purpose: crate::bip32::path::BtcPurpose,
        account: u32,
    ) -> Result<BtcCoin, crate::error::KeyError> {
        BtcCoin::new(matches!(self, Self::Testnet4), purpose, account)
    }

    /// Genesis hash bytes in display order (the §2 hex decoded as written).
    #[must_use]
    pub const fn genesis(self) -> [u8; 32] {
        match self {
            Self::Mainnet => MAINNET_GENESIS,
            Self::Testnet4 => TESTNET4_GENESIS,
        }
    }

    /// Genesis hash as lowercase display-order hex (`getblockhash 0`, Esplora `/block-height/0`).
    #[must_use]
    pub const fn genesis_hex(self) -> &'static str {
        match self {
            Self::Mainnet => MAINNET_GENESIS_HEX,
            Self::Testnet4 => TESTNET4_GENESIS_HEX,
        }
    }

    /// Expected `getblockchaininfo.chain`.
    #[must_use]
    pub const fn core_chain(self) -> &'static str {
        match self {
            Self::Mainnet => "main",
            Self::Testnet4 => "testnet4",
        }
    }

    /// bech32 human-readable part.
    #[must_use]
    pub const fn hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "bc",
            Self::Testnet4 => "tb",
        }
    }

    /// base58check P2PKH version byte.
    #[must_use]
    pub const fn p2pkh_version(self) -> u8 {
        match self {
            Self::Mainnet => 0x00,
            Self::Testnet4 => 0x6f,
        }
    }

    /// base58check P2SH version byte.
    #[must_use]
    pub const fn p2sh_version(self) -> u8 {
        match self {
            Self::Mainnet => 0x05,
            Self::Testnet4 => 0xc4,
        }
    }

    /// The other network.
    #[must_use]
    pub const fn other(self) -> Self {
        match self {
            Self::Mainnet => Self::Testnet4,
            Self::Testnet4 => Self::Mainnet,
        }
    }

    /// `NetworkId` (D13): `bitcoin:mainnet` / `bitcoin:testnet4`.
    #[must_use]
    pub const fn network_id(self) -> &'static str {
        match self {
            Self::Mainnet => "bitcoin:mainnet",
            Self::Testnet4 => "bitcoin:testnet4",
        }
    }

    /// `settings.json` `bitcoin.network` value and `BtcMeta.network`.
    #[must_use]
    pub const fn settings_name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet4 => "testnet4",
        }
    }

    /// Inverse of [`BtcNetwork::settings_name`] (exact, case-sensitive).
    #[must_use]
    pub fn parse_settings_name(text: &str) -> Option<Self> {
        match text {
            "mainnet" => Some(Self::Mainnet),
            "testnet4" => Some(Self::Testnet4),
            _ => None,
        }
    }

    /// Network name in titles (`[Bitcoin 메인넷] 보내기: …`, spec/08 §10).
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Mainnet => "Bitcoin 메인넷",
            Self::Testnet4 => "Bitcoin testnet4",
        }
    }

    /// Banner text (spec/08 §2; mainnet on red, testnet4 on orange).
    #[must_use]
    pub const fn banner(self) -> &'static str {
        match self {
            Self::Mainnet => "BITCOIN MAINNET",
            Self::Testnet4 => "BITCOIN TESTNET4 — 가치 없음",
        }
    }

    /// The banner in `lang` (spec/08 §2; English spec/14 §2).
    #[must_use]
    pub fn banner_in(self, lang: crate::lang::Lang) -> &'static str {
        crate::btc::text::network_banner(lang, self)
    }

    /// Default `esploraBaseUrl` of this network.
    #[must_use]
    pub const fn esplora_default(self) -> &'static str {
        match self {
            Self::Mainnet => BTC_ESPLORA_DEFAULT_MAINNET,
            Self::Testnet4 => BTC_ESPLORA_DEFAULT_TESTNET4,
        }
    }
}
