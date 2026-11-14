//! EVM chain table and registries (spec/03 §1.1–§1.2, §1.6, D14).
//!
//! Only `ChainIdentity {chain_id, genesis}` survives from
//! `archive/spec-v2.4:crates/chain-registry/src/registry.rs:20-28` and
//! `archive/spec-v2.4:crates/wallet-model/src/chain.rs:1-158`; the rest is the v3 table.
//! Registry rows marked "구현 시 확인" in spec/03 §1.2 are kept as specified until the M4 live
//! probe checks them on-chain (docs/acceptance/m2-20261027.md).

use core::fmt;

use super::address::Address;
use super::amount::U256;
use super::fee::{FeeCaps, L1DataFee};
use super::text;
use crate::approval::is_forbidden_display_char;
use crate::lang::{Lang, Text};

/// Ethereum mainnet chain id.
pub const ETHEREUM_MAINNET: u64 = 1;
/// Sepolia chain id.
pub const SEPOLIA: u64 = 11_155_111;
/// `HyperEVM` mainnet chain id.
pub const HYPEREVM_MAINNET: u64 = 999;
/// Arbitrum One chain id.
pub const ARBITRUM_ONE: u64 = 42_161;
/// Base mainnet chain id.
pub const BASE_MAINNET: u64 = 8_453;
/// BNB Smart Chain mainnet chain id.
pub const BSC_MAINNET: u64 = 56;
/// Robinhood Chain mainnet chain id.
pub const ROBINHOOD_MAINNET: u64 = 4_663;
/// Largest chain id (EIP-2294).
pub const MAX_CHAIN_ID: u64 = 9_223_372_036_854_775_771;
/// Default `tip_floor_wei` (0.01 gwei).
pub const TIP_FLOOR_WEI: u64 = 10_000_000;
/// `HyperEVM` small-block gas limit (spec/03 §1.1, A9 (d) observed 3,000,000 on 2026-10-27).
pub const HYPEREVM_SMALL_BLOCK_GAS: u64 = 3_000_000;
/// Sepolia Glamsterdam (Amsterdam) activation, unix seconds (EIP-7773).
pub const SEPOLIA_AMSTERDAM_TIME: u64 = 1_791_294_816;
/// Mainnet genesis hash.
pub const MAINNET_GENESIS: [u8; 32] =
    hex32("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3");
/// Sepolia genesis hash.
pub const SEPOLIA_GENESIS: [u8; 32] =
    hex32("25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9");
/// Arbitrum One genesis hash (block 0 of the Nitro chain, spec/03 §1.1 sources).
pub const ARBITRUM_ONE_GENESIS: [u8; 32] =
    hex32("7ee576b35482195fc49205cec9af72ce14f003b9ae69f6ba0faef4514be8b442");
/// Base mainnet genesis hash.
pub const BASE_GENESIS: [u8; 32] =
    hex32("f712aa9241cc24369b143cf6dce85f0902a9731e70d66818a3a5845b296c73dd");
/// BNB Smart Chain genesis hash.
pub const BSC_GENESIS: [u8; 32] =
    hex32("0d21840abff46b96c84b2ac9e10e4f5cdaeb5693cb665db62a2f3b02d2d57b5b");
/// Robinhood Chain mainnet genesis hash.
pub const ROBINHOOD_GENESIS: [u8; 32] =
    hex32("aad15f3d702aaea00caf3e9bb56395efe9127bc3b31b24921abf1eee3409305c");
/// BSC minimum gas price adopted by validators in 2025 (0.05 gwei), the BSC tip floor.
pub const BSC_TIP_FLOOR_WEI: u64 = 50_000_000;
/// Base tip floor (0.001 gwei): Base priority fees are usually far below the default floor.
pub const BASE_TIP_FLOOR_WEI: u64 = 1_000_000;
/// `OpenSea` conduit key (Seaport display label, spec/03 §1.2).
pub const OPENSEA_CONDUIT_KEY: [u8; 32] =
    hex32("0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000");

const fn hex32(text: &str) -> [u8; 32] {
    crate::hex::const_decode::<32>(text)
}

const fn addr(text: &str) -> Address {
    Address::from_bytes(crate::hex::const_decode::<20>(text))
}

/// Where a chain definition comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainSource {
    /// Built into the wallet (1, 11155111, 999, 42161, 8453, 56, 4663).
    BuiltIn,
    /// Added by the user (spec/03 §1.6).
    User,
}

/// Endpoint URL template metadata for the settings screen (D13). Never used at runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointTemplates {
    /// `QuickNode` network subdomain, `None` for Ethereum mainnet.
    pub quicknode_subdomain: Option<&'static str>,
    /// Path after the token, `None` for a trailing `/`.
    pub quicknode_path: Option<&'static str>,
    /// Alchemy network label, `None` when there is no Alchemy template.
    pub alchemy_label: Option<&'static str>,
}

/// Genesis pin rule (spec/03 §1.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenesisRule {
    /// A hard-coded genesis hash.
    Fixed([u8; 32]),
    /// Pinned on first use; `None` until pinned.
    PinOnFirstUse(Option<[u8; 32]>),
}

/// Whether the chain's RPC is asked for `eth_simulateV1` (D14, D15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SimulationSupport {
    /// Always try `eth_simulateV1` (default).
    Auto = 1,
    /// Never call it; E36.
    Unsupported = 2,
}

impl SimulationSupport {
    /// Settings string `"auto"` / `"unsupported"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Unsupported => "unsupported",
        }
    }

    /// Parses the settings string.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "auto" => Some(Self::Auto),
            "unsupported" => Some(Self::Unsupported),
            _ => None,
        }
    }
}

/// Role of a registered token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenRole {
    /// Plain ERC-20.
    Plain,
    /// Wrapped native token (WETH, WHYPE): `deposit`/`withdraw` and Deposit/Withdrawal logs.
    Weth,
    /// DAI (DAI-style permit).
    Dai,
}

/// A registered token: trusted symbol and decimals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnownToken {
    /// Token contract.
    pub address: Address,
    /// Trusted symbol.
    pub symbol: &'static str,
    /// Decimals.
    pub decimals: u8,
    /// Role.
    pub role: TokenRole,
    /// Address label when the symbol alone would mislead (bridged/pegged tokens), `None` = the
    /// symbol. The symbol stays the on-chain ticker so E19/T20 still catch look-alikes.
    pub label: Option<&'static str>,
}

/// The per-chain registry of trusted tokens.
pub type TokenRegistry = [KnownToken];

/// Role of a registered contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractRole {
    /// Uniswap Permit2.
    Permit2,
    /// `OpenSea` Seaport 1.6.
    Seaport16,
    /// `OpenSea` Seaport 1.5.
    Seaport15,
    /// Label only (no structured interpretation).
    LabelOnly,
}

/// A registered contract with a display label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnownContract {
    /// Contract address.
    pub address: Address,
    /// Display label (shown as `[label]`; the Korean form, also used for registry checks).
    pub label: &'static str,
    /// English display label (equal to `label` unless the label has Korean words, spec/14 §4).
    pub label_en: &'static str,
    /// Role.
    pub role: ContractRole,
}

/// Everything the core needs to know about one EVM chain (spec/03 §1.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainInfo {
    /// Chain id.
    pub chain_id: u64,
    /// Built-in or user chain.
    pub source: ChainSource,
    /// Genesis rule.
    pub genesis: GenesisRule,
    /// Settings-screen URL templates (built-in chains only).
    pub templates: Option<EndpointTemplates>,
    /// Display name (approval title `[name]`).
    pub name: String,
    /// Native symbol.
    pub native_symbol: String,
    /// Native decimals.
    pub native_decimals: u8,
    /// Explorer base URL (display/link only, never used for RPC).
    pub explorer: Option<String>,
    /// Simulation support.
    pub simulation: SimulationSupport,
    /// Glamsterdam activation (unix seconds), `None` when unknown or not applicable.
    pub amsterdam_time: Option<u64>,
    /// Default fee caps.
    pub default_caps: FeeCaps,
    /// Tip floor (wei).
    pub tip_floor_wei: u64,
    /// `HyperEVM` small-block gas limit (E38), `None` elsewhere.
    pub small_block_gas_limit: Option<u64>,
    /// How the chain charges L1 data beyond `gas × price` (spec/03 §3.4a).
    pub l1_data_fee: L1DataFee,
    /// Registered tokens (empty for user chains).
    pub tokens: &'static TokenRegistry,
    /// Registered contracts (empty for user chains).
    pub contracts: &'static [KnownContract],
}

const WETH_MAINNET: Address = addr("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
const PERMIT2: Address = addr("000000000022D473030F116dDEE9F6B43aC78BA3");
const SEAPORT_16: Address = addr("0000000000000068F116a894984e2DB1123eB395");
const SEAPORT_15: Address = addr("00000000000000ADc04C56Bf30aC9d3c0aAF14dC");

static MAINNET_TOKENS: [KnownToken; 4] = [
    KnownToken {
        address: WETH_MAINNET,
        symbol: "WETH",
        decimals: 18,
        role: TokenRole::Weth,
        label: None,
    },
    KnownToken {
        address: addr("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
        symbol: "USDC",
        decimals: 6,
        role: TokenRole::Plain,
        label: None,
    },
    KnownToken {
        address: addr("dAC17F958D2ee523a2206206994597C13D831ec7"),
        symbol: "USDT",
        decimals: 6,
        role: TokenRole::Plain,
        label: None,
    },
    KnownToken {
        address: addr("6B175474E89094C44Da98b954EedeAC495271d0F"),
        symbol: "DAI",
        decimals: 18,
        role: TokenRole::Dai,
        label: None,
    },
];

static SEPOLIA_TOKENS: [KnownToken; 2] = [
    KnownToken {
        address: addr("fFf9976782d46CC05630D1f6eBAb18b2324d6B14"),
        symbol: "WETH",
        decimals: 18,
        role: TokenRole::Weth,
        label: None,
    },
    KnownToken {
        address: addr("1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"),
        symbol: "USDC",
        decimals: 6,
        role: TokenRole::Plain,
        label: None,
    },
];

static HYPEREVM_TOKENS: [KnownToken; 1] = [KnownToken {
    address: addr("5555555555555555555555555555555555555555"),
    symbol: "WHYPE",
    decimals: 18,
    role: TokenRole::Weth,
    label: None,
}];

const fn token(address: &str, symbol: &'static str, decimals: u8, role: TokenRole) -> KnownToken {
    KnownToken {
        address: addr(address),
        symbol,
        decimals,
        role,
        label: None,
    }
}

const fn labeled(token: KnownToken, label: &'static str) -> KnownToken {
    KnownToken {
        label: Some(label),
        ..token
    }
}

/// Arbitrum One: WETH (Arbitrum docs), native USDC (Circle), USDT0 (USDT0 docs).
static ARBITRUM_TOKENS: [KnownToken; 3] = [
    token(
        "82aF49447D8a07e3bd95BD0d56f35241523fBab1",
        "WETH",
        18,
        TokenRole::Weth,
    ),
    token(
        "af88d065e77c8cC2239327C5EDb3A432268e5831",
        "USDC",
        6,
        TokenRole::Plain,
    ),
    labeled(
        token(
            "Fd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",
            "USDT0",
            6,
            TokenRole::Plain,
        ),
        "USDT0 (Tether OFT)",
    ),
];

/// Base: WETH predeploy (OP specs), native USDC (Circle).
static BASE_TOKENS: [KnownToken; 2] = [
    token(
        "4200000000000000000000000000000000000006",
        "WETH",
        18,
        TokenRole::Weth,
    ),
    token(
        "833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        "USDC",
        6,
        TokenRole::Plain,
    ),
];

/// BNB Smart Chain: WBNB and the Binance-Peg USDT/USDC (18 decimals, issued by Binance, not by
/// Tether or Circle).
static BSC_TOKENS: [KnownToken; 3] = [
    token(
        "bb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
        "WBNB",
        18,
        TokenRole::Weth,
    ),
    labeled(
        token(
            "55d398326f99059fF775485246999027B3197955",
            "USDT",
            18,
            TokenRole::Plain,
        ),
        "USDT (Binance-Peg)",
    ),
    labeled(
        token(
            "8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
            "USDC",
            18,
            TokenRole::Plain,
        ),
        "USDC (Binance-Peg)",
    ),
];

/// Robinhood Chain: WETH (Robinhood Chain docs), USDG (Paxos, Robinhood Chain docs).
static ROBINHOOD_TOKENS: [KnownToken; 2] = [
    token(
        "0Bd7D308f8E1639FAb988df18A8011f41EAcAD73",
        "WETH",
        18,
        TokenRole::Weth,
    ),
    labeled(
        token(
            "5fc5360D0400a0Fd4f2af552ADD042D716F1d168",
            "USDG",
            6,
            TokenRole::Plain,
        ),
        "USDG (Global Dollar, Paxos)",
    ),
];

static NO_TOKENS: [KnownToken; 0] = [];
static NO_CONTRACTS: [KnownContract; 0] = [];

const fn contract(address: Address, label: &'static str, role: ContractRole) -> KnownContract {
    KnownContract {
        address,
        label,
        label_en: label,
        role,
    }
}

const fn contract_text(address: Address, label: Text, role: ContractRole) -> KnownContract {
    KnownContract {
        address,
        label: label.ko,
        label_en: label.en,
        role,
    }
}

static MAINNET_CONTRACTS: [KnownContract; 9] = [
    contract(PERMIT2, "Uniswap Permit2", ContractRole::Permit2),
    contract(SEAPORT_16, "OpenSea Seaport 1.6", ContractRole::Seaport16),
    contract(SEAPORT_15, "OpenSea Seaport 1.5", ContractRole::Seaport15),
    contract_text(
        addr("00000000006c3852cbEf3e08E8dF289169EdE581"),
        text::SEAPORT_11_LABEL,
        ContractRole::LabelOnly,
    ),
    contract(
        addr("00000000F9490004C11Cef243f5400493c00Ad63"),
        "Seaport ConduitController",
        ContractRole::LabelOnly,
    ),
    contract(
        addr("1E0049783F008A0085193E00003D00cd54003c71"),
        "OpenSea Conduit",
        ContractRole::LabelOnly,
    ),
    contract(
        addr("66a9893cC07D91D95644AEDD05D03f95e1dBA8Af"),
        "Uniswap Universal Router",
        ContractRole::LabelOnly,
    ),
    contract(
        addr("4C82D1fBFe28C977cBB58D8C7FF8FCF9F70a2cCA"),
        "Uniswap Universal Router",
        ContractRole::LabelOnly,
    ),
    contract(
        addr("23617e59A5925b2A4Bf75d73ff6711cD0b29De85"),
        "Uniswap Universal Router",
        ContractRole::LabelOnly,
    ),
];

static SEPOLIA_CONTRACTS: [KnownContract; 6] = [
    contract(PERMIT2, "Uniswap Permit2", ContractRole::Permit2),
    contract(SEAPORT_16, "OpenSea Seaport 1.6", ContractRole::Seaport16),
    contract(SEAPORT_15, "OpenSea Seaport 1.5", ContractRole::Seaport15),
    contract(
        addr("3A9D48AB9751398BbFa63ad67599Bb04e4BdF98b"),
        "Uniswap Universal Router",
        ContractRole::LabelOnly,
    ),
    contract(
        addr("7DfD4F31be6814D2906BDE155c3e1B146EAc1468"),
        "Uniswap Universal Router",
        ContractRole::LabelOnly,
    ),
    contract(
        addr("7E4f6c5e954Da5c61B3423D81E2277431Ac043f3"),
        "Uniswap Universal Router",
        ContractRole::LabelOnly,
    ),
];

static HYPEREVM_CONTRACTS: [KnownContract; 1] =
    [contract(PERMIT2, "Uniswap Permit2", ContractRole::Permit2)];

fn gwei(value: u64) -> U256 {
    U256::from_u64(value)
        .checked_mul_u64(1_000_000_000)
        .unwrap_or(U256::MAX)
}

/// `numerator / 100` of one native unit (`10^decimals`), rounded up.
fn native_percent(decimals: u8, numerator: u64) -> U256 {
    let Some(hundred) = core::num::NonZeroU64::new(100) else {
        return U256::MAX;
    };
    U256::checked_pow10(decimals)
        .and_then(|unit| unit.ceil_mul_div_u64(numerator, hundred))
        .unwrap_or(U256::MAX)
}

/// Ethereum mainnet (spec/03 §1.1).
#[must_use]
pub fn ethereum_mainnet() -> ChainInfo {
    ChainInfo {
        chain_id: ETHEREUM_MAINNET,
        source: ChainSource::BuiltIn,
        genesis: GenesisRule::Fixed(MAINNET_GENESIS),
        templates: Some(EndpointTemplates {
            quicknode_subdomain: None,
            quicknode_path: None,
            alchemy_label: Some("eth-mainnet"),
        }),
        name: text::CHAIN_ETHEREUM.ko.to_owned(),
        native_symbol: "ETH".to_owned(),
        native_decimals: 18,
        explorer: Some("https://etherscan.io".to_owned()),
        simulation: SimulationSupport::Auto,
        amsterdam_time: None,
        default_caps: FeeCaps {
            max_fee_per_gas: gwei(200),
            max_priority_fee_per_gas: gwei(5),
            max_total_fee: native_percent(18, 5),
        },
        tip_floor_wei: TIP_FLOOR_WEI,
        small_block_gas_limit: None,
        l1_data_fee: L1DataFee::None,
        tokens: &MAINNET_TOKENS,
        contracts: &MAINNET_CONTRACTS,
    }
}

/// Sepolia (spec/03 §1.1).
#[must_use]
pub fn sepolia() -> ChainInfo {
    ChainInfo {
        chain_id: SEPOLIA,
        source: ChainSource::BuiltIn,
        genesis: GenesisRule::Fixed(SEPOLIA_GENESIS),
        templates: Some(EndpointTemplates {
            quicknode_subdomain: Some("ethereum-sepolia"),
            quicknode_path: None,
            alchemy_label: Some("eth-sepolia"),
        }),
        name: text::CHAIN_SEPOLIA.ko.to_owned(),
        native_symbol: "SepoliaETH".to_owned(),
        native_decimals: 18,
        explorer: Some("https://sepolia.etherscan.io".to_owned()),
        simulation: SimulationSupport::Auto,
        amsterdam_time: Some(SEPOLIA_AMSTERDAM_TIME),
        default_caps: FeeCaps {
            max_fee_per_gas: gwei(1_000),
            max_priority_fee_per_gas: gwei(100),
            max_total_fee: native_percent(18, 100),
        },
        tip_floor_wei: TIP_FLOOR_WEI,
        small_block_gas_limit: None,
        l1_data_fee: L1DataFee::None,
        tokens: &SEPOLIA_TOKENS,
        contracts: &SEPOLIA_CONTRACTS,
    }
}

/// `HyperEVM` mainnet (spec/03 §1.1; `simulation = Auto` per the 2026-10-27 probe).
#[must_use]
pub fn hyperevm_mainnet() -> ChainInfo {
    ChainInfo {
        chain_id: HYPEREVM_MAINNET,
        source: ChainSource::BuiltIn,
        genesis: GenesisRule::PinOnFirstUse(None),
        templates: Some(EndpointTemplates {
            quicknode_subdomain: Some("hype-mainnet"),
            quicknode_path: Some("nanoreth"),
            alchemy_label: Some("hyperliquid-mainnet"),
        }),
        name: text::CHAIN_HYPEREVM.ko.to_owned(),
        native_symbol: "HYPE".to_owned(),
        native_decimals: 18,
        // 2026-11-11: HyperEVMScan (Etherscan family, `/tx/` and `/address/`; listed by the
        // Hyperliquid docs).
        explorer: Some("https://hyperevmscan.io".to_owned()),
        simulation: SimulationSupport::Auto,
        amsterdam_time: None,
        default_caps: FeeCaps {
            max_fee_per_gas: gwei(100),
            max_priority_fee_per_gas: gwei(10),
            max_total_fee: native_percent(18, 5),
        },
        tip_floor_wei: TIP_FLOOR_WEI,
        small_block_gas_limit: Some(HYPEREVM_SMALL_BLOCK_GAS),
        l1_data_fee: L1DataFee::None,
        tokens: &HYPEREVM_TOKENS,
        contracts: &HYPEREVM_CONTRACTS,
    }
}

/// Arbitrum One (spec/03 §1.1): the L1 cost is part of `gasUsed`, so `eth_estimateGas` already
/// covers it (no extra L1 fee); the chain ignores the tip.
#[must_use]
pub fn arbitrum_one() -> ChainInfo {
    ChainInfo {
        chain_id: ARBITRUM_ONE,
        source: ChainSource::BuiltIn,
        genesis: GenesisRule::Fixed(ARBITRUM_ONE_GENESIS),
        templates: Some(EndpointTemplates {
            quicknode_subdomain: Some("arbitrum-mainnet"),
            quicknode_path: None,
            alchemy_label: Some("arb-mainnet"),
        }),
        name: "Arbitrum One".to_owned(),
        native_symbol: "ETH".to_owned(),
        native_decimals: 18,
        explorer: Some("https://arbiscan.io".to_owned()),
        simulation: SimulationSupport::Auto,
        amsterdam_time: None,
        default_caps: FeeCaps {
            max_fee_per_gas: gwei(10),
            max_priority_fee_per_gas: gwei(1),
            max_total_fee: native_percent(18, 2),
        },
        tip_floor_wei: TIP_FLOOR_WEI,
        small_block_gas_limit: None,
        l1_data_fee: L1DataFee::None,
        tokens: &ARBITRUM_TOKENS,
        contracts: &NO_CONTRACTS,
    }
}

/// Base mainnet (spec/03 §1.1): OP-stack, the L1 data fee comes on top of `gas × price`
/// (§3.4a).
#[must_use]
pub fn base_mainnet() -> ChainInfo {
    ChainInfo {
        chain_id: BASE_MAINNET,
        source: ChainSource::BuiltIn,
        genesis: GenesisRule::Fixed(BASE_GENESIS),
        templates: Some(EndpointTemplates {
            quicknode_subdomain: Some("base-mainnet"),
            quicknode_path: None,
            alchemy_label: Some("base-mainnet"),
        }),
        name: "Base".to_owned(),
        native_symbol: "ETH".to_owned(),
        native_decimals: 18,
        explorer: Some("https://basescan.org".to_owned()),
        simulation: SimulationSupport::Auto,
        amsterdam_time: None,
        default_caps: FeeCaps {
            max_fee_per_gas: gwei(10),
            max_priority_fee_per_gas: gwei(1),
            max_total_fee: native_percent(18, 2),
        },
        tip_floor_wei: BASE_TIP_FLOOR_WEI,
        small_block_gas_limit: None,
        l1_data_fee: L1DataFee::OpStack,
        tokens: &BASE_TOKENS,
        contracts: &NO_CONTRACTS,
    }
}

/// BNB Smart Chain (spec/03 §1.1): type 2 with base fee 0 (BEP-226), so the whole price is
/// the tip; the floor is the validators' 0.05 gwei minimum.
#[must_use]
pub fn bsc_mainnet() -> ChainInfo {
    ChainInfo {
        chain_id: BSC_MAINNET,
        source: ChainSource::BuiltIn,
        genesis: GenesisRule::Fixed(BSC_GENESIS),
        templates: Some(EndpointTemplates {
            quicknode_subdomain: Some("bsc"),
            quicknode_path: None,
            alchemy_label: Some("bnb-mainnet"),
        }),
        name: "BNB Smart Chain".to_owned(),
        native_symbol: "BNB".to_owned(),
        native_decimals: 18,
        explorer: Some("https://bscscan.com".to_owned()),
        simulation: SimulationSupport::Auto,
        amsterdam_time: None,
        default_caps: FeeCaps {
            max_fee_per_gas: gwei(10),
            max_priority_fee_per_gas: gwei(10),
            max_total_fee: native_percent(18, 2),
        },
        tip_floor_wei: BSC_TIP_FLOOR_WEI,
        small_block_gas_limit: None,
        l1_data_fee: L1DataFee::None,
        tokens: &BSC_TOKENS,
        contracts: &NO_CONTRACTS,
    }
}

/// Robinhood Chain mainnet (spec/03 §1.1): an Arbitrum chain, fees as on Arbitrum One.
#[must_use]
pub fn robinhood_mainnet() -> ChainInfo {
    ChainInfo {
        chain_id: ROBINHOOD_MAINNET,
        source: ChainSource::BuiltIn,
        genesis: GenesisRule::Fixed(ROBINHOOD_GENESIS),
        templates: Some(EndpointTemplates {
            quicknode_subdomain: Some("robinhood-mainnet"),
            quicknode_path: None,
            alchemy_label: Some("robinhood-mainnet"),
        }),
        name: "Robinhood Chain".to_owned(),
        native_symbol: "ETH".to_owned(),
        native_decimals: 18,
        explorer: Some("https://robinhoodchain.blockscout.com".to_owned()),
        simulation: SimulationSupport::Auto,
        amsterdam_time: None,
        default_caps: FeeCaps {
            max_fee_per_gas: gwei(10),
            max_priority_fee_per_gas: gwei(1),
            max_total_fee: native_percent(18, 2),
        },
        tip_floor_wei: TIP_FLOOR_WEI,
        small_block_gas_limit: None,
        l1_data_fee: L1DataFee::None,
        tokens: &ROBINHOOD_TOKENS,
        contracts: &NO_CONTRACTS,
    }
}

/// The built-in chains, in table order.
#[must_use]
pub fn builtin_chains() -> [ChainInfo; 7] {
    [
        ethereum_mainnet(),
        sepolia(),
        hyperevm_mainnet(),
        arbitrum_one(),
        base_mainnet(),
        bsc_mainnet(),
        robinhood_mainnet(),
    ]
}

/// Whether `chain_id` is a built-in mainnet (real assets; the header badge).
#[must_use]
pub const fn is_builtin_mainnet(chain_id: u64) -> bool {
    matches!(
        chain_id,
        ETHEREUM_MAINNET
            | HYPEREVM_MAINNET
            | ARBITRUM_ONE
            | BASE_MAINNET
            | BSC_MAINNET
            | ROBINHOOD_MAINNET
    )
}

/// A built-in chain by id.
#[must_use]
pub fn builtin_chain(chain_id: u64) -> Option<ChainInfo> {
    builtin_chains()
        .into_iter()
        .find(|chain| chain.chain_id == chain_id)
}

impl ChainInfo {
    /// The pinned or fixed genesis, `None` before the first pin.
    #[must_use]
    pub const fn genesis_hash(&self) -> Option<[u8; 32]> {
        match self.genesis {
            GenesisRule::Fixed(hash) | GenesisRule::PinOnFirstUse(Some(hash)) => Some(hash),
            GenesisRule::PinOnFirstUse(None) => None,
        }
    }

    /// The registered token at `address`.
    #[must_use]
    pub fn token(&self, address: &Address) -> Option<&KnownToken> {
        self.tokens.iter().find(|token| token.address == *address)
    }

    /// The registered wrapped-native token.
    #[must_use]
    pub fn weth(&self) -> Option<&KnownToken> {
        self.tokens
            .iter()
            .find(|token| token.role == TokenRole::Weth)
    }

    /// The registered contract at `address`.
    #[must_use]
    pub fn contract(&self, address: &Address) -> Option<&KnownContract> {
        self.contracts
            .iter()
            .find(|contract| contract.address == *address)
    }

    /// The registered contract with `role`.
    #[must_use]
    pub fn contract_with_role(&self, role: ContractRole) -> Option<&KnownContract> {
        self.contracts.iter().find(|contract| contract.role == role)
    }

    /// Whether `address` is this chain's registered Permit2.
    #[must_use]
    pub fn is_permit2(&self, address: &Address) -> bool {
        self.contract(address)
            .is_some_and(|contract| contract.role == ContractRole::Permit2)
    }

    /// Whether `address` is this chain's registered wrapped-native token.
    #[must_use]
    pub fn is_weth(&self, address: &Address) -> bool {
        self.weth().is_some_and(|token| token.address == *address)
    }

    /// The registry label of `address` as displayed in `lang`.
    #[must_use]
    pub fn label_in(&self, address: &Address, lang: Lang) -> Option<&'static str> {
        self.contract(address)
            .map(|contract| lang.pick(contract.label, contract.label_en))
            .or_else(|| {
                self.token(address)
                    .map(|token| token.label.unwrap_or(token.symbol))
            })
    }

    /// The chain name as displayed in `lang`: built-in chains with a Korean name have an English
    /// one (spec/14 §4); every other name (user chains included) is the same in both languages.
    #[must_use]
    pub fn display_name(&self, lang: Lang) -> &str {
        if self.source == ChainSource::BuiltIn {
            for name in [
                text::CHAIN_ETHEREUM,
                text::CHAIN_SEPOLIA,
                text::CHAIN_HYPEREVM,
            ] {
                if self.name == name.ko {
                    return name.get(lang);
                }
            }
        }
        &self.name
    }
}

/// User chain input (spec/03 §1.6). The RPC URL is validated and stored by yw-app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserChainInput {
    /// Chain id.
    pub chain_id: u64,
    /// Display name.
    pub name: String,
    /// Native symbol.
    pub native_symbol: String,
    /// Native decimals.
    pub native_decimals: u8,
    /// Optional explorer URL (checked by yw-app `HttpsUrl::parse`).
    pub explorer: Option<String>,
    /// Simulation support.
    pub simulation: SimulationSupport,
}

/// User chain definition error (spec/03 §1.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainConfigError {
    /// `chain_id` is 0 or above the EIP-2294 maximum.
    ChainIdOutOfRange,
    /// `chain_id` is already registered (built-in or user).
    ChainIdRegistered,
    /// Name is empty, longer than 32 characters or 96 bytes, padded, or has forbidden characters.
    NameInvalid,
    /// Name equals a built-in chain name (case-insensitive).
    NameReserved,
    /// Symbol is not 1–16 characters of 0x21–0x7E.
    SymbolInvalid,
    /// Decimals above 36.
    DecimalsInvalid,
}

impl ChainConfigError {
    /// The S17 form text in `lang` (`Display` is the Korean one).
    #[must_use]
    pub const fn text_in(self, lang: Lang) -> &'static str {
        use config_text as t;
        match self {
            Self::ChainIdOutOfRange => t::CHAIN_ID_OUT_OF_RANGE,
            Self::ChainIdRegistered => t::CHAIN_ID_REGISTERED,
            Self::NameInvalid => t::NAME_INVALID,
            Self::NameReserved => t::NAME_RESERVED,
            Self::SymbolInvalid => t::SYMBOL_INVALID,
            Self::DecimalsInvalid => t::DECIMALS_INVALID,
        }
        .get(lang)
    }
}

impl fmt::Display for ChainConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.text_in(Lang::Ko))
    }
}

/// User chain definition errors shown on the S17 form (spec/03 §1.6; English spec/14 §5).
pub mod config_text {
    crate::texts! {
        CHAIN_ID_OUT_OF_RANGE = "체인 ID는 1 이상 9,223,372,036,854,775,771 이하여야 합니다."
            / "The chain ID must be between 1 and 9,223,372,036,854,775,771.";
        CHAIN_ID_REGISTERED = "이미 등록된 체인 ID입니다." / "This chain ID is already registered.";
        NAME_INVALID = "체인 이름은 앞뒤 공백·제어 문자 없이 1–32자여야 합니다."
            / "The chain name must be 1–32 characters with no leading/trailing spaces or control characters.";
        NAME_RESERVED = "기본 제공 체인과 같은 이름은 쓸 수 없습니다."
            / "A built-in chain already uses this name.";
        SYMBOL_INVALID = "심볼은 공백 없는 ASCII 1–16자여야 합니다."
            / "The symbol must be 1–16 ASCII characters without spaces.";
        DECIMALS_INVALID = "소수 자릿수는 0–36이어야 합니다." / "Decimals must be 0–36.";
    }
}

impl std::error::Error for ChainConfigError {}

/// Validates a user chain definition (spec/03 §1.6).
///
/// # Errors
///
/// [`ChainConfigError`] for the first violated rule.
pub fn validate_user_chain(
    input: &UserChainInput,
    registered: &[u64],
) -> Result<(), ChainConfigError> {
    if input.chain_id == 0 || input.chain_id > MAX_CHAIN_ID {
        return Err(ChainConfigError::ChainIdOutOfRange);
    }
    let builtin = builtin_chains();
    if registered.contains(&input.chain_id)
        || builtin.iter().any(|chain| chain.chain_id == input.chain_id)
    {
        return Err(ChainConfigError::ChainIdRegistered);
    }
    let name = &input.name;
    let characters = name.chars().count();
    if characters == 0
        || characters > 32
        || name.len() > 96
        || name.trim() != name
        || name.chars().any(is_forbidden_display_char)
    {
        return Err(ChainConfigError::NameInvalid);
    }
    let lowered = name.to_lowercase();
    if builtin.iter().any(|chain| {
        Lang::ALL
            .iter()
            .any(|lang| chain.display_name(*lang).to_lowercase() == lowered)
    }) {
        return Err(ChainConfigError::NameReserved);
    }
    let symbol = &input.native_symbol;
    if symbol.is_empty()
        || symbol.len() > 16
        || !symbol.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(ChainConfigError::SymbolInvalid);
    }
    if input.native_decimals > 36 {
        return Err(ChainConfigError::DecimalsInvalid);
    }
    Ok(())
}

/// Builds the [`ChainInfo`] of a validated user chain with its pinned genesis (spec/03 §1.6).
#[must_use]
pub fn user_chain_info(input: &UserChainInput, genesis: [u8; 32]) -> ChainInfo {
    ChainInfo {
        chain_id: input.chain_id,
        source: ChainSource::User,
        genesis: GenesisRule::PinOnFirstUse(Some(genesis)),
        templates: None,
        name: input.name.clone(),
        native_symbol: input.native_symbol.clone(),
        native_decimals: input.native_decimals,
        explorer: input.explorer.clone(),
        simulation: input.simulation,
        amsterdam_time: None,
        default_caps: FeeCaps {
            max_fee_per_gas: gwei(1_000),
            max_priority_fee_per_gas: gwei(100),
            max_total_fee: native_percent(input.native_decimals, 5),
        },
        tip_floor_wei: TIP_FLOOR_WEI,
        small_block_gas_limit: None,
        l1_data_fee: L1DataFee::Probe,
        tokens: &NO_TOKENS,
        contracts: &NO_CONTRACTS,
    }
}
