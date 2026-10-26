//! `settings.json` (spec/04 §6.1–§6.2, D30): plaintext, no secrets, ≤ 64 KiB, strict yw-json
//! parsing, per-key validation with fallback to defaults (each failure becomes a banner entry), and
//! a fixed key order on write.

use yw_core::evm::amount::{U256, parse_units};
use yw_core::evm::chain::{MAX_CHAIN_ID, SimulationSupport, builtin_chains};
use yw_json::{Limits, Object, Value};
use yw_win::http::HttpsUrl;

use crate::network::{BUILTIN_EVM, BtcNet, NetworkId, SolCluster};
use crate::text::{
    hash32_text, is_dns_label, is_symbol, is_valid_label, json_object, json_object_owned, json_str,
    json_u64, parse_hash32,
};

/// File size bound.
pub const SETTINGS_MAX_BYTES: usize = 65_536;
/// Maximum number of user EVM chains (spec/04 §2.17).
pub const MAX_CUSTOM_EVM_CHAINS: usize = 32;
/// Default Esplora base URLs (spec/08 §15).
pub const ESPLORA_DEFAULT_MAINNET: &str = "https://mempool.space/api";
/// Default Esplora base URL for testnet4.
pub const ESPLORA_DEFAULT_TESTNET4: &str = "https://mempool.space/testnet4/api";
/// Largest `max_tokens` for the LLM (spec/06 §2.1).
const LLM_MAX_TOKENS: u64 = 4_096;

const LIMITS: Limits = Limits {
    max_bytes: SETTINGS_MAX_BYTES,
    max_depth: 8,
    max_nodes: 16_384,
    max_items: 16_384,
};

/// `rpc.template` (spec/04 §2.11.1 `RpcTemplate`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcTemplate {
    /// `QuickNode` multichain.
    QuickNode,
    /// Alchemy.
    Alchemy,
    /// Manual URL entry.
    Manual,
}

impl RpcTemplate {
    /// Settings string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QuickNode => "quicknode",
            Self::Alchemy => "alchemy",
            Self::Manual => "manual",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "quicknode" => Some(Self::QuickNode),
            "alchemy" => Some(Self::Alchemy),
            "manual" => Some(Self::Manual),
            _ => None,
        }
    }
}

/// `logLevel`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// `error`.
    Error,
    /// `warn`.
    Warn,
    /// `info`.
    Info,
    /// `debug`.
    Debug,
}

impl LogLevel {
    /// Settings string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }

    /// Parses the settings string.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "error" => Some(Self::Error),
            "warn" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            _ => None,
        }
    }
}

/// `bitcoin.indexer` (spec/04 §1.9 `BtcIndexer`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcIndexer {
    /// `esplora`.
    Esplora,
    /// `bb-rpc`.
    BbRpc,
    /// `bb-rest`.
    BbRest,
}

impl BtcIndexer {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Esplora => "esplora",
            Self::BbRpc => "bb-rpc",
            Self::BbRest => "bb-rest",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "esplora" => Some(Self::Esplora),
            "bb-rpc" => Some(Self::BbRpc),
            "bb-rest" => Some(Self::BbRest),
            _ => None,
        }
    }
}

/// A user EVM chain (`EvmChainDef`, spec/04 §6.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmChainDef {
    /// Chain id.
    pub chain_id: u64,
    /// Display name.
    pub name: String,
    /// Native symbol.
    pub symbol: String,
    /// Native decimals.
    pub decimals: u8,
    /// `QuickNode` template subdomain.
    pub quicknode_subdomain: Option<String>,
    /// Alchemy template label.
    pub alchemy_label: Option<String>,
    /// Explorer base URL.
    pub explorer: Option<String>,
    /// Simulation support.
    pub simulation: SimulationSupport,
    /// Pinned genesis hash.
    pub genesis_hash: [u8; 32],
}

/// One `feeCaps` entry, kept as validated decimal strings.
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_field_names,
    reason = "field names mirror the settings.json keys"
)]
pub struct FeeCapsText {
    /// `maxFeePerGasGwei`.
    pub max_fee_per_gas_gwei: String,
    /// `maxPriorityFeePerGasGwei`.
    pub max_priority_fee_per_gas_gwei: String,
    /// `maxTotalFee` (native units).
    pub max_total_fee: String,
}

/// `solana` (spec/07 §10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SolanaSettings {
    /// Fee cap in lamports.
    pub max_fee_lamports: u64,
    /// CU price cap.
    pub max_cu_price_micro: u64,
    /// Active cluster.
    pub cluster: SolCluster,
}

/// `bitcoin` (spec/08 §2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinSettings {
    /// Bitcoin enabled.
    pub enabled: bool,
    /// Network.
    pub network: BtcNet,
    /// Indexer kind.
    pub indexer: BtcIndexer,
    /// Esplora base URL for mainnet (normalized).
    pub esplora_mainnet: String,
    /// Esplora base URL for testnet4 (normalized).
    pub esplora_testnet4: String,
}

/// `llm_explain` (spec/06 §2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LlmSettings {
    /// Enabled.
    pub enabled: bool,
    /// Endpoint URL (empty = unset).
    pub endpoint: String,
    /// Model (empty = unset).
    pub model: String,
    /// `json_schema` or `json_object`.
    pub response_format: String,
    /// 0 or 1–4096.
    pub max_tokens: u64,
    /// Accepted privacy notice version.
    pub privacy_notice_version: u64,
}

/// The whole settings file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// 1–60.
    pub auto_lock_minutes: u8,
    /// Secret copy toggle.
    pub allow_secret_copy: bool,
    /// localhost dApp toggle.
    pub allow_localhost_dapps: bool,
    /// yw-host auto launch.
    pub browser_auto_launch: bool,
    /// Active EVM chain.
    pub evm_chain_id: u64,
    /// User chains.
    pub evm_chains: Vec<EvmChainDef>,
    /// First-use genesis pins of built-in chains (`eip155:999` only).
    pub evm_genesis_pins: Vec<(u64, [u8; 32])>,
    /// Fee caps per registered chain.
    pub fee_caps: Vec<(u64, FeeCapsText)>,
    /// RPC template.
    pub rpc_template: RpcTemplate,
    /// Solana.
    pub solana: SolanaSettings,
    /// Bitcoin.
    pub bitcoin: BitcoinSettings,
    /// LLM.
    pub llm_explain: LlmSettings,
    /// Log level.
    pub log_level: LogLevel,
}

fn caps(fee: &str, tip: &str, total: &str) -> FeeCapsText {
    FeeCapsText {
        max_fee_per_gas_gwei: fee.to_owned(),
        max_priority_fee_per_gas_gwei: tip.to_owned(),
        max_total_fee: total.to_owned(),
    }
}

fn default_fee_caps() -> Vec<(u64, FeeCapsText)> {
    vec![
        (1, caps("200", "5", "0.05")),
        (11_155_111, caps("1000", "100", "1")),
    ]
}

impl Default for SolanaSettings {
    fn default() -> Self {
        Self {
            max_fee_lamports: 100_000,
            max_cu_price_micro: 1_000_000,
            cluster: SolCluster::Mainnet,
        }
    }
}

impl Default for BitcoinSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            network: BtcNet::Mainnet,
            indexer: BtcIndexer::Esplora,
            esplora_mainnet: ESPLORA_DEFAULT_MAINNET.to_owned(),
            esplora_testnet4: ESPLORA_DEFAULT_TESTNET4.to_owned(),
        }
    }
}

impl Default for LlmSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            model: String::new(),
            response_format: "json_schema".to_owned(),
            max_tokens: 0,
            privacy_notice_version: 0,
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 10,
            allow_secret_copy: false,
            allow_localhost_dapps: false,
            browser_auto_launch: true,
            evm_chain_id: 11_155_111,
            evm_chains: Vec::new(),
            evm_genesis_pins: Vec::new(),
            fee_caps: default_fee_caps(),
            rpc_template: RpcTemplate::QuickNode,
            solana: SolanaSettings::default(),
            bitcoin: BitcoinSettings::default(),
            llm_explain: LlmSettings::default(),
            log_level: LogLevel::Info,
        }
    }
}

/// Result of [`load`]: values plus the banner keys of everything that fell back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingsLoad {
    /// Effective settings.
    pub settings: Settings,
    /// Keys shown in the E-APP-001 banner (`"settings.json"` when the whole file was rejected).
    pub banners: Vec<String>,
}

/// Validates an Esplora base URL (spec/04 §6.1 `EsploraBaseUrl`) and returns its normal form.
#[must_use]
pub fn validate_esplora_url(text: &str) -> Option<String> {
    if text.len() > 256 || text.contains('?') || text.contains('#') || text.ends_with('/') {
        return None;
    }
    let url = HttpsUrl::parse(text).ok()?;
    let host = url.host();
    for provider in ["quiknode.pro", "g.alchemy.com"] {
        if host == provider || host.ends_with(&format!(".{provider}")) {
            return None;
        }
    }
    let normalized = url.expose();
    let after_scheme = normalized.strip_prefix("https://")?;
    let path = after_scheme
        .find('/')
        .map_or("", |index| after_scheme.get(index..).unwrap_or(""));
    if !path.is_empty() {
        for segment in path.get(1..)?.split('/') {
            let mut bytes = segment.bytes();
            let first_ok = bytes.next().is_some_and(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'~' | b'-')
            });
            let rest_ok = bytes.all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-')
            });
            if !first_ok || !rest_ok || segment.len() > 64 {
                return None;
            }
        }
    }
    Some(normalized.to_owned())
}

/// Validates an explorer URL (spec/04 §2.17.1): `HttpsUrl`, ≤ 256 bytes, no `?`/`#`, trailing `/`
/// removed.
#[must_use]
pub fn validate_explorer(text: &str) -> Option<String> {
    let trimmed = text.strip_suffix('/').unwrap_or(text);
    if trimmed.len() > 256
        || trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.ends_with('/')
    {
        return None;
    }
    HttpsUrl::parse(trimmed)
        .ok()
        .map(|url| url.expose().to_owned())
}

fn builtin_names() -> Vec<String> {
    builtin_chains()
        .iter()
        .map(|chain| chain.name.clone())
        .collect()
}

fn parse_chain(item: &Value) -> Option<EvmChainDef> {
    const KEYS: [&str; 9] = [
        "chainId",
        "name",
        "symbol",
        "decimals",
        "quicknodeSubdomain",
        "alchemyLabel",
        "explorer",
        "simulation",
        "genesisHash",
    ];
    let object = item.as_object()?;
    if object.keys().any(|key| !KEYS.contains(&key)) {
        return None;
    }
    let chain_id = object.get("chainId")?.as_number()?.as_u64()?;
    if chain_id == 0 || chain_id > MAX_CHAIN_ID || BUILTIN_EVM.contains(&chain_id) {
        return None;
    }
    let name = object.get("name")?.as_str()?;
    if !is_valid_label(name) {
        return None;
    }
    let symbol = object.get("symbol")?.as_str()?;
    if !is_symbol(symbol) {
        return None;
    }
    let decimals = u8::try_from(object.get("decimals")?.as_number()?.as_u64()?).ok()?;
    if decimals > 36 {
        return None;
    }
    let optional_label = |key: &str| -> Option<Option<String>> {
        match object.get(key) {
            None => Some(None),
            Some(value) => {
                let text = value.as_str()?;
                is_dns_label(text).then(|| Some(text.to_owned()))
            }
        }
    };
    let quicknode_subdomain = optional_label("quicknodeSubdomain")?;
    let alchemy_label = optional_label("alchemyLabel")?;
    let explorer = match object.get("explorer") {
        None => None,
        Some(value) => {
            let text = value.as_str()?;
            let checked = validate_explorer(text)?;
            if checked != text {
                return None;
            }
            Some(checked)
        }
    };
    let simulation = SimulationSupport::parse(object.get("simulation")?.as_str()?)?;
    let genesis_hash = parse_hash32(object.get("genesisHash")?.as_str()?)?;
    Some(EvmChainDef {
        chain_id,
        name: name.to_owned(),
        symbol: symbol.to_owned(),
        decimals,
        quicknode_subdomain,
        alchemy_label,
        explorer,
        simulation,
        genesis_hash,
    })
}

fn load_chains(value: Option<&Value>, banners: &mut Vec<String>) -> Vec<EvmChainDef> {
    let Some(value) = value else {
        return Vec::new();
    };
    let Some(items) = value.as_array() else {
        banners.push("evmChains".to_owned());
        return Vec::new();
    };
    let reserved = builtin_names();
    let mut chains: Vec<EvmChainDef> = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let accepted = (chains.len() < MAX_CUSTOM_EVM_CHAINS)
            .then(|| parse_chain(item))
            .flatten()
            .filter(|chain| {
                !chains.iter().any(|other| {
                    other.chain_id == chain.chain_id || other.name.eq_ignore_ascii_case(&chain.name)
                }) && !reserved
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(&chain.name))
            });
        match accepted {
            Some(chain) => chains.push(chain),
            None => banners.push(format!("evmChains[{index}]")),
        }
    }
    chains
}

/// Native decimals of a registered EVM chain.
#[must_use]
pub fn chain_decimals(chains: &[EvmChainDef], chain_id: u64) -> Option<u8> {
    if BUILTIN_EVM.contains(&chain_id) {
        return Some(18);
    }
    chains
        .iter()
        .find(|chain| chain.chain_id == chain_id)
        .map(|chain| chain.decimals)
}

/// Validates one `feeCaps` entry (spec/04 §6.1).
#[must_use]
pub fn validate_fee_caps(value: &Value, decimals: u8) -> Option<FeeCapsText> {
    let object = value.as_object()?;
    if object.len() != 3 {
        return None;
    }
    let fee_text = object.get("maxFeePerGasGwei")?.as_str()?;
    let tip_text = object.get("maxPriorityFeePerGasGwei")?.as_str()?;
    let total_text = object.get("maxTotalFee")?.as_str()?;
    let gwei = |text: &str| parse_units(text, 9).ok();
    let fee = gwei(fee_text)?;
    let tip = gwei(tip_text)?;
    let total = parse_units(total_text, decimals).ok()?;
    let in_range = |value: U256, low: U256, high: U256| value >= low && value <= high;
    let ok = in_range(fee, gwei("1")?, gwei("10000")?)
        && in_range(tip, gwei("0.01")?, gwei("10000")?)
        && tip <= fee
        && in_range(
            total,
            parse_units("0.0001", decimals).ok()?,
            parse_units("10", decimals).ok()?,
        );
    ok.then(|| caps(fee_text, tip_text, total_text))
}

fn load_solana(object: &Object) -> Option<SolanaSettings> {
    let mut solana = SolanaSettings::default();
    for (key, value) in object.iter() {
        match key {
            "max_fee_lamports" => {
                let number = value.as_number()?.as_u64()?;
                (10_000..=10_000_000).contains(&number).then_some(())?;
                solana.max_fee_lamports = number;
            }
            "max_cu_price_micro" => {
                let number = value.as_number()?.as_u64()?;
                (number <= 100_000_000).then_some(())?;
                solana.max_cu_price_micro = number;
            }
            "cluster" => solana.cluster = SolCluster::parse(value.as_str()?)?,
            _ => return None,
        }
    }
    Some(solana)
}

fn llm_endpoint_valid(text: &str) -> bool {
    if text.is_empty() {
        return true;
    }
    text.len() <= 2_048
        && !text.contains('@')
        && !text.contains('?')
        && !text.contains('#')
        && text.ends_with("/chat/completions")
        && yw_win::http::EndpointUrl::parse(text).is_ok()
}

fn llm_model_valid(text: &str) -> bool {
    text.is_empty()
        || ((1..=128).contains(&text.len())
            && text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:/@+-".contains(&byte)))
}

fn load_llm(object: &Object) -> Option<LlmSettings> {
    let mut llm = LlmSettings::default();
    for (key, value) in object.iter() {
        match key {
            "enabled" => llm.enabled = value.as_bool()?,
            "endpoint" => {
                let text = value.as_str()?;
                llm_endpoint_valid(text).then_some(())?;
                text.clone_into(&mut llm.endpoint);
            }
            "model" => {
                let text = value.as_str()?;
                llm_model_valid(text).then_some(())?;
                text.clone_into(&mut llm.model);
            }
            "response_format" => {
                let text = value.as_str()?;
                matches!(text, "json_schema" | "json_object").then_some(())?;
                text.clone_into(&mut llm.response_format);
            }
            "max_tokens" => {
                let number = value.as_number()?.as_u64()?;
                (number <= LLM_MAX_TOKENS).then_some(())?;
                llm.max_tokens = number;
            }
            "privacy_notice_version" => {
                llm.privacy_notice_version = value.as_number()?.as_u64()?;
            }
            _ => return None,
        }
    }
    Some(llm)
}

fn load_bitcoin(object: &Object, banners: &mut Vec<String>) -> Option<BitcoinSettings> {
    if object
        .keys()
        .any(|key| !matches!(key, "enabled" | "network" | "indexer" | "esploraBaseUrl"))
    {
        return None;
    }
    let mut bitcoin = BitcoinSettings {
        enabled: object.get("enabled")?.as_bool()?,
        network: BtcNet::parse(object.get("network")?.as_str()?)?,
        indexer: BtcIndexer::parse(object.get("indexer")?.as_str()?)?,
        ..BitcoinSettings::default()
    };
    match object.get("esploraBaseUrl") {
        None => {}
        Some(Value::Object(urls)) => {
            for (key, value) in urls.iter() {
                let target = match key {
                    "mainnet" => &mut bitcoin.esplora_mainnet,
                    "testnet4" => &mut bitcoin.esplora_testnet4,
                    _ => {
                        banners.push(format!("bitcoin.esploraBaseUrl.{key}"));
                        continue;
                    }
                };
                match value.as_str().and_then(validate_esplora_url) {
                    Some(url) => *target = url,
                    None => banners.push(format!("bitcoin.esploraBaseUrl.{key}")),
                }
            }
        }
        Some(_) => banners.push("bitcoin.esploraBaseUrl".to_owned()),
    }
    Some(bitcoin)
}

/// Parses `settings.json` bytes (`None` = file absent).
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "one pass over the fixed top-level keys"
)]
pub fn load(bytes: Option<&[u8]>) -> SettingsLoad {
    let mut settings = Settings::default();
    let mut banners = Vec::new();
    let Some(bytes) = bytes else {
        return SettingsLoad { settings, banners };
    };
    let root = yw_json::parse(bytes, &LIMITS).ok();
    let Some(object) = root.as_ref().and_then(Value::as_object).filter(|object| {
        object
            .get("version")
            .and_then(Value::as_number)
            .and_then(yw_json::Number::as_u64)
            == Some(1)
    }) else {
        return SettingsLoad {
            settings,
            banners: vec!["settings.json".to_owned()],
        };
    };
    settings.evm_chains = load_chains(object.get("evmChains"), &mut banners);
    let registered: Vec<u64> = BUILTIN_EVM
        .iter()
        .copied()
        .chain(settings.evm_chains.iter().map(|chain| chain.chain_id))
        .collect();
    for (key, value) in object.iter() {
        match key {
            "version" | "evmChains" => {}
            "autoLockMinutes" => match value
                .as_number()
                .and_then(yw_json::Number::as_u64)
                .filter(|minutes| (1..=60).contains(minutes))
                .and_then(|minutes| u8::try_from(minutes).ok())
            {
                Some(minutes) => settings.auto_lock_minutes = minutes,
                None => banners.push(key.to_owned()),
            },
            "allowSecretCopy" | "allowLocalhostDapps" | "browserAutoLaunch" => {
                match value.as_bool() {
                    Some(flag) => match key {
                        "allowSecretCopy" => settings.allow_secret_copy = flag,
                        "allowLocalhostDapps" => settings.allow_localhost_dapps = flag,
                        _ => settings.browser_auto_launch = flag,
                    },
                    None => banners.push(key.to_owned()),
                }
            }
            "evmChainId" => match value
                .as_number()
                .and_then(yw_json::Number::as_u64)
                .filter(|id| registered.contains(id))
            {
                Some(id) => settings.evm_chain_id = id,
                None => banners.push(key.to_owned()),
            },
            "evmGenesisPins" => {
                let Some(pins) = value.as_object() else {
                    banners.push(key.to_owned());
                    continue;
                };
                for (network, hash) in pins.iter() {
                    let parsed = NetworkId::parse(network)
                        .filter(|id| *id == NetworkId::Eip155(999))
                        .zip(hash.as_str().and_then(parse_hash32));
                    match parsed {
                        Some((NetworkId::Eip155(id), hash)) => {
                            settings.evm_genesis_pins.push((id, hash));
                        }
                        _ => banners.push(format!("evmGenesisPins.{network}")),
                    }
                }
            }
            "feeCaps" => {
                let Some(entries) = value.as_object() else {
                    banners.push(key.to_owned());
                    continue;
                };
                let mut caps_list: Vec<(u64, FeeCapsText)> = Vec::new();
                for (network, entry) in entries.iter() {
                    let id = match NetworkId::parse(network) {
                        Some(NetworkId::Eip155(id)) if registered.contains(&id) => id,
                        _ => {
                            banners.push(format!("feeCaps.{network}"));
                            continue;
                        }
                    };
                    let decimals = chain_decimals(&settings.evm_chains, id).unwrap_or(18);
                    match validate_fee_caps(entry, decimals) {
                        Some(text) => caps_list.push((id, text)),
                        None => banners.push(format!("feeCaps.{network}")),
                    }
                }
                settings.fee_caps = caps_list;
            }
            "rpc" => {
                let template = value
                    .as_object()
                    .filter(|rpc| rpc.len() == 1)
                    .and_then(|rpc| {
                        rpc.get("template")
                            .and_then(Value::as_str)
                            .and_then(RpcTemplate::parse)
                    });
                match template {
                    Some(template) => settings.rpc_template = template,
                    None => banners.push(key.to_owned()),
                }
            }
            "solana" => match value.as_object().and_then(load_solana) {
                Some(solana) => settings.solana = solana,
                None => banners.push(key.to_owned()),
            },
            "bitcoin" => match value
                .as_object()
                .and_then(|bitcoin| load_bitcoin(bitcoin, &mut banners))
            {
                Some(bitcoin) => settings.bitcoin = bitcoin,
                None => banners.push(key.to_owned()),
            },
            "llm_explain" => match value.as_object().and_then(load_llm) {
                Some(llm) => settings.llm_explain = llm,
                None => banners.push(key.to_owned()),
            },
            "logLevel" => match value.as_str().and_then(LogLevel::parse) {
                Some(level) => settings.log_level = level,
                None => banners.push(key.to_owned()),
            },
            _ => banners.push(key.to_owned()),
        }
    }
    SettingsLoad { settings, banners }
}

fn chain_json(chain: &EvmChainDef) -> Value {
    let mut pairs = vec![
        ("chainId", json_u64(chain.chain_id)),
        ("name", json_str(&chain.name)),
        ("symbol", json_str(&chain.symbol)),
        ("decimals", json_u64(u64::from(chain.decimals))),
    ];
    if let Some(subdomain) = &chain.quicknode_subdomain {
        pairs.push(("quicknodeSubdomain", json_str(subdomain)));
    }
    if let Some(label) = &chain.alchemy_label {
        pairs.push(("alchemyLabel", json_str(label)));
    }
    if let Some(explorer) = &chain.explorer {
        pairs.push(("explorer", json_str(explorer)));
    }
    pairs.push(("simulation", json_str(chain.simulation.as_str())));
    pairs.push(("genesisHash", json_str(&hash32_text(&chain.genesis_hash))));
    json_object(pairs)
}

impl Settings {
    /// Registered EVM chain ids (built-in first, then user chains in order).
    #[must_use]
    pub fn registered_evm(&self) -> Vec<u64> {
        BUILTIN_EVM
            .iter()
            .copied()
            .chain(self.evm_chains.iter().map(|chain| chain.chain_id))
            .collect()
    }

    /// Display name of a registered EVM chain.
    #[must_use]
    pub fn evm_chain_name(&self, chain_id: u64) -> Option<String> {
        if let Some(chain) = yw_core::evm::chain::builtin_chain(chain_id) {
            return Some(chain.name);
        }
        self.evm_chains
            .iter()
            .find(|chain| chain.chain_id == chain_id)
            .map(|chain| chain.name.clone())
    }

    /// Deterministic serialization in the spec/04 §6.1 key order.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        let pins = json_object_owned(
            self.evm_genesis_pins
                .iter()
                .map(|(id, hash)| {
                    (
                        NetworkId::Eip155(*id).to_string(),
                        json_str(&hash32_text(hash)),
                    )
                })
                .collect(),
        )
        .unwrap_or_else(|| json_object(Vec::new()));
        let fee_caps = json_object_owned(
            self.fee_caps
                .iter()
                .map(|(id, caps)| {
                    (
                        NetworkId::Eip155(*id).to_string(),
                        json_object(vec![
                            ("maxFeePerGasGwei", json_str(&caps.max_fee_per_gas_gwei)),
                            (
                                "maxPriorityFeePerGasGwei",
                                json_str(&caps.max_priority_fee_per_gas_gwei),
                            ),
                            ("maxTotalFee", json_str(&caps.max_total_fee)),
                        ]),
                    )
                })
                .collect(),
        )
        .unwrap_or_else(|| json_object(Vec::new()));
        let root = json_object(vec![
            ("version", json_u64(1)),
            (
                "autoLockMinutes",
                json_u64(u64::from(self.auto_lock_minutes)),
            ),
            ("allowSecretCopy", Value::Bool(self.allow_secret_copy)),
            (
                "allowLocalhostDapps",
                Value::Bool(self.allow_localhost_dapps),
            ),
            ("browserAutoLaunch", Value::Bool(self.browser_auto_launch)),
            ("evmChainId", json_u64(self.evm_chain_id)),
            (
                "evmChains",
                Value::Array(self.evm_chains.iter().map(chain_json).collect()),
            ),
            ("evmGenesisPins", pins),
            ("feeCaps", fee_caps),
            (
                "rpc",
                json_object(vec![("template", json_str(self.rpc_template.as_str()))]),
            ),
            (
                "solana",
                json_object(vec![
                    ("max_fee_lamports", json_u64(self.solana.max_fee_lamports)),
                    (
                        "max_cu_price_micro",
                        json_u64(self.solana.max_cu_price_micro),
                    ),
                    ("cluster", json_str(self.solana.cluster.as_str())),
                ]),
            ),
            (
                "bitcoin",
                json_object(vec![
                    ("enabled", Value::Bool(self.bitcoin.enabled)),
                    ("network", json_str(self.bitcoin.network.as_str())),
                    ("indexer", json_str(self.bitcoin.indexer.as_str())),
                    (
                        "esploraBaseUrl",
                        json_object(vec![
                            ("mainnet", json_str(&self.bitcoin.esplora_mainnet)),
                            ("testnet4", json_str(&self.bitcoin.esplora_testnet4)),
                        ]),
                    ),
                ]),
            ),
            (
                "llm_explain",
                json_object(vec![
                    ("enabled", Value::Bool(self.llm_explain.enabled)),
                    ("endpoint", json_str(&self.llm_explain.endpoint)),
                    ("model", json_str(&self.llm_explain.model)),
                    (
                        "response_format",
                        json_str(&self.llm_explain.response_format),
                    ),
                    ("max_tokens", json_u64(self.llm_explain.max_tokens)),
                    (
                        "privacy_notice_version",
                        json_u64(self.llm_explain.privacy_notice_version),
                    ),
                ]),
            ),
            ("logLevel", json_str(self.log_level.as_str())),
        ]);
        yw_json::to_vec(&root)
    }
}
