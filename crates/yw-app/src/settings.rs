//! `settings.json` (spec/04 §6.1–§6.2, D30): plaintext, no secrets, ≤ 64 KiB, strict yw-json
//! parsing, per-key validation with fallback to defaults (each failure becomes a banner entry), and
//! a fixed key order on write.
//!
//! Format compatibility (spec/04 §6.6): unknown top-level keys (a newer minor version's) are kept
//! and written back after the known keys; a file with a newer `version` is opened read-only with
//! defaults, and every write reproduces its original bytes instead of overwriting it.

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
/// The `settings.json` format version this build reads and writes (spec/04 §6.6).
pub const SETTINGS_VERSION: u64 = 1;
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

/// Format-compatibility state of the loaded file (spec/04 §6.6). It travels with every clone of
/// [`Settings`], so each write keeps it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SettingsCompat {
    /// Top-level keys this version does not know, in file order (written back after the known
    /// keys while the file stays within [`SETTINGS_MAX_BYTES`]).
    unknown: Vec<(String, Value)>,
    /// A file written by a newer format version: that version and the original bytes.
    newer: Option<(u64, Vec<u8>)>,
}

impl SettingsCompat {
    /// Names of the unknown top-level keys kept for write-back.
    #[must_use]
    pub fn unknown_keys(&self) -> Vec<&str> {
        self.unknown.iter().map(|(key, _)| key.as_str()).collect()
    }

    /// `Some(version)` when the file came from a newer format version: values are defaults, the
    /// file is never rewritten (writes reproduce its original bytes) and changes last only for this
    /// run.
    #[must_use]
    pub fn read_only_version(&self) -> Option<u64> {
        self.newer.as_ref().map(|(version, _)| *version)
    }
}

/// The E-APP-001 banner entry of a newer-version file (spec/04 §6.6).
#[must_use]
pub fn newer_version_banner(version: u64) -> String {
    format!(
        "settings.json은 더 새로운 버전({version})의 앱이 쓴 파일입니다 — 읽기 전용으로 열었고 이번 실행의 설정 변경은 저장되지 않습니다. 앱을 최신 버전으로 업데이트하세요"
    )
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
    /// Format compatibility (unknown keys, read-only newer file; spec/04 §6.6).
    pub compat: SettingsCompat,
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
            compat: SettingsCompat::default(),
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
    text.is_empty() || crate::explain::config::parse_endpoint(text).is_some()
}

fn llm_model_valid(text: &str) -> bool {
    text.is_empty() || crate::explain::config::valid_model(text)
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
    let Some(object) = root.as_ref().and_then(Value::as_object) else {
        return SettingsLoad {
            settings,
            banners: vec!["settings.json".to_owned()],
        };
    };
    match object
        .get("version")
        .and_then(Value::as_number)
        .and_then(yw_json::Number::as_u64)
    {
        Some(SETTINGS_VERSION) => {}
        Some(newer) if newer > SETTINGS_VERSION => {
            // Read-only: defaults for this run, the newer file is kept byte for byte (§6.6).
            settings.compat.newer = Some((newer, bytes.to_vec()));
            return SettingsLoad {
                settings,
                banners: vec![newer_version_banner(newer)],
            };
        }
        _ => {
            return SettingsLoad {
                settings,
                banners: vec!["settings.json".to_owned()],
            };
        }
    }
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
            // A newer minor version's key: kept and written back unchanged (§6.6).
            _ => settings
                .compat
                .unknown
                .push((key.to_owned(), value.clone())),
        }
    }
    SettingsLoad { settings, banners }
}

/// Serializes the `known` members (fixed order) followed by as many `unknown` members, in order,
/// as fit in `max_bytes` (spec/04 §6.6: the known keys always keep their place in the size bound).
/// `known` is called once, or twice when the unknown members do not all fit.
pub(crate) fn serialize_with_unknown(
    known: &dyn Fn() -> Vec<(&'static str, Value)>,
    unknown: &[(String, Value)],
    max_bytes: usize,
) -> Vec<u8> {
    let build = |count: usize| {
        let mut members: Vec<(String, Value)> = known()
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect();
        members.extend(unknown.iter().take(count).cloned());
        yw_json::to_vec(&json_object_owned(members).unwrap_or_else(|| json_object(Vec::new())))
    };
    let all = build(unknown.len());
    if all.len() <= max_bytes || unknown.is_empty() {
        return all;
    }
    // The writer is compact: one more member adds its `{…}` length minus the braces plus a comma.
    let extra: Vec<usize> = unknown
        .iter()
        .map(|(key, value)| {
            let alone = yw_json::to_vec(
                &json_object_owned(vec![(key.clone(), value.clone())])
                    .unwrap_or_else(|| json_object(Vec::new())),
            );
            alone.len().saturating_sub(1)
        })
        .collect();
    let mut size = all.len().saturating_sub(extra.iter().sum::<usize>());
    let mut keep = 0_usize;
    for length in &extra {
        size = size.saturating_add(*length);
        if size > max_bytes {
            break;
        }
        keep = keep.saturating_add(1);
    }
    let fitted = build(keep);
    if fitted.len() <= max_bytes {
        fitted
    } else {
        build(0)
    }
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

    /// Deterministic serialization in the spec/04 §6.1 key order, followed by the unknown keys
    /// kept from the file (§6.6). A newer-version file opened read-only is reproduced byte for
    /// byte, so saving never changes it.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        if let Some((_, original)) = &self.compat.newer {
            return original.clone();
        }
        serialize_with_unknown(
            &|| self.known_members(),
            &self.compat.unknown,
            SETTINGS_MAX_BYTES,
        )
    }

    /// `Some(version)` when the file came from a newer format version and is not written
    /// (spec/04 §6.6).
    #[must_use]
    pub fn read_only(&self) -> Option<u64> {
        self.compat.read_only_version()
    }

    fn known_members(&self) -> Vec<(&'static str, Value)> {
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
        vec![
            ("version", json_u64(SETTINGS_VERSION)),
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
        ]
    }
}

// ----- security settings snapshot (review M1, L15) -------------------------------------------
//
// `settings.json` is plaintext and unauthenticated (D30). The values that decide where wallet
// data goes or how much a transaction may cost are therefore also kept in the vault-encrypted
// `meta.ywm` (`security_settings`, AEAD under a DEK-derived key, so a change made outside the app
// is detected). The app writes the snapshot whenever it changes one of these values itself; after
// each unlock `reconcile` compares the file with it.

/// `security_settings.version`.
pub const SNAPSHOT_VERSION: u64 = 1;
/// The `App::save_settings` key of `파일 값 사용` (accepting every differing file value).
pub const ACCEPT_FILE_KEY: &str = "settingsFileAccepted";
/// The E-APP-001-style banner of a settings file changed outside the app.
pub const SETTINGS_TAMPERED_TEXT: &str = "설정 파일이 앱 밖에서 바뀌었습니다 — 확인하세요";
/// The banner when the AI explanation was on in `settings.json` without the user's consent for
/// that endpoint host in the snapshot.
pub const LLM_FORCED_OFF_TEXT: &str = "AI 설명 설정이 앱 밖에서 바뀌어(동의한 주소와 다름) AI 설명을 껐습니다. 아무것도 보내지 않습니다. 쓰려면 설정 → AI 설명에서 주소를 확인하고 다시 켜세요.";
/// The banner when a genesis pin was missing or changed in `settings.json`.
pub const PIN_RESTORED_TEXT: &str = "설정 파일의 체인 genesis 고정값이 앱 밖에서 지워지거나 바뀌어, 앱에 저장된 값으로 되돌렸습니다.";

/// The consent part of `llm_explain` the user last gave through the app (spec/06 §2.1-2.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LlmConsent {
    /// `enabled` as the app last wrote it.
    pub enabled: bool,
    /// The endpoint `host[:port]` (lowercase) the app last wrote; empty when no valid endpoint.
    pub host: String,
    /// `privacy_notice_version` as the app last wrote it.
    pub notice: u64,
}

/// The security-relevant settings as the app last wrote them (meta `security_settings`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecuritySnapshot {
    /// LLM consent.
    pub llm: LlmConsent,
    /// Genesis pins of every EVM chain that has one (`HyperEVM` from `evmGenesisPins`, user chains
    /// from `evmChains[].genesisHash`), by chain id ascending.
    pub genesis_pins: Vec<(u64, [u8; 32])>,
    /// `feeCaps`, by chain id ascending.
    pub fee_caps: Vec<(u64, FeeCapsText)>,
    /// `autoLockMinutes`.
    pub auto_lock_minutes: u8,
    /// `bitcoin.indexer`.
    pub btc_indexer: BtcIndexer,
    /// `bitcoin.esploraBaseUrl.mainnet`.
    pub esplora_mainnet: String,
    /// `bitcoin.esploraBaseUrl.testnet4`.
    pub esplora_testnet4: String,
}

fn endpoint_host(llm: &LlmSettings) -> String {
    crate::explain::config::parse_endpoint(&llm.endpoint).map_or_else(String::new, |e| e.host)
}

fn sorted_caps(caps: &[(u64, FeeCapsText)]) -> Vec<(u64, FeeCapsText)> {
    let mut out = caps.to_vec();
    out.sort_by_key(|(id, _)| *id);
    out
}

fn pins_of(settings: &Settings) -> Vec<(u64, [u8; 32])> {
    let mut pins: Vec<(u64, [u8; 32])> = settings
        .evm_genesis_pins
        .iter()
        .copied()
        .chain(
            settings
                .evm_chains
                .iter()
                .map(|chain| (chain.chain_id, chain.genesis_hash)),
        )
        .collect();
    pins.sort_by_key(|(id, _)| *id);
    pins.dedup_by_key(|(id, _)| *id);
    pins
}

fn caps_text_valid(text: &str) -> bool {
    (1..=40).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

impl SecuritySnapshot {
    /// The snapshot of `settings`.
    #[must_use]
    pub fn of(settings: &Settings) -> Self {
        Self {
            llm: LlmConsent {
                enabled: settings.llm_explain.enabled,
                host: endpoint_host(&settings.llm_explain),
                notice: settings.llm_explain.privacy_notice_version,
            },
            genesis_pins: pins_of(settings),
            fee_caps: sorted_caps(&settings.fee_caps),
            auto_lock_minutes: settings.auto_lock_minutes,
            btc_indexer: settings.bitcoin.indexer,
            esplora_mainnet: settings.bitcoin.esplora_mainnet.clone(),
            esplora_testnet4: settings.bitcoin.esplora_testnet4.clone(),
        }
    }

    /// The pinned genesis of `chain_id`, if any.
    #[must_use]
    pub fn pin(&self, chain_id: u64) -> Option<[u8; 32]> {
        self.genesis_pins
            .iter()
            .find(|(id, _)| *id == chain_id)
            .map(|(_, hash)| *hash)
    }

    /// Whether the user consented to send AI-explanation data to `host` with the current notice.
    #[must_use]
    pub fn llm_consented_to(&self, host: &str) -> bool {
        self.llm.enabled
            && !host.is_empty()
            && self.llm.host.eq_ignore_ascii_case(host)
            && self.llm.notice >= u64::from(crate::explain::config::PRIVACY_NOTICE_VERSION)
    }

    /// The meta JSON value (fixed key order).
    #[must_use]
    pub fn to_json(&self) -> Value {
        let pins = json_object_owned(
            self.genesis_pins
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
        let caps = json_object_owned(
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
        json_object(vec![
            ("version", json_u64(SNAPSHOT_VERSION)),
            (
                "llm",
                json_object(vec![
                    ("enabled", Value::Bool(self.llm.enabled)),
                    ("host", json_str(&self.llm.host)),
                    ("privacy_notice_version", json_u64(self.llm.notice)),
                ]),
            ),
            ("genesisPins", pins),
            ("feeCaps", caps),
            (
                "autoLockMinutes",
                json_u64(u64::from(self.auto_lock_minutes)),
            ),
            (
                "bitcoin",
                json_object(vec![
                    ("indexer", json_str(self.btc_indexer.as_str())),
                    ("esploraMainnet", json_str(&self.esplora_mainnet)),
                    ("esploraTestnet4", json_str(&self.esplora_testnet4)),
                ]),
            ),
        ])
    }

    /// Parses the meta JSON value strictly (exact keys, valid values); `None` on any violation.
    #[must_use]
    pub fn from_json(value: &Value) -> Option<Self> {
        let exact = |object: &Object, keys: &[&str]| {
            object.len() == keys.len() && keys.iter().all(|key| object.get(key).is_some())
        };
        let object = value.as_object()?;
        if !exact(
            object,
            &[
                "version",
                "llm",
                "genesisPins",
                "feeCaps",
                "autoLockMinutes",
                "bitcoin",
            ],
        ) || object.get("version")?.as_number()?.as_u64()? != SNAPSHOT_VERSION
        {
            return None;
        }
        let llm = object.get("llm")?.as_object()?;
        if !exact(llm, &["enabled", "host", "privacy_notice_version"]) {
            return None;
        }
        let host = llm.get("host")?.as_str()?;
        if host.len() > 300 || !host.is_ascii() {
            return None;
        }
        let consent = LlmConsent {
            enabled: llm.get("enabled")?.as_bool()?,
            host: host.to_owned(),
            notice: llm.get("privacy_notice_version")?.as_number()?.as_u64()?,
        };
        let mut genesis_pins = Vec::new();
        for (network, hash) in object.get("genesisPins")?.as_object()?.iter() {
            let NetworkId::Eip155(id) = NetworkId::parse(network)? else {
                return None;
            };
            genesis_pins.push((id, parse_hash32(hash.as_str()?)?));
        }
        let mut fee_caps = Vec::new();
        for (network, entry) in object.get("feeCaps")?.as_object()?.iter() {
            let NetworkId::Eip155(id) = NetworkId::parse(network)? else {
                return None;
            };
            let entry = entry.as_object()?;
            if !exact(
                entry,
                &[
                    "maxFeePerGasGwei",
                    "maxPriorityFeePerGasGwei",
                    "maxTotalFee",
                ],
            ) {
                return None;
            }
            let text = |key: &str| {
                entry
                    .get(key)
                    .and_then(Value::as_str)
                    .filter(|text| caps_text_valid(text))
            };
            fee_caps.push((
                id,
                caps(
                    text("maxFeePerGasGwei")?,
                    text("maxPriorityFeePerGasGwei")?,
                    text("maxTotalFee")?,
                ),
            ));
        }
        let minutes = object.get("autoLockMinutes")?.as_number()?.as_u64()?;
        if !(1..=60).contains(&minutes) {
            return None;
        }
        let bitcoin = object.get("bitcoin")?.as_object()?;
        if !exact(bitcoin, &["indexer", "esploraMainnet", "esploraTestnet4"]) {
            return None;
        }
        let url = |key: &str| {
            let text = bitcoin.get(key)?.as_str()?;
            (validate_esplora_url(text)? == text).then(|| text.to_owned())
        };
        genesis_pins.sort_by_key(|(id, _)| *id);
        fee_caps.sort_by_key(|(id, _)| *id);
        Some(Self {
            llm: consent,
            genesis_pins,
            fee_caps,
            auto_lock_minutes: u8::try_from(minutes).ok()?,
            btc_indexer: BtcIndexer::parse(bitcoin.get("indexer")?.as_str()?)?,
            esplora_mainnet: url("esploraMainnet")?,
            esplora_testnet4: url("esploraTestnet4")?,
        })
    }
}

/// A component of the snapshot whose file value differs and is not taken over silently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Differing {
    /// `feeCaps`.
    FeeCaps,
    /// `autoLockMinutes`.
    AutoLock,
    /// `bitcoin.indexer` / `bitcoin.esploraBaseUrl`.
    Indexer,
    /// User EVM chains present in the file but not in the snapshot (their genesis was never
    /// pinned by the app).
    NewChains,
}

impl Differing {
    /// The settings key named in the banner.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::FeeCaps => "feeCaps",
            Self::AutoLock => "autoLockMinutes",
            Self::Indexer => "bitcoin.indexer/esploraBaseUrl",
            Self::NewChains => "evmChains",
        }
    }
}

/// The outcome of [`reconcile`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reconciled {
    /// The settings to use from now on: the snapshot's value for every difference.
    pub effective: Settings,
    /// The file's settings with only the non-negotiable repairs (pins restored, LLM switched
    /// off): written to `settings.json` when `write_file`, and the values `파일 값 사용` takes.
    pub file: Settings,
    /// `file` differs from the input (a pin was restored or the LLM switched off).
    pub write_file: bool,
    /// The LLM was on in the file without a matching consent: it is off now.
    pub llm_forced_off: bool,
    /// Chains whose genesis pin was restored from the snapshot.
    pub pins_restored: Vec<u64>,
    /// Components that use the snapshot value until the user decides.
    pub differing: Vec<Differing>,
    /// The snapshot to store: the input plus what was taken over (keys the app itself saved
    /// before the check, and pins recorded on first use that the snapshot did not have yet).
    pub snapshot: SecuritySnapshot,
}

/// Compares the settings in use with the snapshot (after unlock). `accepted` are the save keys
/// (`App::save_settings`) the app itself wrote before the snapshot was available: those values
/// are taken over. A genesis pin that differs from the snapshot is always restored, even then.
///
/// - LLM: switched on (effectively) without a consent for the current endpoint host in the
///   snapshot → off (`file` and `effective`).
/// - Genesis pins: missing or changed → the snapshot's pin (`file` and `effective`); a pin the
///   snapshot lacks (first use) is taken over.
/// - Fee caps, auto-lock, Bitcoin indexer/Esplora URLs, user chains unknown to the snapshot →
///   `effective` uses the snapshot value, `file` keeps the file value ([`Differing`]).
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "one pass over the snapshot components in a fixed order"
)]
pub fn reconcile(current: &Settings, snapshot: &SecuritySnapshot, accepted: &[&str]) -> Reconciled {
    // `파일 값 사용` pressed while locked takes over every component except the LLM consent
    // (which only the S15 consent flow records).
    let all = accepted.contains(&ACCEPT_FILE_KEY);
    let saved = |prefix: &str| all || accepted.iter().any(|key| key.starts_with(prefix));
    let llm_saved = accepted.iter().any(|key| key.starts_with("llm_explain"));
    let mut file = current.clone();
    let mut next = snapshot.clone();
    let mut llm_forced_off = false;
    let mut pins_restored = Vec::new();
    let mut differing = Vec::new();

    // LLM consent.
    let host = endpoint_host(&current.llm_explain);
    if llm_saved {
        next.llm = SecuritySnapshot::of(current).llm;
    } else if crate::explain::config::effectively_enabled(&current.llm_explain)
        && !snapshot.llm_consented_to(&host)
    {
        file.llm_explain.enabled = false;
        llm_forced_off = true;
    }

    // Genesis pins.
    for (id, pin) in &snapshot.genesis_pins {
        if BUILTIN_EVM.contains(id) {
            let found = file
                .evm_genesis_pins
                .iter()
                .find(|(pinned, _)| pinned == id);
            if found.map(|(_, hash)| hash) != Some(pin) {
                file.evm_genesis_pins.retain(|(pinned, _)| pinned != id);
                file.evm_genesis_pins.push((*id, *pin));
                pins_restored.push(*id);
            }
        } else if let Some(chain) = file.evm_chains.iter_mut().find(|c| c.chain_id == *id)
            && chain.genesis_hash != *pin
        {
            chain.genesis_hash = *pin;
            pins_restored.push(*id);
        }
    }
    for (id, hash) in &current.evm_genesis_pins {
        if next.pin(*id).is_none() {
            next.genesis_pins.push((*id, *hash));
        }
    }
    let mut effective = file.clone();
    let unknown_chains: Vec<u64> = current
        .evm_chains
        .iter()
        .map(|chain| chain.chain_id)
        .filter(|id| snapshot.pin(*id).is_none())
        .collect();
    if !unknown_chains.is_empty() {
        if saved("evmChains") {
            for chain in current
                .evm_chains
                .iter()
                .filter(|chain| unknown_chains.contains(&chain.chain_id))
            {
                next.genesis_pins.push((chain.chain_id, chain.genesis_hash));
            }
        } else {
            differing.push(Differing::NewChains);
            effective
                .evm_chains
                .retain(|chain| !unknown_chains.contains(&chain.chain_id));
            if !effective.registered_evm().contains(&effective.evm_chain_id) {
                effective.evm_chain_id = Settings::default().evm_chain_id;
            }
            let registered = effective.registered_evm();
            effective.fee_caps.retain(|(id, _)| registered.contains(id));
        }
    }
    next.genesis_pins.sort_by_key(|(id, _)| *id);

    // Fee caps (only for chains registered in what is used).
    let registered = effective.registered_evm();
    let snapshot_caps: Vec<(u64, FeeCapsText)> = snapshot
        .fee_caps
        .iter()
        .filter(|(id, _)| registered.contains(id))
        .cloned()
        .collect();
    let current_caps: Vec<(u64, FeeCapsText)> = sorted_caps(&effective.fee_caps)
        .into_iter()
        .filter(|(id, _)| registered.contains(id))
        .collect();
    if saved("feeCaps") {
        next.fee_caps = sorted_caps(&current.fee_caps);
    } else if current_caps != snapshot_caps {
        differing.push(Differing::FeeCaps);
        effective.fee_caps = snapshot_caps;
    }

    // Auto-lock.
    if saved("autoLockMinutes") {
        next.auto_lock_minutes = current.auto_lock_minutes;
    } else if current.auto_lock_minutes != snapshot.auto_lock_minutes {
        differing.push(Differing::AutoLock);
        effective.auto_lock_minutes = snapshot.auto_lock_minutes;
    }

    // Bitcoin indexer and Esplora URLs.
    let bitcoin = &current.bitcoin;
    if saved("bitcoin") {
        next.btc_indexer = bitcoin.indexer;
        next.esplora_mainnet.clone_from(&bitcoin.esplora_mainnet);
        next.esplora_testnet4.clone_from(&bitcoin.esplora_testnet4);
    } else if bitcoin.indexer != snapshot.btc_indexer
        || bitcoin.esplora_mainnet != snapshot.esplora_mainnet
        || bitcoin.esplora_testnet4 != snapshot.esplora_testnet4
    {
        differing.push(Differing::Indexer);
        effective.bitcoin.indexer = snapshot.btc_indexer;
        effective
            .bitcoin
            .esplora_mainnet
            .clone_from(&snapshot.esplora_mainnet);
        effective
            .bitcoin
            .esplora_testnet4
            .clone_from(&snapshot.esplora_testnet4);
    }

    let write_file = file != *current;
    Reconciled {
        effective,
        file,
        write_file,
        llm_forced_off,
        pins_restored,
        differing,
        snapshot: next,
    }
}
