//! ST-5 (spec/04 §6.6): format compatibility across app versions with fixture files —
//! `settings.json` of the previous release, of a newer minor version (unknown top-level keys) and
//! of a newer major version (read-only), a newer minor version's `meta.ywm` plaintext, and
//! `apikeys.dpapi` orphan and unknown entries surviving saves. Names, tokens and keys are fake.

use yw_app::apikeys::{ApiKeys, KeyName, is_registered};
use yw_app::meta::{Meta, parse as parse_meta};
use yw_app::network::{BtcNet, NetworkId, SolCluster};
use yw_app::settings::{
    LogLevel, RpcTemplate, SETTINGS_MAX_BYTES, Settings, load, newer_version_banner,
};
use yw_json::Limits;
use yw_win::http::HttpsUrl;

const SETTINGS_V1: &[u8] = include_bytes!("fixtures/compat/settings-v1.json");
const SETTINGS_V1_NEWER_MINOR: &[u8] =
    include_bytes!("fixtures/compat/settings-v1-newer-minor.json");
const SETTINGS_V2: &[u8] = include_bytes!("fixtures/compat/settings-v2.json");
const META_V3_NEWER_MINOR: &[u8] = include_bytes!("fixtures/compat/meta-v3-newer-minor.json");

const LIMITS: Limits = Limits {
    max_bytes: SETTINGS_MAX_BYTES,
    max_depth: 8,
    max_nodes: 16_384,
    max_items: 16_384,
};

/// Top-level keys in file order (empty when `bytes` is not a JSON object).
fn keys_of(bytes: &[u8]) -> Vec<String> {
    yw_json::parse(bytes, &LIMITS)
        .ok()
        .and_then(|root| {
            root.as_object()
                .map(|object| object.keys().map(str::to_owned).collect())
        })
        .unwrap_or_default()
}

#[test]
fn settings_of_the_previous_release_load_without_banners_and_round_trip() {
    let loaded = load(Some(SETTINGS_V1));
    assert!(loaded.banners.is_empty(), "{:?}", loaded.banners);
    let settings = &loaded.settings;
    assert_eq!(settings.read_only(), None);
    assert!(settings.compat.unknown_keys().is_empty());
    assert_eq!(settings.auto_lock_minutes, 15);
    assert!(settings.allow_localhost_dapps && !settings.browser_auto_launch);
    assert_eq!(settings.evm_chain_id, 84_532);
    assert_eq!(settings.evm_chains.len(), 1);
    assert_eq!(
        settings.evm_chains[0].quicknode_subdomain.as_deref(),
        Some("base-sepolia")
    );
    assert_eq!(settings.evm_genesis_pins.len(), 1);
    assert_eq!(settings.fee_caps.len(), 1);
    assert_eq!(settings.solana.cluster, SolCluster::Devnet);
    assert!(settings.bitcoin.enabled);
    assert_eq!(settings.bitcoin.network, BtcNet::Testnet4);
    assert_eq!(
        settings.bitcoin.esplora_testnet4,
        "https://blockstream.info/testnet4/api"
    );
    assert_eq!(settings.log_level, LogLevel::Warn);
    // Written in the fixed order; reading it back gives the same values and bytes.
    let written = settings.to_json();
    let again = load(Some(&written));
    assert!(again.banners.is_empty());
    assert_eq!(&again.settings, settings);
    assert_eq!(again.settings.to_json(), written);
}

#[test]
fn settings_of_a_newer_minor_version_keep_unknown_keys_on_write() {
    let loaded = load(Some(SETTINGS_V1_NEWER_MINOR));
    assert!(loaded.banners.is_empty(), "{:?}", loaded.banners);
    assert_eq!(
        loaded.settings.compat.unknown_keys(),
        ["uiTheme", "addressLabels"]
    );
    assert_eq!(loaded.settings.evm_chains.len(), 1);
    assert_eq!(loaded.settings.rpc_template, RpcTemplate::Manual);
    // A user change in this version, then a save.
    let mut changed = loaded.settings.clone();
    changed.auto_lock_minutes = 5;
    let written = changed.to_json();
    let keys = keys_of(&written);
    assert_eq!(keys.first().map(String::as_str), Some("version"));
    assert_eq!(
        &keys[keys.len() - 3..],
        ["logLevel", "uiTheme", "addressLabels"]
    );
    let text = String::from_utf8(written.clone()).unwrap();
    assert!(text.ends_with(
        r#""uiTheme":"dark","addressLabels":{"enabled":true,"sources":["local","ens"],"limit":500}}"#
    ));
    let again = load(Some(&written));
    assert!(again.banners.is_empty());
    assert_eq!(again.settings.auto_lock_minutes, 5);
    assert_eq!(again.settings, changed);
}

#[test]
fn settings_of_a_newer_major_version_open_read_only() {
    let loaded = load(Some(SETTINGS_V2));
    assert_eq!(loaded.banners, [newer_version_banner(2)]);
    assert!(loaded.banners[0].contains("읽기 전용"));
    let settings = loaded.settings;
    assert_eq!(settings.read_only(), Some(2));
    // Values are this version's defaults (the newer layout is not interpreted).
    let defaults = Settings::default();
    assert_eq!(settings.evm_chain_id, defaults.evm_chain_id);
    assert!(settings.evm_chains.is_empty());
    // Changes last for this run only: every write reproduces the newer file byte for byte.
    let mut changed = settings.clone();
    changed.auto_lock_minutes = 30;
    changed.log_level = LogLevel::Debug;
    assert_eq!(changed.to_json(), SETTINGS_V2);
    assert_eq!(changed.read_only(), Some(2));
}

#[test]
fn unknown_keys_give_way_to_the_size_bound() {
    let filler = "x".repeat(60_000);
    let file = format!(r#"{{"version":1,"futureBlob":"{filler}","futureFlag":true}}"#);
    let loaded = load(Some(file.as_bytes()));
    assert!(loaded.banners.is_empty());
    assert_eq!(
        loaded.settings.compat.unknown_keys(),
        ["futureBlob", "futureFlag"]
    );
    assert!(loaded.settings.to_json().len() <= SETTINGS_MAX_BYTES);
    // 32 user chains make the known keys larger: the unknown keys that no longer fit are left out
    // and the file stays readable.
    let base = load(Some(SETTINGS_V1)).settings;
    let mut grown = loaded.settings.clone();
    grown.evm_chains = (0..32_u64)
        .map(|index| {
            let mut chain = base.evm_chains[0].clone();
            chain.chain_id = 20_000 + index;
            chain.name = format!("Chain {index}");
            chain.explorer = Some(format!(
                "https://explorer-{index}.example/{}",
                "p".repeat(150)
            ));
            chain
        })
        .collect();
    let written = grown.to_json();
    assert!(written.len() <= SETTINGS_MAX_BYTES, "{}", written.len());
    let again = load(Some(&written));
    assert!(again.banners.is_empty(), "{:?}", again.banners);
    assert_eq!(again.settings.evm_chains.len(), 32);
    assert!(again.settings.compat.unknown_keys().is_empty());
}

#[test]
fn meta_of_a_newer_minor_version_keeps_unknown_keys() {
    let parsed = parse_meta(META_V3_NEWER_MINOR).unwrap();
    assert!(!parsed.prefs_reset);
    let mut meta = parsed.meta;
    let unknown: Vec<&str> = meta.unknown.iter().map(|(key, _)| key.as_str()).collect();
    assert_eq!(unknown, ["watch_only", "ui_layout"]);
    assert_eq!(meta.book().len(), 1);
    assert_eq!(meta.tokens_of("eip155:84532").len(), 1);
    assert_eq!(meta.activity_of("eip155:84532").len(), 1);
    // A change in this version keeps the newer keys, after the known ones.
    meta.evm_accounts[0].label = "주 계정".to_owned();
    let written = meta.to_json();
    let text = String::from_utf8(written.clone()).unwrap();
    assert!(text.starts_with(r#"{"schema":"yw-meta/3","evm_accounts":"#));
    assert!(text.ends_with(
        r#""watch_only":[{"chain":"evm","address":"0x8617e340b3d01fa5f11f306f4090fd50e238070d","label":"보관"}],"ui_layout":{"columns":2}}"#
    ));
    let again = parse_meta(&written).unwrap();
    assert_eq!(again.meta, meta);
    assert_eq!(again.meta.to_json(), written);
    // Another schema is not this format (a format break moves to a new data folder).
    let other = String::from_utf8(META_V3_NEWER_MINOR.to_vec())
        .unwrap()
        .replacen("yw-meta/3", "yw-meta/4", 1);
    assert!(parse_meta(other.as_bytes()).is_err());
    assert!(Meta::default().unknown.is_empty());
}

fn entry(name: &str, value: &[u8]) -> Vec<u8> {
    let mut out = vec![u8::try_from(name.len()).unwrap_or(u8::MAX)];
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(value);
    out
}

fn plaintext(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = b"YWAPIK01".to_vec();
    out.push(u8::try_from(entries.len()).unwrap_or(u8::MAX));
    for (name, value) in entries {
        out.extend(entry(name, value));
    }
    out
}

#[test]
fn rpc_urls_of_user_chains_survive_a_newer_settings_file() {
    // The upgrade scenario: a newer major settings.json (read-only, defaults) hides the user
    // chain, so its `rpc:` entry is an orphan. It is kept through saves and comes back when the
    // chain is registered again.
    let settings = load(Some(SETTINGS_V2)).settings;
    let chain_url = b"https://base-sepolia.rpc.example/fake-path";
    let sepolia_url = b"https://sepolia.rpc.example/fake-path";
    let bytes = plaintext(&[
        ("rpc:eip155:84532", chain_url),
        ("rpc:eip155:11155111", sepolia_url),
        ("tpl:infura", b"FakeInfuraKey_0123456789"),
    ]);
    let decoded = ApiKeys::decode(&bytes, &|network| is_registered(&settings, network)).unwrap();
    assert_eq!(decoded.orphans, [KeyName::Rpc(NetworkId::Eip155(84_532))]);
    let mut keys = decoded.keys;
    assert_eq!(keys.endpoints().len(), 1);
    assert!(!keys.has(KeyName::Rpc(NetworkId::Eip155(84_532))));
    assert_eq!(keys.dormant_names(), ["rpc:eip155:84532", "tpl:infura"]);
    // An unrelated save in this run (e.g. a new Sepolia URL).
    keys.set_rpc(
        NetworkId::Eip155(11_155_111),
        &HttpsUrl::parse("https://sepolia-2.rpc.example/fake-path").unwrap(),
    );
    let saved = keys.encode();
    // The next run reads the previous-release settings again: the chain is registered.
    let v1 = load(Some(SETTINGS_V1)).settings;
    let back = ApiKeys::decode(&saved, &|network| is_registered(&v1, network)).unwrap();
    assert!(back.orphans.is_empty());
    assert_eq!(
        back.keys
            .rpc_url(NetworkId::Eip155(84_532))
            .unwrap()
            .expose()
            .as_bytes(),
        chain_url
    );
    assert_eq!(back.keys.dormant_names(), ["tpl:infura"]);
    assert_eq!(back.keys.endpoints().len(), 2);
}
