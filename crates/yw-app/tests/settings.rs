//! ST-1 (spec/04 §6.5): `settings.json` validation, per-key fallback with banners, and the
//! fixed-order round trip.

use yw_app::network::{BtcNet, SolCluster};
use yw_app::settings::{
    ESPLORA_DEFAULT_MAINNET, ESPLORA_DEFAULT_TESTNET4, LogLevel, RpcTemplate, Settings,
    SettingsLoad, load, validate_esplora_url,
};

fn genesis(byte: &str) -> String {
    format!("0x{}", byte.repeat(64))
}

fn chain(id: u64, name: &str) -> String {
    format!(
        r#"{{"chainId":{id},"name":"{name}","symbol":"ETH","decimals":18,"simulation":"auto","genesisHash":"{}"}}"#,
        genesis("a")
    )
}

fn with(body: &str) -> SettingsLoad {
    load(Some(format!(r#"{{"version":1,{body}}}"#).as_bytes()))
}

#[test]
fn absent_file_and_whole_file_errors_use_defaults() {
    assert_eq!(load(None).settings, Settings::default());
    assert!(load(None).banners.is_empty());
    for bad in [
        b"not json".as_slice(),
        br#"{"version":2}"#,
        br"[]",
        br#"{"version":1,"version":1}"#,
        br#"{"autoLockMinutes":5}"#,
    ] {
        let loaded = load(Some(bad));
        assert_eq!(loaded.settings, Settings::default());
        assert_eq!(loaded.banners, ["settings.json"]);
    }
    let oversized = format!(r#"{{"version":1,"logLevel":"{}"}}"#, "x".repeat(70_000));
    assert_eq!(load(Some(oversized.as_bytes())).banners, ["settings.json"]);
}

#[test]
fn chains_beyond_32_are_dropped() {
    let chains: Vec<String> = (0..33)
        .map(|i| chain(100 + i, &format!("체인 {i}")))
        .collect();
    let loaded = with(&format!(r#""evmChains":[{}]"#, chains.join(",")));
    assert_eq!(loaded.settings.evm_chains.len(), 32);
    assert_eq!(loaded.banners, ["evmChains[32]"]);
}

#[test]
fn invalid_chain_items_are_dropped_one_by_one() {
    let items = [
        chain(84_532, "Base Sepolia"),
        chain(999, "Hyper again"),
        chain(84_532, "Duplicate id"),
        chain(7, "sepolia 테스트넷"),
        chain(8, "Decimals").replace(r#""decimals":18"#, r#""decimals":37"#),
        chain(9, "Off").replace(r#""simulation":"auto""#, r#""simulation":"off""#),
        chain(10, "Upper").replace(&genesis("a"), &genesis("A")),
        chain(11, "Explorer").replace(
            r#""symbol""#,
            r#""explorer":"https://scan.example/?q=1","symbol""#,
        ),
        chain(12, "Unknown key").replace(r#""symbol""#, r#""rpcUrl":"https://x.example","symbol""#),
        chain(13, "Bad sub").replace(
            r#""symbol""#,
            r#""quicknodeSubdomain":"Base_Sepolia","symbol""#,
        ),
        chain(14, "Good sub").replace(
            r#""symbol""#,
            r#""quicknodeSubdomain":"base-sepolia","symbol""#,
        ),
    ];
    let loaded = with(&format!(
        r#""evmChains":[{}],"evmChainId":7,"feeCaps":{{"eip155:7":{{"maxFeePerGasGwei":"1","maxPriorityFeePerGasGwei":"1","maxTotalFee":"1"}}}},"evmGenesisPins":{{"eip155:1":"{}","eip155:999":"{}"}}"#,
        items.join(","),
        genesis("b"),
        genesis("c")
    ));
    let ids: Vec<u64> = loaded
        .settings
        .evm_chains
        .iter()
        .map(|c| c.chain_id)
        .collect();
    assert_eq!(ids, [84_532, 14]);
    assert_eq!(
        loaded.settings.evm_chains[1].quicknode_subdomain.as_deref(),
        Some("base-sepolia")
    );
    for index in 1..=9 {
        assert!(
            loaded.banners.contains(&format!("evmChains[{index}]")),
            "{index}"
        );
    }
    assert_eq!(loaded.settings.evm_chain_id, 11_155_111);
    assert!(loaded.banners.contains(&"evmChainId".to_owned()));
    assert!(loaded.settings.fee_caps.is_empty());
    assert!(loaded.banners.contains(&"feeCaps.eip155:7".to_owned()));
    assert_eq!(loaded.settings.evm_genesis_pins.len(), 1);
    assert_eq!(loaded.settings.evm_genesis_pins[0].0, 999);
    assert!(
        loaded
            .banners
            .contains(&"evmGenesisPins.eip155:1".to_owned())
    );
}

#[test]
fn rpc_and_bitcoin_objects_fall_back_as_a_whole() {
    let loaded = with(r#""rpc":{"template":"infura"}"#);
    assert_eq!(loaded.settings.rpc_template, RpcTemplate::QuickNode);
    assert_eq!(loaded.banners, ["rpc"]);
    let loaded = with(r#""rpc":{"template":"alchemy","provider":"x"}"#);
    assert_eq!(loaded.settings.rpc_template, RpcTemplate::QuickNode);
    assert_eq!(loaded.banners, ["rpc"]);
    let loaded = with(r#""rpc":{"template":"manual"}"#);
    assert_eq!(loaded.settings.rpc_template, RpcTemplate::Manual);

    let loaded = with(
        r#""bitcoin":{"enabled":true,"network":"testnet4","indexer":"blockbook","esploraBaseUrl":{"mainnet":"https://a.example"}}"#,
    );
    assert_eq!(loaded.settings.bitcoin, Settings::default().bitcoin);
    assert_eq!(loaded.banners, ["bitcoin"]);

    let loaded = with(r#""bitcoin":{"enabled":true,"network":"testnet4","indexer":"bb-rpc"}"#);
    assert!(loaded.banners.is_empty());
    assert!(loaded.settings.bitcoin.enabled);
    assert_eq!(loaded.settings.bitcoin.network, BtcNet::Testnet4);
    assert_eq!(
        loaded.settings.bitcoin.esplora_mainnet,
        ESPLORA_DEFAULT_MAINNET
    );
}

#[test]
fn esplora_urls_are_validated_per_network_key() {
    for bad in [
        "http://mempool.space/api",
        "https://mempool.space/api/",
        "https://mempool.space/api?x=1",
        "https://u@mempool.space/api",
        "https://mempool.space/api/../x",
        "https://mempool.space/a%20b",
        "https://x.btc.quiknode.pro/tok",
        "https://bitcoin-mainnet.g.alchemy.com/v2/k",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain([format!("https://mempool.space/{}", "a".repeat(235))])
    {
        let loaded = with(&format!(
            r#""bitcoin":{{"enabled":true,"network":"testnet4","indexer":"esplora","esploraBaseUrl":{{"mainnet":"{bad}","testnet4":"https://blockstream.info/testnet4/api"}}}}"#
        ));
        assert_eq!(loaded.banners, ["bitcoin.esploraBaseUrl.mainnet"], "{bad}");
        let bitcoin = &loaded.settings.bitcoin;
        assert_eq!(bitcoin.esplora_mainnet, ESPLORA_DEFAULT_MAINNET);
        assert_eq!(
            bitcoin.esplora_testnet4,
            "https://blockstream.info/testnet4/api"
        );
        assert!(bitcoin.enabled);
        assert_eq!(bitcoin.network, BtcNet::Testnet4);
    }
    assert_eq!(
        validate_esplora_url("https://MEMPOOL.space/api").as_deref(),
        Some("https://mempool.space/api")
    );
    assert!(validate_esplora_url("https://esplora.example.com:3002").is_some());
    let loaded = with(
        r#""bitcoin":{"enabled":false,"network":"mainnet","indexer":"esplora","esploraBaseUrl":{"signet":"https://a.example"}}"#,
    );
    assert_eq!(loaded.banners, ["bitcoin.esploraBaseUrl.signet"]);
    assert_eq!(
        loaded.settings.bitcoin.esplora_testnet4,
        ESPLORA_DEFAULT_TESTNET4
    );
}

#[test]
fn scalar_keys_and_unknown_keys() {
    let loaded = with(
        r#""autoLockMinutes":61,"allowSecretCopy":true,"logLevel":"debug","rpcUrl":"x","solana":{"cluster":"devnet"},"llm_explain":{"enabled":true,"extra":1}"#,
    );
    assert_eq!(loaded.settings.auto_lock_minutes, 10);
    assert!(loaded.settings.allow_secret_copy);
    assert_eq!(loaded.settings.log_level, LogLevel::Debug);
    assert_eq!(loaded.settings.solana.cluster, SolCluster::Devnet);
    assert!(!loaded.settings.llm_explain.enabled);
    assert_eq!(loaded.banners, ["autoLockMinutes", "rpcUrl", "llm_explain"]);
}

#[test]
fn round_trip_is_byte_identical_with_fixed_key_order() {
    let loaded = with(&format!(
        r#""evmChains":[{}],"evmChainId":84532,"evmGenesisPins":{{"eip155:999":"{}"}}"#,
        chain(84_532, "Base Sepolia").replace(
            r#""symbol""#,
            r#""quicknodeSubdomain":"base-sepolia","alchemyLabel":"base-sepolia","explorer":"https://sepolia.basescan.org","symbol""#
        ),
        genesis("d")
    ));
    assert!(loaded.banners.is_empty(), "{:?}", loaded.banners);
    let bytes = loaded.settings.to_json();
    let again = load(Some(&bytes));
    assert!(again.banners.is_empty());
    assert_eq!(again.settings, loaded.settings);
    assert_eq!(again.settings.to_json(), bytes);
    let text = String::from_utf8(Settings::default().to_json()).unwrap();
    assert!(text.starts_with(r#"{"version":1,"autoLockMinutes":10,"allowSecretCopy":false,"allowLocalhostDapps":false,"browserAutoLaunch":true,"evmChainId":11155111,"evmChains":[],"evmGenesisPins":{},"feeCaps":{"eip155:1":{"maxFeePerGasGwei":"200","maxPriorityFeePerGasGwei":"5","maxTotalFee":"0.05"},"eip155:11155111":"#));
    assert!(text.contains(r#""esploraBaseUrl":{"mainnet":"https://mempool.space/api","testnet4":"https://mempool.space/testnet4/api"}"#));
    assert!(text.ends_with(r#""logLevel":"info"}"#));
    assert!(load(Some(text.as_bytes())).banners.is_empty());
}
